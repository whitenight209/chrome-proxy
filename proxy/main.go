package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"myproxy/db"
	"net/http"
	"os"
	"strings"
	"time"

	"myproxy/core"

	"github.com/elazarl/goproxy"
)

const (
	maxBodySize = 1 * 1024 * 1024 // 1MB
)

// loadTLSCert loads PEM cert+key and returns tls.Certificate and parsed x509.Certificate (root)
func loadTLSCert(certPath, keyPath string) (tls.Certificate, *x509.Certificate, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	// parse first cert in chain to x509.Certificate
	if len(tlsCert.Certificate) == 0 {
		return tls.Certificate{}, nil, err
	}
	rootCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return tlsCert, rootCert, nil
}

func maybeGunzip(b []byte, hdr http.Header) ([]byte, bool, error) {
	enc := strings.ToLower(hdr.Get("Content-Encoding"))
	if enc == "gzip" {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil, false, err
		}
		defer r.Close()
		out, err := ioutil.ReadAll(r)
		if err != nil {
			return nil, false, err
		}
		return out, true, nil
	}
	return b, false, nil
}

func gzipBytes(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(src); err != nil {
		gw.Close()
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// initDB prepares the PostgreSQL connection pool
func initDB(ctx context.Context, dsn string) (*db.Store, error) {
	log.Println("🔄 Initializing PostgreSQL connection pool...")

	store, err := db.NewStore(ctx, dsn)
	if err != nil {
		return nil, err
	}

	log.Println("✅ PostgreSQL connection pool ready")
	return store, nil
}

// --- Body 처리 (gzip 해제 + base64 + 압축/트렁케이션) ---
func captureBody(body io.ReadCloser, encoding, contentType string) []byte {
	if body == nil {
		return nil
	}
	defer body.Close()

	// 이미지나 바이너리류는 스킵
	if skipContent(contentType) {
		return []byte("[SKIPPED_BINARY_CONTENT]")
	}

	// gzip 해제
	var reader io.Reader = body
	if strings.Contains(encoding, "gzip") {
		gzReader, err := gzip.NewReader(body)
		if err == nil {
			defer gzReader.Close()
			reader = gzReader
		}
	}

	// 1MB까지만 읽기
	limited := io.LimitReader(reader, maxBodySize+1)
	data, err := io.ReadAll(limited)
	if err != nil && err != io.EOF {
		log.Printf("⚠️ Failed to read body: %v", err)
	}

	// 1MB 초과 시 압축 저장 + 표시
	if len(data) > maxBodySize {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(data)
		gz.Close()
		compressed := base64.StdEncoding.EncodeToString(buf.Bytes())
		return []byte("[TRUNCATED & COMPRESSED]:" + compressed)
	}

	// Base64 인코딩
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// --- 특정 content-type 스킵 여부 ---
func skipContent(ct string) bool {
	ct = strings.ToLower(ct)
	skipTypes := []string{
		"image/", "video/", "audio/", "font/",
		"application/octet-stream",
	}
	for _, s := range skipTypes {
		if strings.HasPrefix(ct, s) {
			return true
		}
	}
	return false
}

// --- HTTP 메서드별 Body 허용 ---
func hasBodyMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

// --- Header 복제 ---
func cloneHeader(src http.Header) map[string][]string {
	dst := make(map[string][]string)
	for k, v := range src {
		dst[k] = append([]string(nil), v...)
	}
	return dst
}
func processBody(data []byte, encoding, contentType string) []byte {
	if skipContent(contentType) {
		return []byte("[SKIPPED_BINARY_CONTENT]")
	}

	// gzip 해제
	if strings.Contains(encoding, "gzip") {
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err == nil {
			defer gr.Close()
			decompressed, _ := io.ReadAll(gr)
			data = decompressed
		}
	}

	// 1MB 초과 시 압축+인코딩
	if len(data) > maxBodySize {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(data)
		gz.Close()
		return []byte("[TRUNCATED & COMPRESSED]:" + base64.StdEncoding.EncodeToString(buf.Bytes()))
	}

	// base64 인코딩
	return []byte(base64.StdEncoding.EncodeToString(data))
}

// --- 메인 프록시 핸들러 ---
func handleRequest(req *http.Request, ctx *goproxy.ProxyCtx, store *db.Store) (*http.Request, *http.Response) {
	start := time.Now()

	// --- Request Body 수집 + 복원 ---
	var reqBodyCopy []byte
	if req.Body != nil && hasBodyMethod(req.Method) {
		body, err := io.ReadAll(req.Body)
		if err != nil && err != io.EOF {
			log.Printf("⚠️ Failed to read request body: %v", err)
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewBuffer(body)) // 복원 (필수)
		reqBodyCopy = processBody(body, req.Header.Get("Content-Encoding"), req.Header.Get("Content-Type"))
	}

	reqHeaders := cloneHeader(req.Header)
	reqCT := req.Header.Get("Content-Type")

	// --- 요청 전달 ---
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("❌ Error forwarding request: %v", err)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, err.Error())
	}

	// --- Response Body 수집 + 복원 ---
	var respBodyCopy []byte
	if resp.Body != nil {
		body, err := io.ReadAll(resp.Body)
		if err != nil && err != io.EOF {
			log.Printf("⚠️ Failed to read response body: %v", err)
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewBuffer(body)) // 복원 (Chrome 응답 위해 필수)
		respBodyCopy = processBody(body, resp.Header.Get("Content-Encoding"), resp.Header.Get("Content-Type"))
	}

	respHeaders := cloneHeader(resp.Header)
	respCT := resp.Header.Get("Content-Type")
	duration := time.Since(start).Milliseconds()

	// --- 비동기 DB 로깅 ---
	if store != nil && core.LogQueue != nil {
		entry := db.ProxyLog{
			ClientIP:            req.RemoteAddr,
			Method:              req.Method,
			URL:                 req.URL.String(),
			StatusCode:          resp.StatusCode,
			ResponseTimeMs:      int(duration),
			RequestBody:         reqBodyCopy,
			ResponseBody:        respBodyCopy,
			RequestContentType:  reqCT,
			ResponseContentType: respCT,
			RequestHeaders:      reqHeaders,
			ResponseHeaders:     respHeaders,
		}

		select {
		case core.LogQueue <- entry:
		default:
			log.Printf("⚠️ Log queue full — dropping entry for %s", req.URL.String())
		}
	}

	return req, resp
}

func main() {
	certPath := "ca-cert.pem"
	keyPath := "ca-key.pem"
	grpcAddr := "127.0.0.1:9898"
	enableDB := flag.Bool("db", false, "Enable PostgreSQL connection")
	dsn := flag.String("dsn", "postgres://postgres:qkrcjfgh1@localhost:5432/playground?sslmode=disable", "PostgreSQL DSN")
	flag.Parse()
	ctx := context.Background()
	var store *db.Store
	var err error
	if *enableDB {
		store, err = initDB(ctx, *dsn)
		if err != nil {
			log.Fatalf("❌ Failed to initialize DB: %v", err)
		}
		err := core.InitLogWorkers(store, grpcAddr)
		if err != nil {
			log.Fatalf("❌ Failed to InitLogWorkers: %v", err)
		}
		defer store.Close()
	} else {
		log.Println("⚠️  PostgreSQL flag disabled — skipping initialization")
	}

	tlsCert, rootCert, err := loadTLSCert(certPath, keyPath)
	if err != nil {
		log.Fatalf("failed to load CA cert/key: %v", err)
	}

	// --- 핵심: goproxy가 내부에서 사용할 CA에 우리가 로드한 tls.Certificate를 할당
	// goproxy package expects a tls.Certificate value in GoproxyCa
	// (this variable exists in upstream goproxy implementations)
	goproxy.GoproxyCa = tlsCert

	// (선택) 로그로 확인
	log.Printf("Loaded CA for goproxy: Subject=%s\n", rootCert.Subject.CommonName)
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false

	// Enable MITM for CONNECT (goproxy will sign per-host certs using GoproxyCa)
	// Use the predefined handler AlwaysMitm (do MITM). We don't register any DoFunc/ModifyResponse,
	// so requests/responses bodies are not modified.
	proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		return handleRequest(req, ctx, store)
	})
	//// 요청 차단
	//proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	//	if req == nil || req.URL == nil {
	//		return req, nil
	//	}
	//	host := req.URL.Hostname()
	//	path := req.URL.Path
	//
	//	// lookup with short timeout
	//	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	//	defer cancel()
	//	rule, err := lookupRule(cctx, host, path)
	//	if err != nil {
	//		log.Printf("lookup error: %v", err)
	//		return req, nil
	//	}
	//	if rule == nil || !rule.Enabled {
	//		return req, nil
	//	}
	//
	//	action := strings.ToLower(rule.Action)
	//	switch action {
	//	case "block":
	//		// Return immediate block response (do not contact origin)
	//		// Use goproxy helper to craft response
	//		body := "Blocked by proxy"
	//		resp := goproxy.NewResponse(req,
	//			goproxy.ContentTypeText, http.StatusForbidden, body)
	//		log.Printf("Blocked request %s%s", host, path)
	//		return req, resp
	//	// For print or modify we handle in OnResponse to preserve response handling logic.
	//	default:
	//		return req, nil
	//	}
	//})
	//
	//// OnResponse: print or modify or pass
	//proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	//	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
	//		return resp
	//	}
	//	host := resp.Request.URL.Hostname()
	//	path := resp.Request.URL.Path
	//
	//	cctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	//	defer cancel()
	//	rule, err := lookupRule(cctx, host, path)
	//	if err != nil {
	//		log.Printf("lookupRule err: %v", err)
	//		return resp
	//	}
	//	if rule == nil || !rule.Enabled {
	//		return resp
	//	}
	//
	//	switch strings.ToLower(rule.Action) {
	//	case "print":
	//		// read limited body, print, restore
	//		cw := &captureWriter{max: MaxBytesCapture}
	//
	//		// wrap original body with TeeReader: streams to client & capture buffer
	//		resp.Body = io.NopCloser(io.TeeReader(resp.Body, cw))
	//
	//		// async log so client not slowed down
	//		go func(h, p string, cap *captureWriter) {
	//			// wait a bit so body can flow in
	//			time.Sleep(100 * time.Millisecond)
	//			log.Printf("[PRINT %s%s]\n%s", h, p, string(cap.buf))
	//		}(host, path, cw)
	//		return resp
	//
	//	case "modify":
	//		// do not read origin; replace body with rule.ReplaceBody
	//		_ = resp.Body.Close()
	//		newBody := []byte(rule.ReplaceBody)
	//		resp.Body = io.NopCloser(bytes.NewReader(newBody))
	//		resp.ContentLength = int64(len(newBody))
	//		resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
	//		resp.Header.Del("Content-Encoding")
	//		resp.Header.Del("Transfer-Encoding")
	//		log.Printf("Modified response for %s%s", host, path)
	//		return resp
	//
	//	case "block":
	//		// fallback: block at response time (in case not blocked at request)
	//		_ = resp.Body.Close()
	//		body := "Blocked by proxy"
	//		// craft a fresh response
	//		newResp := goproxy.NewResponse(resp.Request, goproxy.ContentTypeText, http.StatusForbidden, body)
	//		log.Printf("Blocked at response for %s%s", host, path)
	//		return newResp
	//
	//	default:
	//		return resp
	//	}
	//})

	addr := ":8080"
	log.Printf("Starting proxy (MITM using provided CA) on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, proxy))
}
