package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"github.com/elazarl/goproxy"
	"github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"io"
	"io/ioutil"
	"log"
	"myproxy/db"
	"net/http"
	"os"
	"strings"
	"time"
)

type RulePayload struct {
	Host        string `json:"host"`
	Path        string `json:"path"`
	Action      string `json:"action"`       // "pass"|"print"|"modify"|"block"
	ReplaceBody string `json:"replace_body"` // for modify
	Enabled     bool   `json:"enabled"`
}

var (
	rdb      *redis.Client
	locCache *cache.Cache
)

// init redis & local cache
func initPubsub(redisAddr string) {
	rdb = redis.NewClient(&redis.Options{Addr: redisAddr})
	locCache = cache.New(30*time.Second, 1*time.Minute)
	// start subscriber
	go startSubscriber(context.Background())
}

func startSubscriber(ctx context.Context) {
	pubsub := rdb.Subscribe(ctx, "proxy:rule_update")
	ch := pubsub.Channel()
	log.Println("Subscribed to proxy:rule_update")
	for {
		select {
		case <-ctx.Done():
			_ = pubsub.Close()
			return
		case msg := <-ch:
			key := msg.Payload // e.g. "proxy:rule:www.korail.com|/dynaPath.do"
			// load value
			val, err := rdb.Get(ctx, key).Result()
			if err != nil {
				// missing -> invalidate local cache
				parts := strings.SplitN(strings.TrimPrefix(key, "proxy:rule:"), "|", 2)
				if len(parts) == 2 {
					locCache.Delete(parts[0] + "|" + parts[1])
				}
				continue
			}
			var r RulePayload
			if err := json.Unmarshal([]byte(val), &r); err != nil {
				log.Printf("bad rule json %s: %v", key, err)
				continue
			}
			locCache.Set(r.Host+"|"+r.Path, &r, cache.DefaultExpiration)
			log.Printf("cached rule %s|%s -> %s", r.Host, r.Path, r.Action)
		}
	}
}

// lookup: local cache first, then redis
func lookupRule(ctx context.Context, host, path string) (*RulePayload, error) {
	key := host + "|" + path
	if v, ok := locCache.Get(key); ok {
		if r, ok2 := v.(*RulePayload); ok2 {
			return r, nil
		}
	}
	redisKey := "proxy:rule:" + key
	val, err := rdb.Get(ctx, redisKey).Result()
	if err != nil {
		return nil, nil // no rule
	}
	var r RulePayload
	if err := json.Unmarshal([]byte(val), &r); err != nil {
		return nil, err
	}
	locCache.Set(key, &r, cache.DefaultExpiration)
	return &r, nil
}

const MaxBytesCapture = 5 * 1024 * 1024

type captureWriter struct {
	buf []byte
	max int
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if len(w.buf) < w.max {
		n := w.max - len(w.buf)
		if len(p) < n {
			n = len(p)
		}
		w.buf = append(w.buf, p[:n]...)
	}
	return len(p), nil
}

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

func handleRequest(req *http.Request, ctx *goproxy.ProxyCtx, store *db.Store) (*http.Request, *http.Response) {
	start := time.Now()

	var reqBody []byte
	if req.Body != nil {
		contentType := req.Header.Get("Content-Type")
		body, err := io.ReadAll(req.Body)
		if err != nil && err != io.EOF {
			log.Printf("⚠️ Failed to read request body: %v", err)
		}
		req.Body = io.NopCloser(bytes.NewBuffer(body)) // restore body for forwarding
		if strings.Contains(contentType, "application/json") {
			reqBody = body
		}
	}

	// Forward the request normally
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		log.Printf("❌ Error forwarding request: %v", err)
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, err.Error())
	}

	var respBody []byte
	if resp.Body != nil {
		contentType := resp.Header.Get("Content-Type")
		body, err := io.ReadAll(resp.Body)
		if err != nil && err != io.EOF {
			log.Printf("⚠️ Failed to read request body: %v", err)
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(body)) // restore body for client
		if strings.Contains(contentType, "application/json") {
			respBody = body
		}
	}

	duration := time.Since(start).Milliseconds()

	if store != nil {
		entry := db.ProxyLog{
			ClientIP:       req.RemoteAddr,
			Method:         req.Method,
			URL:            req.URL.String(),
			StatusCode:     resp.StatusCode,
			ResponseTimeMs: int(duration),
			RequestBody:    string(reqBody),
			ResponseBody:   string(respBody),
		}

		// ✅ Run async: don’t block proxy response
		go func(e db.ProxyLog) {
			ctxTimeout, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if err := store.StoreProxyLog(ctxTimeout, e); err != nil {
				log.Printf("❌ DB insert failed: %v", err)
			}
		}(entry)
	}

	return req, resp
}

func main() {
	certPath := "ca-cert.pem"
	keyPath := "ca-key.pem"
	enableDB := flag.Bool("db", false, "Enable PostgreSQL connection")
	dsn := flag.String("dsn", "postgres://user:password@localhost:5432/mydb?sslmode=disable", "PostgreSQL DSN")
	flag.Parse()
	ctx := context.Background()
	var store *db.Store
	var err error
	if *enableDB {
		store, err = initDB(ctx, *dsn)
		if err != nil {
			log.Fatalf("❌ Failed to initialize DB: %v", err)
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
	log.Printf("start connect to redis...")
	initPubsub("127.0.0.1:6379")
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

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
