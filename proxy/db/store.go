package db

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ProxyLog struct {
	ClientIP            string
	Method              string
	URL                 string
	StatusCode          int
	ResponseTimeMs      int
	RequestBody         []byte
	ResponseBody        []byte
	RequestContentType  string
	ResponseContentType string
	RequestHeaders      map[string][]string
	ResponseHeaders     map[string][]string
}

type Store struct {
	Pool *pgxpool.Pool
}

// NewStore initializes a new database connection pool
func NewStore(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to create pgx pool: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close closes the pool connection
func (s *Store) Close() {
	s.Pool.Close()
}

func (s *Store) StoreProxyLog(ctx context.Context, entry ProxyLog) (string, error) {
	query := `
        INSERT INTO proxy_logs (
            client_ip,
            method,
            url,
            status_code,
            response_time_ms,
            request_body,
            response_body,
            request_content_type,
            response_content_type,
            request_headers,
            response_headers
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
        RETURNING id
    `
	reqHdrJSON, err1 := json.Marshal(entry.RequestHeaders)
	if err1 != nil {
		log.Printf("❌ Failed to marshal request headers: %v", err1)
	}
	respHdrJSON, err2 := json.Marshal(entry.ResponseHeaders)
	if err2 != nil {
		log.Printf("❌ Failed to marshal response headers: %v", err2)
	}
	//log.Printf("📥 Inserting ProxyLog:\n"+
	//	"ClientIP=%s\nMethod=%s\nURL=%s\nStatus=%d\nTime=%dms\n"+
	//	"RequestContentType=%s\nResponseContentType=%s\n"+
	//	"RequestHeaders=%s\nResponseHeaders=%s\n",
	//	entry.ClientIP,
	//	entry.Method,
	//	entry.URL,
	//	entry.StatusCode,
	//	entry.ResponseTimeMs,
	//	entry.RequestContentType,
	//	entry.ResponseContentType,
	//	string(reqHdrJSON),
	//	string(respHdrJSON),
	//)
	var id string
	err := s.Pool.QueryRow(ctx, query,
		entry.ClientIP,
		entry.Method,
		entry.URL,
		entry.StatusCode,
		entry.ResponseTimeMs,
		entry.RequestBody,
		entry.ResponseBody,
		entry.RequestContentType,
		entry.ResponseContentType,
		reqHdrJSON,  // map → JSONB 자동 변환 (pgx 지원)
		respHdrJSON, // map → JSONB 자동 변환
	).Scan(&id)

	if err != nil {
		return "", err
	}
	return id, nil
}
