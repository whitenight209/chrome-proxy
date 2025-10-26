package db

import (
	"context"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ProxyLog struct {
	ClientIP       string
	Method         string
	URL            string
	StatusCode     int
	ResponseTimeMs int
	RequestBody    string
	ResponseBody   string
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

// StoreProxyLog inserts a single proxy log into the database
func (s *Store) StoreProxyLog(ctx context.Context, entry ProxyLog) error {
	query := `
        INSERT INTO proxy_logs (client_ip, method, url, status_code, response_time_ms, request_body, response_body)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    `
	_, err := s.Pool.Exec(ctx, query,
		entry.ClientIP,
		entry.Method,
		entry.URL,
		entry.StatusCode,
		entry.ResponseTimeMs,
		entry.RequestBody,
		entry.ResponseBody,
	)
	return err
}
