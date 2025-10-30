// notifier/notifier.go
package notifier

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "myproxy/grpc/chrome-proxy"
)

const (
	queueSize     = 1000
	workerCount   = 2
	rpcTimeout    = 1500 * time.Millisecond
	retryBackoff  = 400 * time.Millisecond
	maxRetryTimes = 3
)

type Notifier struct {
	conn    *grpc.ClientConn
	client  pb.ProxyNotifierClient
	queue   chan string // request_id만 보냄
	started bool
}

func New(serverAddr string) (*Notifier, error) {
	// 필요 시 TLS로 변경: credentials.NewClientTLSFromFile(...)
	conn, err := grpc.Dial(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	n := &Notifier{
		conn:   conn,
		client: pb.NewProxyNotifierClient(conn),
		queue:  make(chan string, queueSize),
	}
	for i := 0; i < workerCount; i++ {
		go n.worker(i)
	}
	n.started = true
	log.Printf("gRPC notifier started, addr=%s, workers=%d", serverAddr, workerCount)
	return n, nil
}

func (n *Notifier) Close() error {
	if n.started {
		close(n.queue)
		n.started = false
	}
	if n.conn != nil {
		return n.conn.Close()
	}
	return nil
}

func (n *Notifier) Enqueue(id string) {
	select {
	case n.queue <- id:
	default:
		log.Printf("gRPC notify queue full, drop id=%s", id)
	}
}

func (n *Notifier) worker(idx int) {
	for id := range n.queue {
		var lastErr error
		for attempt := 1; attempt <= maxRetryTimes; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
			_, lastErr = n.client.SendProxyEvent(ctx, &pb.ProxyEvent{RequestId: id})
			cancel()
			if lastErr == nil {
				break
			}
			time.Sleep(retryBackoff)
		}
		if lastErr != nil {
			log.Printf("worker-%d: gRPC notify failed after %d tries: %v (id=%s)", idx, maxRetryTimes, lastErr, id)
		}
	}
}
