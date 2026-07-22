package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestInterceptHealthcheckTimesOutWhenSOCKSPeerDoesNotReply(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan struct{})
	release := make(chan struct{})
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		close(accepted)
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
	}()
	defer close(release)

	cfg := Config{
		Listen:   listener.Addr().String(),
		Username: "healthcheck-user",
		Password: "healthcheck-password",
		MITM:     MITMSettings{Enabled: true},
		Modules: []Module{{
			Enabled:      true,
			CaptureHosts: []string{"*.example.com"},
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	started := time.Now()
	err = checkInterceptHealth(ctx, cfg)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("healthcheck unexpectedly succeeded against a silent SOCKS peer")
	}
	// The socket deadline and context timer share the same deadline. The read
	// can observe its timeout just before the scheduler publishes ctx.Done(), so
	// wait for that already-due signal instead of racing ctx.Err().
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("healthcheck returned a timeout before its context became done")
	}
	if ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("healthcheck context error = %v", ctx.Err())
	}
	if elapsed > time.Second {
		t.Fatalf("healthcheck exceeded its context deadline: %s", elapsed)
	}
	select {
	case <-accepted:
	default:
		t.Fatal("healthcheck did not reach the silent SOCKS peer")
	}
}
