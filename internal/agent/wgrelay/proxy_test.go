package wgrelay

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyHalfCloseAndShutdown(t *testing.T) {
	backend, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	done := make(chan error, 1)
	go func() {
		c, e := backend.Accept()
		if e != nil {
			done <- e
			return
		}
		defer c.Close()
		b, e := io.ReadAll(c)
		if e == nil {
			_, e = c.Write(append([]byte("reply:"), b...))
		}
		done <- e
	}()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := startProxy(listener, func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp4", backend.Addr().String())
	})
	defer p.close()
	c, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err = c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "reply:hello" {
		t.Fatal(string(b))
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !p.renew() {
		t.Fatal("live proxy failed renewal")
	}
	if err = p.close(); err != nil {
		t.Fatal(err)
	}
	if p.renew() {
		t.Fatal("closed proxy renewed")
	}
}

func TestProxyLeaseClosesListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := startProxy(listener, func(context.Context) (net.Conn, error) { return nil, context.Canceled })
	defer p.close()
	p.mu.Lock()
	p.lease.Reset(10 * time.Millisecond)
	p.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("lease did not close relay")
		}
		time.Sleep(time.Millisecond)
	}
	if p.renew() {
		t.Fatal("expired lease reopened")
	}
}
