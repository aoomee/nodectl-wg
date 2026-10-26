package wgrelay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const maxSessions = 128
const sessionLifetime = 30 * time.Minute

type dialFunc func(context.Context, string, string, string) (net.Conn, error)

type proxy struct {
	listener net.Listener
	cancel   context.CancelFunc
	mu       sync.Mutex
	sessions map[net.Conn]struct{}
	closed   bool
	lease    *time.Timer
	wg       sync.WaitGroup
}

func startProxy(listener net.Listener, dial func(context.Context) (net.Conn, error)) *proxy {
	ctx, cancel := context.WithCancel(context.Background())
	p := &proxy{listener: listener, cancel: cancel, sessions: make(map[net.Conn]struct{})}
	// A disconnected/revoked controller must not leave an untracked public relay.
	p.lease = time.AfterFunc(90*time.Second, func() { _ = p.close() })
	slots := make(chan struct{}, maxSessions)
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				_ = client.Close()
				continue
			}
			if !p.track(client) {
				<-slots
				_ = client.Close()
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer func() { <-slots }()
				defer p.release(client)
				dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
				upstream, err := dial(dctx)
				dcancel()
				if err != nil {
					return
				}
				if !p.track(upstream) {
					_ = upstream.Close()
					return
				}
				defer p.release(upstream)
				deadline := time.Now().Add(sessionLifetime)
				_ = client.SetDeadline(deadline)
				_ = upstream.SetDeadline(deadline)
				done := make(chan struct{})
				go func() { copyHalf(upstream, client); close(done) }()
				copyHalf(client, upstream)
				<-done
			}()
		}
	}()
	return p
}
func (p *proxy) renew() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	if p.lease != nil {
		p.lease.Reset(90 * time.Second)
	}
	return true
}

func copyHalf(dst, src net.Conn) {
	_, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
		return
	}
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	} else {
		_ = dst.Close()
	}
}
func (p *proxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.sessions[c] = struct{}{}
	return true
}
func (p *proxy) release(c net.Conn) { _ = c.Close(); p.mu.Lock(); delete(p.sessions, c); p.mu.Unlock() }
func (p *proxy) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	if p.lease != nil {
		p.lease.Stop()
	}
	p.cancel()
	err := p.listener.Close()
	for c := range p.sessions {
		_ = c.Close()
	}
	p.mu.Unlock()
	p.wg.Wait()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
