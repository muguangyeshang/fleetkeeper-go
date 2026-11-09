package scanner

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeServer is one local listener with a per-connection handler. Every
// test runs against real sockets — no mocking of net.Conn, so the tests
// cover deadlines, banner reads and TCP teardown as well as the logic.
type fakeServer struct {
	ln   net.Listener
	port int
}

func startFake(t *testing.T, handler func(net.Conn)) *fakeServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fs := &fakeServer{ln: ln, port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handler(c)
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return fs
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

func fastConfig(ports ...int) Config {
	return Config{
		Host:        "127.0.0.1",
		Ports:       ports,
		Timeout:     300 * time.Millisecond,
		PassiveWait: 60 * time.Millisecond,
		Workers:     4,
		BannerBytes: 1024,
	}
}

func TestScanFingerprints(t *testing.T) {
	ssh := startFake(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-OpenSSH_9.6 TestServer\r\n"))
		time.Sleep(80 * time.Millisecond)
	})
	httpSrv := startFake(t, func(c net.Conn) {
		buf := make([]byte, 1024)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := c.Read(buf)
		if bytes.HasPrefix(buf[:n], []byte("GET")) {
			c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
		}
	})
	redis := startFake(t, func(c net.Conn) {
		buf := make([]byte, 1024)
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := c.Read(buf)
		if bytes.Contains(buf[:n], []byte("PING")) {
			c.Write([]byte("+PONG\r\n"))
		} else {
			c.Write([]byte("-ERR unknown command\r\n"))
		}
	})
	closed := freePort(t)

	// Deliberately unsorted input: Scan must return port-sorted results.
	cfg := fastConfig(redis.port, closed, httpSrv.port, ssh.port)
	got := Scan(cfg)
	if len(got) != 4 {
		t.Fatalf("want 4 results, got %d: %+v", len(got), got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Port >= got[i].Port {
			t.Fatalf("results not sorted ascending: %d then %d", got[i-1].Port, got[i].Port)
		}
	}

	byPort := map[int]Result{}
	for _, r := range got {
		byPort[r.Port] = r
	}
	for _, tc := range []struct {
		port int
		want string
	}{
		{ssh.port, "ssh"},
		{httpSrv.port, "http"},
		{redis.port, "redis"},
	} {
		r := byPort[tc.port]
		if !r.Open {
			t.Errorf("port %d should be open, got %+v", tc.port, r)
		}
		if r.Protocol != tc.want {
			t.Errorf("port %d protocol = %q, want %q (banner=%q)", tc.port, r.Protocol, tc.want, r.Banner)
		}
	}
	if byPort[closed].Open {
		t.Errorf("free port %d reported open", closed)
	}
}

func TestScanEmptyPorts(t *testing.T) {
	got := Scan(Config{Host: "127.0.0.1"})
	if len(got) != 0 {
		t.Fatalf("empty port list should return empty slice, got %+v", got)
	}
}

// Concurrency is bounded by Workers, measured as the number of DISTINCT
// ports being probed at once. Counting raw connections is wrong here: one
// port opens several sequential sockets (passive + active probes), and a
// server that has not yet reaped a closed socket overlaps the next one.
// Keying by LocalAddr collapses those into one entry per port.
func TestScanConcurrencyBound(t *testing.T) {
	var mu sync.Mutex
	active := map[string]bool{}
	maxPorts := 0
	ports := make([]int, 0, 8)
	for i := 0; i < 8; i++ {
		srv := startFake(t, func(c net.Conn) {
			key := c.LocalAddr().String()
			mu.Lock()
			active[key] = true
			if len(active) > maxPorts {
				maxPorts = len(active)
			}
			mu.Unlock()

			// Hold the connection until the client closes it; this tracks
			// the lifetime of one probe, not a fixed sleep.
			buf := make([]byte, 64)
			c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			for {
				if _, err := c.Read(buf); err != nil {
					break
				}
			}
			mu.Lock()
			delete(active, key)
			mu.Unlock()
		})
		ports = append(ports, srv.port)
	}
	cfg := fastConfig(ports...)
	cfg.Workers = 2
	cfg.PassiveWait = 20 * time.Millisecond
	cfg.Timeout = 120 * time.Millisecond
	got := Scan(cfg)
	if len(got) != len(ports) {
		t.Fatalf("want %d results, got %d", len(ports), len(got))
	}
	mu.Lock()
	m := maxPorts
	mu.Unlock()
	if m > 2 {
		t.Fatalf("concurrency exceeded Workers=2: observed %d distinct ports", m)
	}
	for _, r := range got {
		if !r.Open {
			t.Fatalf("port %d should be open: %+v", r.Port, r)
		}
	}
}

// tokenBucket starts full (Rate permits) and refills one per 1/Rate sec.
// With Rate=2, the third permit must not be available within 200ms.
func TestTokenBucketRefill(t *testing.T) {
	stop := make(chan struct{})
	defer close(stop)
	p := tokenBucket(2, stop)
	for i := 0; i < 2; i++ {
		select {
		case <-p:
		case <-time.After(50 * time.Millisecond):
			t.Fatalf("initial bucket should contain permit #%d", i+1)
		}
	}
	select {
	case <-p:
		t.Fatal("third permit appeared before the refill tick")
	case <-time.After(200 * time.Millisecond):
		// expected: next tick is at 500ms
	}
	select {
	case <-p:
		// refill happened after 500ms
	case <-time.After(600 * time.Millisecond):
		t.Fatal("bucket never refilled")
	}
}

func TestPrintBannerAndMySQLGreeting(t *testing.T) {
	// \x00 和 \xff 各转一个点，\r\n 转成空格后被 TrimSpace 去掉
	if got := printBanner([]byte("SSH-2.0\x00\xff\r\n"), 160); got != "SSH-2.0.." {
		t.Fatalf("printBanner = %q", got)
	}
	greeting := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', 0x00}
	if !mysqlGreeting(greeting) {
		t.Fatal("valid MySQL handshake was not recognised")
	}
	if mysqlGreeting([]byte("HTTP/1.1 200 OK")) {
		t.Fatal("HTTP response misclassified as MySQL")
	}
}

func BenchmarkScan(b *testing.B) {
	// 16 local listeners, all open; the benchmark measures scheduling and
	// fingerprint cost, not connect timeouts on closed ports.
	servers := make([]*fakeServer, 0, 16)
	ports := make([]int, 0, 16)
	for i := 0; i < 16; i++ {
		s := &fakeServer{}
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		s.ln = ln
		s.port = ln.Addr().(*net.TCPAddr).Port
		servers = append(servers, s)
		ports = append(ports, s.port)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					buf := make([]byte, 512)
					c.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
					n, _ := c.Read(buf)
					if bytes.HasPrefix(buf[:n], []byte("GET")) {
						c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"))
					}
				}()
			}
		}()
	}
	b.Cleanup(func() {
		for _, s := range servers {
			s.ln.Close()
		}
	})
	cfg := fastConfig(ports...)
	cfg.Workers = 8
	cfg.PassiveWait = 5 * time.Millisecond
	cfg.Timeout = 100 * time.Millisecond
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got := Scan(cfg)
		if len(got) != len(ports) {
			b.Fatalf("got %d results, want %d", len(got), len(ports))
		}
	}
}
