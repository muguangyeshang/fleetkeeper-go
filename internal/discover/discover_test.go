package discover

import (
	"fmt"
	"net"
	"strings"

	"testing"
	"time"
)

// serve spins up a real loopback HTTP server. Real socket, not a mock:
// the Python suite has the same rule (mocks hide real bugs).
func serve(t *testing.T, responses map[string]string) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			select {
			case <-done:
				if conn != nil {
					conn.Close()
				}
				return
			default:
			}
			if err != nil {
				return
			}
			go func(c net.Conn) {
				buf := make([]byte, 2048)
				c.Read(buf)
				req := string(buf)
				path := "/"
				if i := strings.Index(req, " "); i > 0 {
					parts := strings.Fields(req)
					if len(parts) > 1 {
						path = parts[1]
					}
				}
				body := responses[path]
				if body == "" {
					body = "not found"
				}
				fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n%s", body)
				c.Close()
			}(conn)
		}
	}()
	cleanup := func() { close(done); ln.Close() }
	port := ln.Addr().(*net.TCPAddr).Port
	return port, cleanup
}

func TestOllamaPortIsClassifiedHigh(t *testing.T) {
	port, stop := serve(t, map[string]string{"/api/tags": `{"models":[{"name":"qwen"}]}`})
	defer stop()

	got := HTTPPorts([]int{port}, nil, time.Second, 4)
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	c := got[0]
	if c.Kind != "ollama" || c.Confidence != "high" || c.Name != "Ollama" {
		t.Fatalf("wrong classification: %+v", c)
	}
}

func TestOpenAIPortIsClassifiedHigh(t *testing.T) {
	port, stop := serve(t, map[string]string{"/v1/models": `{"data":[{"id":"m1"}]}`})
	defer stop()

	got := HTTPPorts([]int{port}, nil, time.Second, 4)
	if len(got) != 1 || got[0].Kind != "openai-compatible" {
		t.Fatalf("wrong classification: %+v", got)
	}
}

func TestUnknownHTTPFallsToLowConfidence(t *testing.T) {
	port, stop := serve(t, map[string]string{"/": `{"hello":"world"}`})
	defer stop()

	got := HTTPPorts([]int{port}, nil, time.Second, 4)
	if len(got) != 1 || got[0].Kind != "http" || got[0].Confidence != "low" {
		t.Fatalf("wrong classification: %+v", got)
	}
}

func TestExistingPortIsMarked(t *testing.T) {
	port, stop := serve(t, map[string]string{"/api/tags": `{"models":[]}`})
	defer stop()

	got := HTTPPorts([]int{port}, []int{port}, time.Second, 4)
	if len(got) != 1 || !strings.Contains(got[0].Name, "已在配置") {
		t.Fatalf("existing mark missing: %+v", got)
	}
}

func TestDeadPortReturnsNothing(t *testing.T) {
	// Port 1 on loopback: nothing listens there on CI or locally.
	got := HTTPPorts([]int{1}, nil, 300*time.Millisecond, 1)
	if len(got) != 0 {
		t.Fatalf("dead port must produce no candidate, got %+v", got)
	}
}

func TestConcurrencyIsBoundedAndSafe(t *testing.T) {
	// 64 ports against 4 workers, half of them real listeners: the
	// goroutine pool must not leak, order does not matter, every
	// listener is found.
	ports := make([]int, 0, 64)
	stops := []func(){}
	for i := 0; i < 8; i++ {
		p, stop := serve(t, map[string]string{"/v1/models": `{"data":[]}`})
		ports = append(ports, p)
		stops = append(stops, stop)
	}
	for i := len(ports); i < 64; i++ {
		ports = append(ports, 10000+i) // likely dead
	}
	defer func() {
		for _, s := range stops {
			s()
		}
	}()

	got := HTTPPorts(ports, nil, 500*time.Millisecond, 4)
	if len(got) != 8 {
		t.Fatalf("want 8 listeners found, got %d", len(got))
	}
}
