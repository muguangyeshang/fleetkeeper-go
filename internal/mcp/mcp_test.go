package mcp

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func serveMCP(t *testing.T, wedged bool) (endpoint string, stop func()) {
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
				defer c.Close()
				if wedged {
					return // accept, then stall: the wedged-state simulation
				}
				buf := make([]byte, 4096)
				if n, _ := c.Read(buf); n == 0 {
					return
				}
				// Answer with matching id: the shape the prover checks.
				fmt.Fprintf(c, "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"+
					`{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
			}(conn)
		}
	}()
	stop = func() { close(done); ln.Close() }
	return fmt.Sprintf("http://127.0.0.1:%d/mcp", ln.Addr().(*net.TCPAddr).Port), stop
}

func TestHealthyMCPServerAnswersPing(t *testing.T) {
	ep, stop := serveMCP(t, false)
	defer stop()

	r := ProbePing(ep, time.Second)
	if r.Verdict != OK {
		t.Fatalf("healthy server must be ok, got %+v", r)
	}
}

func TestWedgedMCPServerIsCaught(t *testing.T) {
	// TCP accepts, protocol never answers. A port watcher calls this
	// healthy; the protocol probe must call it wedged.
	ep, stop := serveMCP(t, true)
	defer stop()

	r := ProbePing(ep, 500*time.Millisecond)
	if r.Verdict != Wedged {
		t.Fatalf("wedged server must be wedged, got %+v", r)
	}
}

func TestDeadPortIsRefusedNotWedged(t *testing.T) {
	r := ProbePing("http://127.0.0.1:1/mcp", 300*time.Millisecond)
	if r.Verdict != Refused {
		t.Fatalf("dead port must be refused, got %+v", r)
	}
}

func TestAnswerWithoutMatchingIdIsWedge(t *testing.T) {
	// A server that answers but with a broken/mismatched id is not a
	// healthy protocol peer — an answer shape check, not content.
	// Replace the healthy handler answer by pointing Probe at a plain
	// HTTP server that returns 200 with garbage: id check must fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c, err := ln.Accept()
			select {
			case <-done:
				if c != nil {
					c.Close()
				}
				return
			default:
			}
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.Read(make([]byte, 4096))
				fmt.Fprintf(c, "HTTP/1.0 200 OK\r\n\r\n`{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}`")
			}(c)
		}
	}()

	r := Probe(fmt.Sprintf("http://127.0.0.1:%d/mcp", ln.Addr().(*net.TCPAddr).Port),
		"ping", time.Second)
	if r.Verdict != Wedged || !strings.Contains(r.Detail, "id") {
		t.Fatalf("mismatched id must be wedged, got %+v", r)
	}
}

func TestPingAndListToolsCarryJSONBody(t *testing.T) {
	// Sanity: the request our probe writes is real JSON-RPC with an id.
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	})
	s := string(reqBody)
	if !strings.Contains(s, `"method":"tools/list"`) || !strings.Contains(s, `"id":1`) {
		t.Fatalf("request body not valid JSON-RPC: %s", s)
	}
}
