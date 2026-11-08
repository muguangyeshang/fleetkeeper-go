// Package mcp adds protocol-level health checks for MCP servers.
//
// Why this exists: a process can hold its port open while the MCP
// protocol inside is wedged — TCP connect succeeds, HTTP may even
// return 200, and yet every tool call hangs. Port-based watching
// cannot see that; a real protocol round-trip can.
//
// Two probes, both read-only, both JSON-RPC 2.0 over HTTP:
//   - ping:      {"jsonrpc":"2.0","id":1,"method":"ping"}      -> must
//     answer any result (or empty result) with id=1
//   - list_tools: method "tools/list"                        -> must
//     answer with a tools array
//
// Spec basis: MCP Streamable HTTP transport. Servers that only speak
// stdio (the other transport) are out of scope here — they have no
// loopback port to probe.
package mcp

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Verdict is one protocol probe's outcome. Ladder mapping:
// OK -> protocol layer proven; WEDGED -> port open, protocol dead
// (the state ordinary watchers report as healthy).
type Verdict string

const (
	OK      Verdict = "ok"      // protocol round-trip answered
	Wedged  Verdict = "wedged"  // port accepts connections but protocol does not answer
	Refused Verdict = "refused" // TCP connect failed (watchdog territory, not ours)
)

// Result is one probe result.
type Result struct {
	Verdict Verdict `json:"verdict"`
	Detail  string  `json:"detail"`
	// ElapsedMS is how long the round-trip took; a "wedged" server
	// usually shows a timeout-sized number here, which distinguishes
	// it from a fast refusal.
	ElapsedMS int64 `json:"elapsed_ms"`
}

// Probe sends one JSON-RPC method to an MCP server's HTTP endpoint and
// interprets the answer. endpoint is a full URL, e.g.
// http://127.0.0.1:8080/mcp — servers pick their own path, so it is a
// parameter, never a constant.
func Probe(endpoint, method string, timeout time.Duration) Result {
	start := time.Now()
	body, err := rpc(endpoint, method, timeout)
	ms := time.Since(start).Milliseconds()
	if err != nil {
		// Distinguish "nothing listening" from "listening but stuck":
		// a connection refused is the watchdog's domain, anything else
		// (timeout, unreadable answer, malformed JSON) is a wedge.
		if isRefused(err) {
			return Result{Verdict: Refused, Detail: short(err.Error()), ElapsedMS: ms}
		}
		return Result{Verdict: Wedged, Detail: short(err.Error()), ElapsedMS: ms}
	}
	// A healthy server answers with id matching our request id (1) and
	// either a result or a defined error — both prove the protocol
	// loop is alive. The answer shape, not the content, is the proof.
	if !strings.Contains(body, `"id":1`) {
		return Result{Verdict: Wedged, Detail: "answer has no matching id", ElapsedMS: ms}
	}
	return Result{Verdict: OK, Detail: method + " answered", ElapsedMS: ms}
}

// ProbePing is the cheap liveness check: one round-trip, no payload.
func ProbePing(endpoint string, timeout time.Duration) Result {
	return Probe(endpoint, "ping", timeout)
}

// rpc posts one JSON-RPC 2.0 request using a hand-written HTTP/1.0
// exchange — same zero-dependency rule as the discover module's probe.
func rpc(endpoint, method string, timeout time.Duration) (string, error) {
	reqBody, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "2.0", "id": 1, "method": method,
	})
	conn, err := dialHTTP(endpoint, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	req := fmt.Sprintf("POST %s HTTP/1.0\r\nHost: 127.0.0.1\r\n"+
		"Content-Type: application/json\r\nAccept: application/json\r\n"+
		"Content-Length: %d\r\n\r\n%s", endpoint, len(reqBody), reqBody)
	if _, err = conn.Write([]byte(req)); err != nil {
		return "", err
	}
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf) // one read: status line + first body bytes suffice
	if err != nil && n == 0 {
		return "", err
	}
	raw := string(buf[:n])
	i := strings.Index(raw, "\r\n\r\n")
	if i < 0 {
		return "", fmt.Errorf("no HTTP header terminator in answer")
	}
	return raw[i+4:], nil
}

// dialHTTP splits "http://host:port/path" into a bare TCP dial to
// host:port. Using net.DialTimeout (not net/http) keeps the whole
// module dependency-free and lets us time the round-trip precisely.
func dialHTTP(endpoint string, timeout time.Duration) (net.Conn, error) {
	host := endpoint
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://") // loopback TLS is out of scope
	if i := strings.Index(host, "/"); i > 0 {
		host = host[:i]
	}
	return net.DialTimeout("tcp", host, timeout)
}

// isRefused reports whether the dial error means "nothing listening"
// (ECONNREFUSED family) versus a timeout/wedge.
func isRefused(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "actively refused")
}

func short(s string) string {
	if len(s) > 80 {
		return s[:80]
	}
	return s
}
