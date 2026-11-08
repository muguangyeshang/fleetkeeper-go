// Package discover is the Go port of fleetkeeper's discovery core:
// find localhost TCP listeners, probe them with HTTP product
// fingerprints, classify what is running.
//
// Why Go for this module specifically: the Python original pays one
// `tasklist` batch call and a ThreadPoolExecutor for concurrency; Go
// gets both from the standard library (net, goroutines) with no
// subprocess at all. This file is the language-difference showcase.
package discover

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Signature is one product fingerprint. Ordered: first match wins.
type Signature struct {
	Kind       string // "ollama", "openai-compatible", "comfyui", "http"
	Label      string
	Confidence string // high / medium / low
	ProbePath  string // path whose response identifies the product
	// JSONKey is the top-level field a correct product answers with
	// (e.g. Ollama's /api/tags answers "models"). Empty means any
	// HTTP status line counts.
	JSONKey string
}

// SIGNATURES mirrors discover.py's table. Same order, same semantics.
var SIGNATURES = []Signature{
	{"ollama", "Ollama", "high", "/api/tags", "models"},
	{"openai-compatible", "OpenAI 兼容接口", "high", "/v1/models", "data"},
	{"comfyui", "ComfyUI", "high", "/system_stats", "system"},
	// Last: any HTTP status line counts, never auto-applied.
	{"http", "未识别的 HTTP 服务", "low", "/", ""},
}

// Candidate is one classified local service.
type Candidate struct {
	Port       int    `json:"port"`
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Confidence string `json:"confidence"`
	Evidence   string `json:"evidence"`
}

// HTTPPorts scans every port in `ports` and returns those with a live
// HTTP-ish listener, classified. Concurrency: one goroutine per port
// bounded by `workers` — in Python this needed a ThreadPoolExecutor,
// here it is language-native. Ports already in `existing` are marked
// "已在配置" instead of "new", same as the Python original.
func HTTPPorts(ports []int, existing []int, timeout time.Duration, workers int) []Candidate {
	isExisting := map[int]bool{}
	for _, p := range existing {
		isExisting[p] = true
	}

	results := make([]Candidate, 0, len(ports))
	var mu sync.Mutex
	sem := make(chan struct{}, workers) // bounded pool
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			sem <- struct{}{}        // acquire
			defer func() { <-sem }() // release

			cand, ok := classify(p, timeout, isExisting[p])
			if !ok {
				return
			}
			mu.Lock()
			results = append(results, cand)
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return results
}

// classify probes one port: first a product-path GET, then a bare
// status-line fallback. Returns (candidate, true) when anything
// answers, (zero, false) when the port is not HTTP.
func classify(port int, timeout time.Duration, existing bool) (Candidate, bool) {
	for _, sig := range SIGNATURES {
		if status, body, err := probe(port, sig.ProbePath, timeout); err == nil {
			if sig.JSONKey == "" || strings.Contains(body, `"`+sig.JSONKey+`"`) {
				return build(port, sig, status, existing), true
			}
		}
	}
	return Candidate{}, false
}

// probe does one GET on 127.0.0.1:port. Body capped at 64 KiB —
// same MAX_PROBE_BYTES rule as the Python version.
func probe(port int, path string, timeout time.Duration) (string, string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Hand-written HTTP/1.0: no dependency, server closes on EOF.
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: fleetkeeper-go\r\n\r\n", path)
	if _, err = conn.Write([]byte(req)); err != nil {
		return "", "", err
	}

	buf := make([]byte, 64*1024)
	n, _ := conn.Read(buf) // one read is enough for status+first body bytes
	raw := string(buf[:n])
	status := ""
	if i := strings.Index(raw, "\r\n"); i > 0 {
		status = raw[:i]
	}
	body := raw
	if i := strings.Index(raw, "\r\n\r\n"); i > 0 {
		body = raw[i+4:]
	}
	return status, body, nil
}

func build(port int, sig Signature, status string, existing bool) Candidate {
	name := sig.Label
	if existing {
		name += "（已在配置）"
	}
	return Candidate{
		Port:       port,
		Kind:       sig.Kind,
		Name:       name,
		Confidence: sig.Confidence,
		Evidence:   status,
	}
}
