// Package scanner is a standalone TCP port scanner with rate limiting,
// bounded concurrency and passive/active protocol fingerprinting.
//
// It has no dependency outside the standard library and no knowledge of
// the fleetkeeper cloud: Scan() takes a Config, returns []Result. Wire it
// to a CLI, a scheduler, or a report payload — the module does not care.
//
// Cost model: for P ports, at most P * (1 + len(probers)) TCP connections;
// wall time ~= P / min(Workers, Rate) seconds. The bottleneck is the
// per-port connect timeout on closed/filtered ports, not the CPU.
package scanner

import (
	"errors"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Config is fully externalised: nothing is hard-coded in the scan loop.
type Config struct {
	Host        string        // target host or IP
	Ports       []int         // ports to probe
	Timeout     time.Duration // per-connection deadline
	PassiveWait time.Duration // how long to wait for a server-first banner
	Workers     int           // max concurrent ports
	Rate        int           // max ports started per second; <= 0 = unlimited
	BannerBytes int           // banner cap, prevents memory abuse
}

// Result is the JSON shape consumed by the CLI and any downstream module.
type Result struct {
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Open     bool    `json:"open"`
	Protocol string  `json:"protocol,omitempty"`
	Banner   string  `json:"banner,omitempty"`
	RTTMs    float64 `json:"rtt_ms"`
	Error    string  `json:"error,omitempty"`
}

func (c Config) withDefaults() Config {
	if c.Host == "" {
		c.Host = "127.0.0.1"
	}
	if c.Timeout <= 0 {
		c.Timeout = 500 * time.Millisecond
	}
	if c.PassiveWait <= 0 || c.PassiveWait > c.Timeout {
		c.PassiveWait = minDuration(c.Timeout, 300*time.Millisecond)
	}
	if c.Workers <= 0 {
		c.Workers = 16
	}
	if c.BannerBytes <= 0 || c.BannerBytes > 64*1024 {
		c.BannerBytes = 4096
	}
	return c
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// tokenBucket yields one permit per port-sweep (a sweep may open several
// connections, one per prober). It starts full so the first Rate ports are
// not artificially delayed, and refills at 1/Rate intervals.
func tokenBucket(rate int, stop <-chan struct{}) <-chan struct{} {
	out := make(chan struct{}, rate)
	for i := 0; i < rate; i++ {
		out <- struct{}{}
	}
	go func() {
		defer close(out)
		t := time.NewTicker(time.Second / time.Duration(rate))
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				select {
				case out <- struct{}{}:
				default: // bucket full, drop this token
				}
			}
		}
	}()
	return out
}

// Scan probes every port in cfg.Ports and returns results sorted by port.
// Results from closed ports are included with Open=false; callers may
// filter them (the CLI does). Concurrency is bounded by Workers; the rate
// at which new ports are started is bounded by Rate (each port may open
// several sequential connections, one per prober).
func Scan(cfg Config) []Result {
	cfg = cfg.withDefaults()
	if len(cfg.Ports) == 0 {
		return []Result{}
	}

	stop := make(chan struct{})
	var pacer <-chan struct{}
	if cfg.Rate > 0 {
		pacer = tokenBucket(cfg.Rate, stop)
	}

	workers := cfg.Workers
	if workers > len(cfg.Ports) {
		workers = len(cfg.Ports)
	}

	jobs := make(chan int)
	results := make([]Result, 0, len(cfg.Ports))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range jobs {
				if pacer != nil {
					<-pacer // one permit per port-sweep (all its probes)
				}
				r := probePort(cfg, port)
				mu.Lock()
				results = append(results, r)
				mu.Unlock()
			}
		}()
	}
	for _, p := range cfg.Ports {
		jobs <- p
	}
	close(jobs)
	wg.Wait()
	close(stop)

	// goroutine scheduling makes completion order nondeterministic;
	// sorting keeps output stable for diffing and tests.
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

// probePort: one connection for liveness + passive banner, then one
// connection per active prober until a fingerprint matches.
func probePort(cfg Config, port int) Result {
	r := Result{Host: cfg.Host, Port: port}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		r.Error = errorText(err)
		r.RTTMs = float64(time.Since(start).Microseconds()) / 1000.0
		return r
	}
	r.Open = true
	banner := readUpTo(conn, cfg.PassiveWait, cfg.BannerBytes)
	conn.Close()
	r.RTTMs = float64(time.Since(start).Microseconds()) / 1000.0

	// Server-first protocols need no payload.
	for _, p := range probers {
		if p.payload == nil && p.match(banner) {
			r.Protocol = p.label(banner)
			r.Banner = printBanner(banner, 160)
			return r
		}
	}

	// Client-first protocols: a fresh connection each, so an HTTP/1.0
	// server closing the socket after one request cannot hide Redis/TLS.
	for _, p := range probers {
		if p.payload == nil {
			continue
		}
		c, err := net.DialTimeout("tcp", addr, cfg.Timeout)
		if err != nil {
			continue // liveness already proven; a refused second connect is not fatal
		}
		c.SetDeadline(time.Now().Add(cfg.Timeout))
		if _, err = c.Write(p.payload); err == nil {
			resp := readUpTo(c, cfg.Timeout, cfg.BannerBytes)
			if p.match(resp) {
				r.Protocol = p.label(resp)
				r.Banner = printBanner(resp, 160)
				c.Close()
				return r
			}
		}
		c.Close()
	}

	r.Protocol = "unknown"
	r.Banner = printBanner(banner, 160)
	return r
}

// readUpTo reads at most 3 chunks or until deadline/EOF. The cap is a
// hard bound on bytes held per port — a hostile banner cannot exhaust RAM.
func readUpTo(conn net.Conn, wait time.Duration, capBytes int) []byte {
	conn.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, capBytes)
	total := 0
	for i := 0; i < 3 && total < capBytes; i++ {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil || n == 0 {
			break
		}
		// After the first bytes arrive, shrink the remaining wait to 20ms:
		// this still collects a split banner, but avoids burning the full
		// Timeout on servers that keep the socket open (HTTP keep-alive).
		conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	}
	return buf[:total]
}

func errorText(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout"
	}
	return err.Error()
}
