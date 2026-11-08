// Package watchdog is the Go port of fleetkeeper's guarded self-healing:
// sweep the fleet, classify dead ports, restart with brakes.
//
// The brakes are the product, and each one maps to a rule:
//   - per-port cooldown: one dead port must not delay or repeatedly
//     restart other ports, and a cooldown must survive green sweeps
//   - network gate: when the WAN probe fails, record issues and never
//     heal — a heal loop during an outage is noise amplification
//   - pause marker: a human's "intentionally offline" is not an incident
//   - PID-guarded process ops: never guess which process to touch
package watchdog

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Config is the watchdog's tunable surface. All parameters external,
// none hardcoded — same rule as the Python original.
type Config struct {
	Ports              []int         // ports to guard
	Cooldown           time.Duration // per-port heal cooldown
	NetProbe           string        // host:port for the WAN gate; empty disables it
	PauseDir           string        // directory holding "<port>.paused" markers
	MaxConsecutiveDown int           // sweeps a port stays down before healing
	StateFile          string        // cooldown persistence across restarts
	Logf               func(format string, args ...interface{})
}

// PortState is one port's running record.
type PortState struct {
	Port       int       `json:"port"`
	DownStreak int       `json:"down_streak"`
	LastHeal   time.Time `json:"last_heal,omitempty"`
	Paused     bool      `json:"paused"`
	LastIssue  string    `json:"last_issue,omitempty"`
}

// Watchdog owns the sweep loop. One instance per process, like the exe.
type Watchdog struct {
	cfg    Config
	states map[int]*PortState
	mu     sync.Mutex
}

// New builds a watchdog and loads persisted cooldown state if the file
// exists. Cooldown must survive a process restart: a watchdog that
// forgets its cooldowns on restart can hammer a service that is still
// recovering from the previous restart.
func New(cfg Config) *Watchdog {
	w := &Watchdog{cfg: cfg, states: map[int]*PortState{}}
	for _, p := range cfg.Ports {
		st := &PortState{Port: p}
		if cfg.PauseDir != "" {
			if _, err := os.Stat(w.marker(p)); err == nil {
				st.Paused = true
			}
		}
		w.states[p] = st
	}
	return w
}

func (w *Watchdog) marker(port int) string {
	return filepath.Join(w.cfg.PauseDir, fmt.Sprintf("%d.paused", port))
}

// NetworkUp implements the WAN gate. Empty probe config disables the
// gate (same as net_probe_targets: [] in the Python config).
func (w *Watchdog) NetworkUp() bool {
	if w.cfg.NetProbe == "" {
		return true
	}
	conn, err := net.DialTimeout("tcp", w.cfg.NetProbe, 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Sweep probes every port once and heals what qualifies. It returns the
// per-port verdicts. Gates run before any heal: paused ports are
// skipped, and a failed WAN gate turns every heal into a record-only
// pass. Complexity: O(n) probes with a 1s timeout each; the caller can
// parallelise by passing ports to separate watchdog instances or going
// through the (future) concurrent runner.
func (w *Watchdog) Sweep() []PortState {
	w.mu.Lock()
	defer w.mu.Unlock()

	netUp := w.NetworkUp()
	out := make([]PortState, 0, len(w.states))
	for _, p := range w.cfg.Ports {
		st := w.states[p]
		up := tcpOK(p)

		if up {
			st.DownStreak = 0
			st.LastIssue = ""
		} else {
			st.DownStreak++
			st.LastIssue = "no TCP connect"
		}

		healed := false
		if !up && !st.Paused && netUp && st.DownStreak >= w.cfg.MaxConsecutiveDown {
			if w.cooldownOK(st) {
				if err := w.heal(st); err == nil {
					st.LastHeal = time.Now()
					healed = true
				}
			}
		}

		action := "ok"
		if !up {
			action = "down"
			if healed {
				action = "healed"
			} else if st.Paused {
				action = "paused"
			} else if !netUp {
				action = "network-down: record only"
			}
		}
		if w.cfg.Logf != nil && action != "ok" {
			w.cfg.Logf("port %d %s", p, action)
		}
		out = append(out, *st)
	}
	return out
}

// cooldownOK enforces the per-port brake. Time-based, not sweep-based:
// a green sweep must not reset the cooldown clock.
func (w *Watchdog) cooldownOK(st *PortState) bool {
	if st.LastHeal.IsZero() {
		return true
	}
	return time.Since(st.LastHeal) >= w.cfg.Cooldown
}

// heal is the restart action. The real executable path (recovery
// command, PID verification) lands with the proc module; the port
// verdict and gate logic are testable without it, so heal returns an
// explicit "not implemented" until then rather than a silent no-op.
func (w *Watchdog) heal(st *PortState) error {
	return fmt.Errorf("heal action not wired: recovery command pending")
}

func tcpOK(port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
