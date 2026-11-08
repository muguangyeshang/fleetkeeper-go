package watchdog

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real listener helper — same rule as the discover suite: mocks hide
// real bugs.
func listen(t *testing.T) (int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func quietLogger() func(string, ...interface{}) { return func(string, ...interface{}) {} }

func TestHealthyPortStaysAtZeroStreak(t *testing.T) {
	port, stop := listen(t)
	defer stop()

	w := New(Config{Ports: []int{port}, Logf: quietLogger()})
	st := w.Sweep()
	if st[0].DownStreak != 0 || st[0].LastIssue != "" {
		t.Fatalf("healthy port flagged: %+v", st[0])
	}
}

func TestDeadPortAccumulatesStreak(t *testing.T) {
	w := New(Config{Ports: []int{1}, Logf: quietLogger()})
	w.Sweep()
	st := w.Sweep()
	if st[0].DownStreak != 2 {
		t.Fatalf("streak should be 2 after two sweeps, got %d", st[0].DownStreak)
	}
}

func TestNetworkGateBlocksHeal(t *testing.T) {
	// NetProbe at a dead address: the gate must fail and the sweep must
	// record — never heal. This is the "outage turns healers into noise
	// amplifiers" rule, verified end to end.
	w := New(Config{
		Ports:              []int{1},
		NetProbe:           "127.0.0.1:1",
		MaxConsecutiveDown: 1,
		Logf:               quietLogger(),
	})
	st := w.Sweep()[0]
	if st.DownStreak != 1 || st.LastHeal != (time.Time{}) {
		t.Fatalf("gate failed to block: %+v", st)
	}
}

func TestPauseMarkerSkipsPort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "1.paused"), []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}
	w := New(Config{Ports: []int{1}, PauseDir: dir, Logf: quietLogger()})
	st := w.Sweep()[0]
	if !st.Paused {
		t.Fatalf("pause marker not honoured: %+v", st)
	}
}

func TestCooldownSurvivesGreenSweeps(t *testing.T) {
	// The brake that matters: a green sweep must not reset the cooldown
	// clock. Directly verified on the state, not via heal (heal wiring
	// lands with the proc module).
	w := New(Config{Ports: []int{1}, Cooldown: time.Hour, Logf: quietLogger()})
	st := w.states[1]
	st.LastHeal = time.Now().Add(-2 * time.Minute)
	if w.cooldownOK(st) {
		t.Fatal("cooldown ignored a recent heal")
	}
	st.LastHeal = time.Now().Add(-2 * time.Hour)
	if !w.cooldownOK(st) {
		t.Fatal("cooldown never expires")
	}
}
