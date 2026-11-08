package proc

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

// jsonUnmarshal hides the import inside one helper so the rest of the
// file reads as process logic, not JSON plumbing.
func jsonUnmarshal(b []byte, v interface{}) error { return json.Unmarshal(b, v) }

// sleepChild is a real long-lived child process — the same test rule
// as the Python suite: a mock cannot prove a kill works. On Windows
// `ping -n 30` is the classic long sleep with no external dependency.
func sleepChild() (*exec.Cmd, func()) {
	var c *exec.Cmd
	if runtime.GOOS == "windows" {
		c = exec.Command("ping", "-n", "30", "127.0.0.1")
	} else {
		c = exec.Command("sleep", "30")
	}
	_ = c.Start()
	kill := func() {
		if c.Process != nil {
			c.Process.Kill()
			c.Wait()
		}
	}
	return c, kill
}

func TestVerifyPIDAcceptsTheRealChild(t *testing.T) {
	c, kill := sleepChild()
	defer kill()
	time.Sleep(300 * time.Millisecond)

	// expect matches the child's own command line: verification passes.
	info, err := VerifyPID(c.Process.Pid, "ping")
	if err != nil {
		t.Fatalf("verify refused a real child: %v", err)
	}
	if info.Name == "" {
		t.Fatal("verify passed but returned no name")
	}
}

func TestVerifyPIDRefusesAMismatchedExpect(t *testing.T) {
	c, kill := sleepChild()
	defer kill()
	time.Sleep(300 * time.Millisecond)

	_, err := VerifyPID(c.Process.Pid, "zzz-not-in-cmdline")
	if err == nil {
		t.Fatal("mismatched expect must be refused")
	}
	if _, ok := err.(Refused); !ok {
		t.Fatalf("refusal must be a Refused, got %T", err)
	}
}

func TestVerifyPIDRefusesADeadPID(t *testing.T) {
	// Start and immediately stop a process: its PID is dead (and on
	// Windows ripe for recycling — which is why verification exists).
	c, kill := sleepChild()
	kill()
	time.Sleep(300 * time.Millisecond)

	_, err := VerifyPID(c.Process.Pid, "")
	if err == nil {
		t.Fatal("dead PID must be refused")
	}
}

func TestRestartRunsACommand(t *testing.T) {
	// End-to-end: verify the real child, restart it as a fresh ping.
	c, kill := sleepChild()
	defer kill()
	time.Sleep(300 * time.Millisecond)

	info, err := Restart(c.Process.Pid, "ping", "ping -n 20 127.0.0.1")
	if err != nil {
		t.Fatalf("restart failed: %v", err)
	}
	if info.Name == "" {
		t.Fatal("restart returned no process name")
	}
	// The replacement is a real ping we can stop by name-free PID ops:
	// it dies with the test process tree, nothing to clean here.
}

func TestRefusedErrorMessageIsActionable(t *testing.T) {
	r := Refused{Why: "pid 123 not running"}
	if !strings.Contains(r.Error(), "refused") || !strings.Contains(r.Error(), "123") {
		t.Fatalf("error must name the reason and pid: %s", r.Error())
	}
	_ = fmt.Sprint()
}

func TestSplitCommandHonoursQuotes(t *testing.T) {
	got := splitCommand(`"C:\Program Files\My App\svc.exe" --port 4002`)
	if len(got) != 3 || got[0] != `C:\Program Files\My App\svc.exe` || got[2] != "4002" {
		t.Fatalf("quote-aware split broken: %#v", got)
	}
}
