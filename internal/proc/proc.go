// Package proc implements guarded process operations for the Go port.
//
// The rule carried over from the Python original: there is no
// kill-by-name API, and no PID operation runs without first verifying
// that the process is still the one we decided to touch. On Windows a
// PID can be recycled within seconds, so verification is not paranoia —
// it is the difference between restarting your gateway and killing an
// unrelated process that happened to reuse the PID.
package proc

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// Refused is returned when a guard decides an operation must not run.
// Callers should treat it as authoritative, not retry.
type Refused struct{ Why string }

func (r Refused) Error() string { return "refused: " + r.Why }

// CREATE_NO_WINDOW keeps a restart off the user's desktop — a headless
// watchdog must not flash a console window on every heal.
const createNoWindow = 0x08000000

// procInfo is what we know about one PID before acting.
type procInfo struct {
	PID     int
	Name    string // image name, e.g. "python.exe"
	Cmdline string // full command line; empty means unreadable (never guessed)
}

// describe reads name + command line for a PID. Windows path uses
// PowerShell + CIM (Get-CimInstance) because wmic is removed from
// current Windows builds; the query is one batch call, ~1s.
func describe(pid int) (procInfo, error) {
	info := procInfo{PID: pid}
	if runtime.GOOS != "windows" {
		out, err := exec.Command("ps", "-p", fmt.Sprint(pid), "-o", "comm=").Output()
		if err != nil {
			return info, fmt.Errorf("pid %d not running", pid)
		}
		name := strings.TrimSpace(string(out))
		if name == "" {
			return info, fmt.Errorf("pid %d not running", pid)
		}
		info.Name = name
		info.Cmdline = name // POSIX ps comm is the best we get without /proc parsing
		return info, nil
	}

	script := fmt.Sprintf(
		`(Get-CimInstance Win32_Process -Filter "ProcessId=%d") | `+
			`Select-Object Name,CommandLine | ConvertTo-Json -Compress`, pid)
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = hiddenAttr()
	out, err := cmd.Output()
	if err != nil {
		return info, fmt.Errorf("pid %d query failed: %w", pid, err)
	}
	var row struct {
		Name        string `json:"Name"`
		CommandLine string `json:"CommandLine"`
	}
	if err := json.Unmarshal(out, &row); err != nil {
		return info, fmt.Errorf("pid %d answer unreadable: %w", pid, err)
	}
	if row.Name == "" {
		return info, fmt.Errorf("pid %d not running", pid)
	}
	info.Name = row.Name
	info.Cmdline = row.CommandLine
	return info, nil
}

// VerifyPID checks that `pid` is alive and its command line contains
// `expect`. Empty expect means "alive check only" — allowed, but the
// caller takes responsibility for PID recycling.
func VerifyPID(pid int, expect string) (procInfo, error) {
	info, err := describe(pid)
	if err != nil {
		return info, Refused{Why: err.Error()}
	}
	if expect != "" && !strings.Contains(info.Cmdline, expect) {
		return info, Refused{Why: fmt.Sprintf(
			"pid %d command line does not match expectation (got %q)", pid, info.Cmdline)}
	}
	return info, nil
}

// Restart stops the verified process and starts `command` afresh.
// order: verify first, then stop, then start — stopping an unverified
// PID is exactly the indiscriminate kill the Python version refuses.
// The new process inherits nothing: fresh env, no window, detached.
func Restart(pid int, expect, command string) (procInfo, error) {
	info, err := VerifyPID(pid, expect)
	if err != nil {
		return info, err
	}
	if err := stop(info); err != nil {
		return info, fmt.Errorf("stop pid %d: %w", pid, err)
	}
	// Small grace period so the port is released before the replacement
	// binds; without it the fresh process can race the old one's TIME_WAIT.
	time.Sleep(500 * time.Millisecond)

	var start *exec.Cmd
	if runtime.GOOS == "windows" {
		// Go's exec.Command takes argv, not a verbatim command line
		// (the Python Popen(string) path is CreateProcess-native and has
		// no direct Go equivalent without raw syscalls). Splitting
		// quote-aware keeps paths with spaces working and still avoids
		// cmd.exe — the restart command never passes through a shell.
		parts := splitCommand(command)
		if len(parts) == 0 {
			return info, fmt.Errorf("restart command is empty")
		}
		start = exec.Command(parts[0], parts[1:]...)
		start.SysProcAttr = hiddenAttr()
	} else {
		start = exec.Command("sh", "-c", command)
	}
	start.Env = nil // inherit — restarts keep their service environment
	if err := start.Start(); err != nil {
		return info, fmt.Errorf("start %q: %w", command, err)
	}
	return info, nil
}

func stop(info procInfo) error {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("taskkill", "/PID", fmt.Sprint(info.PID), "/T", "/F")
		cmd.SysProcAttr = hiddenAttr()
		return cmd.Run()
	}
	cmd := exec.Command("kill", fmt.Sprint(info.PID))
	return cmd.Run()
}

// splitCommand splits a one-line command into argv, honouring double
// quotes so "C:\Program Files\x\x.exe" --flag survives as one token.
// Complexity O(n); restart runs rarely, so simplicity beats speed here.
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
