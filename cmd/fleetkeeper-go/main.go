// Command fleetkeeper-go is the CLI entry: scan or guard, one flag
// each. Kept deliberately small — the modules under internal/ are the
// deliverable; this binary wires them to argv.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/muguangyeshang/fleetkeeper-go/internal/discover"
	"github.com/muguangyeshang/fleetkeeper-go/internal/watchdog"
)

func main() {
	ports := flag.String("ports", "", "comma-separated ports to scan/guard")
	existing := flag.String("existing", "", "comma-separated ports already in config (marked, not auto-added)")
	mode := flag.String("mode", "discover", "discover | guard")
	timeout := flag.Duration("timeout", 600*time.Millisecond, "per-probe timeout")
	workers := flag.Int("workers", 16, "concurrent probe workers")
	cooldown := flag.Duration("cooldown", 180*time.Second, "per-port heal cooldown (guard mode)")
	threshold := flag.Int("threshold", 2, "consecutive down sweeps before a heal (guard mode)")
	flag.Parse()

	list, err := parsePorts(*ports)
	if err != nil || len(list) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fleetkeeper-go -ports 11434,4002 [-mode guard] [-existing 4002]")
		os.Exit(2)
	}

	switch *mode {
	case "discover":
		cands := discover.HTTPPorts(list, parseList(*existing), *timeout, *workers)
		out, _ := json.MarshalIndent(cands, "", "  ")
		fmt.Println(string(out))
	case "guard":
		w := watchdog.New(watchdog.Config{
			Ports:              list,
			Cooldown:           *cooldown,
			MaxConsecutiveDown: *threshold,
			Logf: func(f string, a ...interface{}) {
				fmt.Printf(time.Now().Format("15:04:05")+" "+f+"\n", a...)
			},
		})
		for {
			w.Sweep()
			time.Sleep(30 * time.Second)
		}
	default:
		fmt.Fprintln(os.Stderr, "-mode must be discover or guard")
		os.Exit(2)
	}
}

func parsePorts(s string) ([]int, error) {
	return parseList(s), nil
}

func parseList(s string) []int {
	var out []int
	for _, part := range split(s) {
		var p int
		if _, err := fmt.Sscanf(part, "%d", &p); err == nil && p > 0 && p < 65536 {
			out = append(out, p)
		}
	}
	return out
}

func split(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' || r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
