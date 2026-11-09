// Command fleetkeeper-go is the CLI entry: scan, guard, or report.
// Kept deliberately small — the modules under internal/ are the
// deliverable; this binary wires them to argv.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/muguangyeshang/fleetkeeper-go/internal/discover"
	"github.com/muguangyeshang/fleetkeeper-go/internal/watchdog"
)

func main() {
	ports := flag.String("ports", "", "comma-separated ports to scan/guard/report")
	existing := flag.String("existing", "", "comma-separated ports already in config (marked, not auto-added)")
	mode := flag.String("mode", "discover", "discover | guard | report")
	timeout := flag.Duration("timeout", 600*time.Millisecond, "per-probe timeout")
	workers := flag.Int("workers", 16, "concurrent probe workers")
	cooldown := flag.Duration("cooldown", 180*time.Second, "per-port heal cooldown (guard mode)")
	threshold := flag.Int("threshold", 2, "consecutive down sweeps before a heal (guard mode)")
	interval := flag.Duration("interval", 60*time.Second, "report cadence (report mode)")
	reporter := flag.String("reporter", "fleetkeeper-go", "machine identity sent with reports")
	cloud := flag.String("cloud", "", "cloud endpoint base URL, e.g. http://localhost:8090")
	token := flag.String("token", "", "JWT from POST /api/login on the cloud")
	flag.Parse()

	list, err := parsePorts(*ports)
	if err != nil || len(list) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fleetkeeper-go -ports 11434,4002 [-mode guard|report] [-cloud http://host:8090 -token JWT]")
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

	case "report":
		// 全家桶链路的第一环：本机 discover 结果周期性推给云端 Spring API。
		// 幂等全量覆盖——断网丢几轮无所谓，下一轮上来就是全量真相。
		if *cloud == "" || *token == "" {
			fmt.Fprintln(os.Stderr, "report mode needs -cloud and -token (POST /api/login first)")
			os.Exit(2)
		}
		for {
			cands := discover.HTTPPorts(list, nil, *timeout, *workers)
			if err := pushReport(*cloud, *token, *reporter, cands); err != nil {
				fmt.Printf(time.Now().Format("15:04:05")+" report failed: %v\n", err)
			} else {
				fmt.Printf(time.Now().Format("15:04:05")+" reported %d services\n", len(cands))
			}
			time.Sleep(*interval)
		}

	default:
		fmt.Fprintln(os.Stderr, "-mode must be discover, guard or report")
		os.Exit(2)
	}
}

// pushReport POSTs one full snapshot. The cloud replaces the reporter's
// rows wholesale, so retries after a network failure cannot duplicate.
func pushReport(cloud, token, reporter string, cands []discover.Candidate) error {
	type row struct {
		Name  string `json:"name"`
		Port  int    `json:"port"`
		Level int    `json:"level"`
	}
	services := make([]row, 0, len(cands))
	for _, c := range cands {
		lvl := 1
		switch c.Confidence {
		case "high":
			lvl = 4
		case "medium":
			lvl = 3
		}
		services = append(services, row{Name: c.Name, Port: c.Port, Level: lvl})
	}
	body, _ := json.Marshal(map[string]interface{}{
		"reporter": reporter,
		"services": services,
	})
	req, err := http.NewRequest("POST", cloud+"/api/report", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("cloud answered HTTP %d", resp.StatusCode)
	}
	return nil
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
