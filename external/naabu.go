package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// NaabuResult is a single line of naabu's -json output.
type NaabuResult struct {
	Host string `json:"host"`
	IP   string `json:"ip"`
	Port int    `json:"port"`
	URL  string `json:"url"`
}

// NaabuScan runs naabu against one approved host with a bounded port list.
// If ports is empty, naabu uses its default top-ports list; this is only
// allowed when the engagement explicitly permits it.
func NaabuScan(ctx context.Context, r *Runner, host string, ports []int) ([]Record, error) {
	if err := r.ValidateIP(host); err != nil {
		return nil, fmt.Errorf("scope check failed for %s: %w", host, err)
	}

	args := []string{"-host", host, "-json", "-silent"}
	if len(ports) > 0 {
		args = append(args, "-p", strings.Join(intSliceToStrings(ports), ","))
	}

	out, err := r.Run(ctx, "naabu", args...)
	if err != nil {
		return nil, fmt.Errorf("naabu failed: %w", err)
	}

	return parseNaabuOutput(host, r.ScopeApprovalID(), out), nil
}

func parseNaabuOutput(host, scopeID string, out []byte) []Record {
	var records []Record
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res NaabuResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		records = append(records, Record{
			Stage:           StageNaabu,
			Tool:            "naabu",
			ScopeApprovalID: scopeID,
			Target:          host,
			Observation: map[string]any{
				"host": res.Host,
				"ip":   res.IP,
				"port": res.Port,
				"url":  res.URL,
			},
			Confidence:   Detected,
			TimestampUTC: time.Now().UTC(),
		})
	}
	return records
}

func intSliceToStrings(in []int) []string {
	out := make([]string, 0, len(in))
	for _, n := range in {
		out = append(out, strconv.Itoa(n))
	}
	return out
}
