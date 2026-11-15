package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SubfinderResult is one host object from subfinder's JSON output.
type SubfinderResult struct {
	Host           string `json:"host"`
	Source         string `json:"source"`
	Input          string `json:"input"`
	Resolver       string `json:"resolver"`
	IsWildcard     bool   `json:"is_wildcard"`
}

// SubfinderEnumerate runs passive subdomain enumeration for an owned domain.
func SubfinderEnumerate(ctx context.Context, r *Runner, domain string) ([]Record, error) {
	args := []string{"-d", domain, "-oJ", "-silent"}
	out, err := r.Run(ctx, "subfinder", args...)
	if err != nil {
		return nil, fmt.Errorf("subfinder failed: %w", err)
	}
	return parseSubfinderOutput(domain, r.ScopeApprovalID(), out), nil
}

func parseSubfinderOutput(domain, scopeID string, out []byte) []Record {
	var records []Record
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res SubfinderResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		records = append(records, Record{
			Stage:           StageSubfinder,
			Tool:            "subfinder",
			ScopeApprovalID: scopeID,
			Target:          domain,
			Observation: map[string]any{
				"host":        res.Host,
				"source":      res.Source,
				"input":       res.Input,
				"resolver":    res.Resolver,
				"is_wildcard": res.IsWildcard,
			},
			Confidence:   Detected,
			TimestampUTC: time.Now().UTC(),
		})
	}
	return records
}
