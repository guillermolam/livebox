package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// KatanaScan runs a bounded web crawl against an approved HTTP service.
func KatanaScan(ctx context.Context, r *Runner, startURL string) ([]Record, error) {
	host, _, err := splitHostPort(startURL)
	if err != nil {
		return nil, err
	}
	if err := r.ValidateIP(host); err != nil {
		return nil, fmt.Errorf("scope check failed for %s: %w", host, err)
	}

	args := []string{
		"-u", startURL,
		"-jsonl",
		"-silent",
		"-d", "2",
		"-ct", "30s",
	}
	out, err := r.Run(ctx, "katana", args...)
	if err != nil {
		return nil, fmt.Errorf("katana failed: %w", err)
	}

	return parseKatanaOutput(startURL, r.ScopeApprovalID(), out), nil
}

func parseKatanaOutput(startURL, scopeID string, out []byte) []Record {
	var records []Record
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var observation map[string]any
		if err := json.Unmarshal([]byte(line), &observation); err != nil {
			continue
		}
		records = append(records, Record{
			Stage:           StageKatana,
			Tool:            "katana",
			ScopeApprovalID: scopeID,
			Target:          startURL,
			Observation:     observation,
			Confidence:      Detected,
			TimestampUTC:    time.Now().UTC(),
		})
	}
	return records
}
