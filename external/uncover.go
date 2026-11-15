package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// UncoverSearch queries passive search indexes for an owned-domain or
// approved-range query. Results are treated as leads, not approved targets.
func UncoverSearch(ctx context.Context, r *Runner, query string) ([]Record, error) {
	args := []string{"-q", query, "-json"}
	out, err := r.Run(ctx, "uncover", args...)
	if err != nil {
		return nil, fmt.Errorf("uncover failed: %w", err)
	}
	return parseUncoverOutput(query, r.ScopeApprovalID(), out), nil
}

func parseUncoverOutput(query, scopeID string, out []byte) []Record {
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
			Stage:           StageUncover,
			Tool:            "uncover",
			ScopeApprovalID: scopeID,
			Target:          query,
			Observation:     observation,
			Confidence:      Inconclusive,
			TimestampUTC:    time.Now().UTC(),
		})
	}
	return records
}
