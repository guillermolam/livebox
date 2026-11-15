package external

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// NucleiScan runs a reviewed Nuclei template lane against approved targets.
// Only explicit template IDs are used; the full catalog is never sprayed.
func NucleiScan(ctx context.Context, r *Runner, targets []string, templates []string) ([]Record, error) {
	if len(targets) == 0 {
		return nil, fmt.Errorf("at least one target is required")
	}
	if len(templates) == 0 {
		return nil, fmt.Errorf("at least one template ID is required")
	}

	for _, t := range targets {
		host, _, err := splitHostPort(t)
		if err != nil {
			return nil, err
		}
		if err := r.ValidateIP(host); err != nil {
			return nil, fmt.Errorf("scope check failed for %s: %w", host, err)
		}
	}

	args := []string{"-jsonl", "-silent"}
	for _, t := range targets {
		args = append(args, "-u", t)
	}
	for _, tpl := range templates {
		args = append(args, "-t", tpl)
	}

	out, err := r.Run(ctx, "nuclei", args...)
	if err != nil {
		return nil, fmt.Errorf("nuclei failed: %w", err)
	}

	return parseNucleiOutput(targets, r.ScopeApprovalID(), templates, out), nil
}

func parseNucleiOutput(targets []string, scopeID string, templates []string, out []byte) []Record {
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
		target := strings.Join(targets, ",")
		if t, ok := observation["host"].(string); ok {
			target = t
		}
		templateID := ""
		if t, ok := observation["template-id"].(string); ok {
			templateID = t
		}
		hashInput := scopeID + target + templateID + line
		sum := sha256.Sum256([]byte(hashInput))
		records = append(records, Record{
			Stage:           StageNuclei,
			Tool:            "nuclei",
			ScopeApprovalID: scopeID,
			Target:          target,
			Observation:     observation,
			FindingID:       hex.EncodeToString(sum[:])[:16],
			Confidence:      Detected,
			TimestampUTC:    time.Now().UTC(),
		})
	}
	return records
}
