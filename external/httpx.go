package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// HttpxScan runs httpx against one approved host:port and returns a normalized
// record with HTTP/TLS metadata.
func HttpxScan(ctx context.Context, r *Runner, target string) (*Record, error) {
	// target is expected as host:port or URL.
	host, _, err := splitHostPort(target)
	if err != nil {
		return nil, err
	}
	if err := r.ValidateIP(host); err != nil {
		return nil, fmt.Errorf("scope check failed for %s: %w", host, err)
	}

	args := []string{"-u", target, "-json", "-silent"}
	out, err := r.Run(ctx, "httpx", args...)
	if err != nil {
		return nil, fmt.Errorf("httpx failed: %w", err)
	}

	return parseHttpxOutput(target, r.ScopeApprovalID(), out)
}

func parseHttpxOutput(target, scopeID string, out []byte) (*Record, error) {
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
		return &Record{
			Stage:           StageHttpx,
			Tool:            "httpx",
			ScopeApprovalID: scopeID,
			Target:          target,
			Observation:     observation,
			Confidence:      Detected,
			TimestampUTC:    time.Now().UTC(),
		}, nil
	}
	return nil, fmt.Errorf("no httpx result for %s", target)
}

func splitHostPort(target string) (string, string, error) {
	// target may be a URL; strip scheme and path.
	s := target
	if idx := strings.Index(s, "://"); idx != -1 {
		s = s[idx+3:]
	}
	if idx := strings.IndexAny(s, "/?#"); idx != -1 {
		s = s[:idx]
	}
	// If no port, assume the whole string is a host.
	if !strings.Contains(s, ":") {
		return s, "", nil
	}
	parts := strings.SplitN(s, ":", 2)
	return parts[0], parts[1], nil
}
