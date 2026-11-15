package external

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// PDTMInstall installs or upgrades a pinned set of ProjectDiscovery tools.
// It is intended for one-shot toolchain setup, not for unattended upgrades.
func PDTMInstall(ctx context.Context, r *Runner, tools []string) (*Record, error) {
	if len(tools) == 0 {
		return nil, fmt.Errorf("at least one tool is required")
	}
	args := []string{"-i", strings.Join(tools, ",")}
	out, err := r.Run(ctx, "pdtm", args...)
	if err != nil {
		return nil, fmt.Errorf("pdtm failed: %w", err)
	}
	return &Record{
		Stage:           StagePDTM,
		Tool:            "pdtm",
		ScopeApprovalID: r.ScopeApprovalID(),
		Target:          strings.Join(tools, ","),
		Observation: map[string]any{
			"installed": tools,
			"output":    string(out),
		},
		Confidence:   Detected,
		TimestampUTC: time.Now().UTC(),
	}, nil
}
