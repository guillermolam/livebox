package external

import (
	"context"
	"fmt"
	"time"
)

// NotifySend sends a redacted summary to the configured notify provider.
func NotifySend(ctx context.Context, r *Runner, message string) (*Record, error) {
	args := []string{"-msg", message}
	out, err := r.Run(ctx, "notify", args...)
	if err != nil {
		return nil, fmt.Errorf("notify failed: %w", err)
	}
	return &Record{
		Stage:           StageNotify,
		Tool:            "notify",
		ScopeApprovalID: r.ScopeApprovalID(),
		Target:          "notification-provider",
		Observation: map[string]any{
			"message": message,
			"output":  string(out),
		},
		Confidence:   Detected,
		TimestampUTC: time.Now().UTC(),
	}, nil
}
