package external

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// InteractshPollResult is a single interaction polled from the server.
type InteractshPollResult struct {
	Protocol      string `json:"protocol"`
	UniqueID      string `json:"unique-id"`
	FullID        string `json:"full-id"`
	QType         string `json:"q-type"`
	RemoteAddress string `json:"remote-address"`
	Timestamp     string `json:"timestamp"`
	RawRequest    string `json:"raw-request"`
	SMTPFrom      string `json:"smtp-from"`
}

// InteractshClient wraps interactsh-client for private out-of-band validation.
// It currently models the polling path; a future iteration can manage the
// long-lived client process and token-authenticated server registration.
type InteractshClient struct {
	Server string
}

// NewInteractshClient returns a client pointing at a self-hosted server.
func NewInteractshClient(server string) *InteractshClient {
	return &InteractshClient{Server: server}
}

// Poll runs interactsh-client -poll against the configured server and returns
// any interactions. The server must already be registered and authenticated
// outside of this wrapper.
func (c *InteractshClient) Poll(ctx context.Context, r *Runner) ([]Record, error) {
	args := []string{"-poll", "-server", c.Server, "-json"}
	out, err := r.Run(ctx, "interactsh-client", args...)
	if err != nil {
		return nil, fmt.Errorf("interactsh-client failed: %w", err)
	}
	return parseInteractshOutput(r.ScopeApprovalID(), out), nil
}

func parseInteractshOutput(scopeID string, out []byte) []Record {
	var records []Record
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var res InteractshPollResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}
		records = append(records, Record{
			Stage:           StageInteract,
			Tool:            "interactsh-client",
			ScopeApprovalID: scopeID,
			Target:          res.RemoteAddress,
			Observation: map[string]any{
				"protocol":       res.Protocol,
				"unique-id":      res.UniqueID,
				"full-id":        res.FullID,
				"remote-address": res.RemoteAddress,
				"timestamp":      res.Timestamp,
			},
			Confidence:   Corroborated,
			TimestampUTC: time.Now().UTC(),
		})
	}
	return records
}
