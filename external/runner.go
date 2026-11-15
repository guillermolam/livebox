package external

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/guillermolam/livebox/audit"
)

// Runner executes external binaries behind the scope manifest. It pins
// timeout, working directory, and dry-run behavior for every tool.
type Runner struct {
	Manifest *audit.Manifest
	Timeout  time.Duration
	WorkDir  string
	DryRun   bool
}

// NewRunner validates the manifest and returns a runner with sensible defaults.
func NewRunner(manifest *audit.Manifest) (*Runner, error) {
	if manifest == nil {
		return nil, errors.New("a scope manifest is required to run external tools")
	}
	return &Runner{
		Manifest: manifest,
		Timeout:  5 * time.Minute,
	}, nil
}

// ValidateIP returns an error if the supplied IP is not approved for probing.
func (r *Runner) ValidateIP(ip string) error {
	_, err := r.Manifest.Check(ip, "")
	return err
}

// ScopeApprovalID returns the manifest's approval ID for records.
func (r *Runner) ScopeApprovalID() string {
	return manifestApprovalID(r.Manifest)
}

func manifestApprovalID(m *audit.Manifest) string {
	if m == nil {
		return ""
	}
	return m.ScopeApprovalID
}

// Command builds an os/exec.Cmd with the runner defaults applied.
func (r *Runner) Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	if r.WorkDir != "" {
		cmd.Dir = r.WorkDir
	}
	return cmd
}

// Run executes a command or, in dry-run mode, returns a placeholder error.
func (r *Runner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if r.DryRun {
		return nil, fmt.Errorf("dry-run: would run %s %v", name, args)
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()
	cmd := r.Command(ctx, name, args...)
	return cmd.Output()
}

// LookPath reports whether a tool is available on PATH.
func LookPath(name string) (string, error) {
	return exec.LookPath(name)
}
