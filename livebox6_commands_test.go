package main

import (
	"context"
	"errors"
	"testing"

	"github.com/spf13/cobra"
)

// runCommand executes a cobra command with the given args in a background
// context and returns the error it produced.
func runCommand(t *testing.T, cmd *cobra.Command, args []string) error {
	t.Helper()
	cmd.SetArgs(args)
	return cmd.ExecuteContext(context.Background())
}

func TestWriteCommandsReturnNotImplemented(t *testing.T) {
	writeCommands := []struct {
		args []string
	}{
		{args: []string{"reboot"}},
		{args: []string{"phone"}},
		{args: []string{"wifi", "enable"}},
		{args: []string{"wifi", "disable"}},
		{args: []string{"wifi", "config", "--ssid", "x"}},
		{args: []string{"port-forward", "set", "x"}},
		{args: []string{"port-forward", "rm", "x"}},
		{args: []string{"dmz", "set", "192.168.1.1"}},
		{args: []string{"dmz", "rm"}},
		{args: []string{"static-lease", "set", "aa:bb:cc:dd:ee:ff", "192.168.1.2"}},
		{args: []string{"static-lease", "rm", "aa:bb:cc:dd:ee:ff"}},
		{args: []string{"dns", "set", "aa:bb:cc:dd:ee:ff", "name"}},
		{args: []string{"pinhole", "ls"}},
		{args: []string{"pinhole", "set", "x"}},
		{args: []string{"pinhole", "rm", "x"}},
	}

	rootCmd := &cobra.Command{Use: "livebox", SilenceUsage: true, SilenceErrors: true}
	rootCmd.AddCommand(
		rebootCmd(),
		phoneCmd(),
		wifiCmd(),
		portForwardCmd(),
		dmzCmd(),
		staticLeaseCmd(),
		dnsCmd(),
		pinholeCmd(),
	)

	for _, tc := range writeCommands {
		t.Run(tc.args[0], func(t *testing.T) {
			err := runCommand(t, rootCmd, tc.args)
			if !errors.Is(err, errLivebox6WriteNotImplemented) {
				t.Errorf("%v returned %v, want errLivebox6WriteNotImplemented", tc.args, err)
			}
		})
	}
}
