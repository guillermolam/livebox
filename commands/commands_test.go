package commands

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
	writeCommands := [][]string{
		{"reboot"},
		{"phone"},
		{"wifi", "enable"},
		{"wifi", "disable"},
		{"wifi", "config", "--ssid", "x"},
		{"dmz", "set", "192.168.1.1"},
		{"dmz", "rm"},
		{"pinhole", "ls"},
		{"pinhole", "set", "x"},
		{"pinhole", "rm", "x"},
	}

	rootCmd := &cobra.Command{Use: "livebox", SilenceUsage: true, SilenceErrors: true}
	rootCmd.AddCommand(
		RebootCommand(),
		PhoneCommand(),
		WiFiCommand(),
		PortForwardCommand(),
		DMZCommand(),
		StaticLeaseCommand(),
		DNSCommand(),
		PinholeCommand(),
	)

	for _, args := range writeCommands {
		args := args
		t.Run(args[0], func(t *testing.T) {
			err := runCommand(t, rootCmd, args)
			if !errors.Is(err, errWriteNotImplemented) {
				t.Errorf("%v returned %v, want errWriteNotImplemented", args, err)
			}
		})
	}
}
