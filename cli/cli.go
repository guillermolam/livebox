// Package cli wires the root command, the global flags, and the signal
// context together, and executes the command tree.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/charmbracelet/fang"
	"github.com/guillermolam/livebox/commands"
	"github.com/spf13/cobra"
)

// Run builds and executes the livebox CLI.
func Run() {
	rootCmd := &cobra.Command{
		Use:   "livebox",
		Short: "A CLI for interacting with a Livebox 6 (Orange)",

		// SilenceUsage prevents Cobra from displaying the command's and
		// subcommands' usage on errors. Most of the errors have nothing to do
		// with the usage of the flags, and it is more confusing than helpful.
		// In case of an issue the flags, the user will still see an helpful
		// error message, and they can use --help to get the usage information.
		// See: https://github.com/spf13/cobra/issues/340#issuecomment-243790200
		SilenceUsage: true,

		// SilenceErrors prevents Cobra from logging the error returned from the
		// subcommands' RunE functions since we want to log the error ourselves
		// once Execute returns.
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().String("address", "", "IP or hostname of the livebox")
	rootCmd.PersistentFlags().String("username", "", "Username to use for authentication")
	rootCmd.PersistentFlags().String("password", "", "Password to use for authentication")
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug output")

	rootCmd.AddCommand(
		commands.LoginCommand(),
		commands.DevicesCommand(),
		commands.RebootCommand(),
		commands.PhoneCommand(),
		commands.SpeedCommand(),
		commands.FiberCommand(),
		commands.PortForwardCommand(),
		commands.PinholeCommand(),
		commands.APICommand(),
		commands.StaticLeaseCommand(),
		commands.DMZCommand(),
		commands.WiFiCommand(),
		commands.DNSCommand(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := fang.Execute(ctx, rootCmd)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
