package commands

import (
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// PinholeCommand manages IPv6 pinhole rules.
func PinholeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pinhole",
		Short: "Manage IPv6 pinhole rules",
		Long: undent.Undent(`
			Manage IPv6 pinhole rules.
		`),
	}

	for _, use := range []string{"ls", "set", "rm"} {
		use := use
		cmd.AddCommand(writeStub(use, "Not yet implemented for Livebox 6/7"))
	}

	return cmd
}
