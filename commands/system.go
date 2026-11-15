package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// RebootCommand reboots the Livebox. The connection drops for a couple of
// minutes while the router restarts.
func RebootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "reboot",
		Short: "Reboots the livebox",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			fmt.Println("Rebooting the Livebox...")
			return client.Reboot(cmd.Context())
		},
	}
}

// PhoneCommand shows recent phone calls.
func PhoneCommand() *cobra.Command {
	return writeStub("phone", "Show recent phone calls")
}
