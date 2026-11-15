package commands

import "github.com/spf13/cobra"

// RebootCommand reboots the Livebox.
func RebootCommand() *cobra.Command {
	return writeStub("reboot", "Reboots the livebox")
}

// PhoneCommand shows recent phone calls.
func PhoneCommand() *cobra.Command {
	return writeStub("phone", "Show recent phone calls")
}
