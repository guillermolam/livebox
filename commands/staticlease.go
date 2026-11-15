package commands

import (
	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// StaticLeaseCommand manages static leases.
func StaticLeaseCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "static-lease",
		Short: "Manage static leases",
		Long: undent.Undent(`
			Manage static leases.
		`),
		Example: undent.Undent(`
			static-lease ls
		`),
	}

	cmd.AddCommand(
		staticLeaseLsCmd(),
		writeStub("set", "Set a static lease"),
		writeStub("rm", "Remove a static lease"),
	)

	return cmd
}

func staticLeaseLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all static leases",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			leases, err := client.StaticLeases(cmd.Context())
			if err != nil {
				return err
			}

			rows := make([][]string, 0, len(leases))
			for _, lease := range leases {
				active := "no"
				if lease.Active {
					active = "yes"
				}
				rows = append(rows, []string{lease.Name, lease.MAC, lease.IP, active})
			}
			utils.PrintTable([]string{"Name", "MAC address", "IP address", "Active"}, rows)
			return nil
		},
	}
}
