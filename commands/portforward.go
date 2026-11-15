package commands

import (
	"fmt"

	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// PortForwardCommand manages IPv4 port forwarding rules.
func PortForwardCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port-forward",
		Short: "Manage forwarding rules",
		Long: undent.Undent(`
			Manage IPv4 port forwarding rules.
		`),
		Example: undent.Undent(`
			port-forward ls
		`),
	}

	cmd.AddCommand(
		portForwardLsCmd(),
		writeStub("set", "Set a port forwarding rule"),
		writeStub("rm", "Remove a port forwarding rule"),
	)

	return cmd
}

func portForwardLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all port forwarding rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			rules, err := client.PortForwards(cmd.Context())
			if err != nil {
				return err
			}

			rows := make([][]string, 0, len(rules))
			for _, rule := range rules {
				rows = append(rows, []string{
					rule.ID,
					fmt.Sprintf("%s/%s", rule.PublicPort, rule.Protocol),
					rule.PrivateIP,
					rule.PrivatePort,
				})
			}
			utils.PrintTable([]string{"ID", "from", "to IP", "to port"}, rows)
			return nil
		},
	}
}
