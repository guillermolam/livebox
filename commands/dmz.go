package commands

import (
	"fmt"

	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// DMZCommand manages the DMZ configuration.
func DMZCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dmz",
		Short: "Manage DMZ",
		Long: undent.Undent(`
			Manage DMZ.
		`),
		Example: undent.Undent(`
			dmz get
		`),
	}

	cmd.AddCommand(
		dmzGetCmd(),
		dmzSetCmd(),
		dmzRmCmd(),
	)

	return cmd
}

var dmzIP string

func dmzSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set <ip>",
		Short: "Enable the DMZ and point it at an IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.DMZSet(cmd.Context(), args[0])
		},
	}
}

func dmzRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Disable the DMZ",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.DMZRm(cmd.Context())
		},
	}
}

func dmzGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the current IP configured in the DMZ",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			dmz, err := client.DMZ(cmd.Context())
			if err != nil {
				return err
			}

			if !dmz.Enabled || dmz.HostIP == "" || dmz.HostIP == "0.0.0.0" {
				fmt.Println("No DMZ configured")
				return nil
			}
			fmt.Println(dmz.HostIP)
			return nil
		},
	}
}
