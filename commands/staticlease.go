package commands

import (
	"fmt"

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
		staticLeaseSetCmd(),
		staticLeaseRmCmd(),
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

var (
	staticLeaseName string
	staticLeaseMAC  string
	staticLeaseIP   string
)

func staticLeaseSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a static lease",
		Example: undent.Undent(`
			static-lease set --name nas --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.10
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if staticLeaseMAC == "" || staticLeaseIP == "" {
				return fmt.Errorf("--mac and --ip are required")
			}

			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.StaticLeaseSet(cmd.Context(), staticLeaseMAC, staticLeaseIP, staticLeaseName)
		},
	}
	cmd.Flags().StringVar(&staticLeaseName, "name", "", "Device name")
	cmd.Flags().StringVar(&staticLeaseMAC, "mac", "", "MAC address")
	cmd.Flags().StringVar(&staticLeaseIP, "ip", "", "IP address to reserve")
	return cmd
}

func staticLeaseRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <mac>",
		Short: "Remove a static lease by its MAC address",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.StaticLeaseRm(cmd.Context(), args[0])
		},
	}
}
