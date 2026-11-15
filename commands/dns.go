package commands

import (
	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// DNSCommand manages static DNS entries.
func DNSCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Manage static DNS entries",
		Example: undent.Undent(`
			dns ls
		`),
	}
	cmd.AddCommand(dnsLsCmd(), writeStub("set", "Set the name of a device"))
	return cmd
}

func dnsLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all static DNS entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			records, err := client.DNSRecords(cmd.Context())
			if err != nil {
				return err
			}

			rows := make([][]string, 0, len(records))
			for _, record := range records {
				rows = append(rows, []string{record.Hostname, record.IP})
			}
			utils.PrintTable([]string{"Hostname", "IP address"}, rows)
			return nil
		},
	}
}
