package commands

import (
	"fmt"

	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// APICommand fetches a raw cgi data file from the router.
func APICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api <cgi-page>",
		Short: "Fetch a raw cgi data file from the router",
		Long: undent.Undent(`
			Fetch a raw cgi data file from the router and print it to stdout.
			Useful for exploring the router data while write support is being
			reverse-engineered.
		`),
		Example: undent.Undent(`
			api nat_osp
			api wlan_combine
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			data, err := client.CGI(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Print(data.Raw)
			return nil
		},
	}
}
