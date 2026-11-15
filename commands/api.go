package commands

import (
	"fmt"
	"strings"

	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// APICommand fetches a raw cgi data file or page from the router.
func APICommand() *cobra.Command {
	return &cobra.Command{
		Use:   "api <cgi-page|path>",
		Short: "Fetch a raw cgi data file or UI page from the router",
		Long: undent.Undent(`
			Fetch a raw cgi data file from the router and print it to stdout.
			With a path (starting with /), fetch that page verbatim instead.
			Useful for exploring the router data while write support is being
			reverse-engineered.
		`),
		Example: undent.Undent(`
			api nat_osp
			api wlan_combine
			api /advanced_network_dmz.htm
			api /js/global.js
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			if strings.HasPrefix(args[0], "/") {
				body, err := client.Get(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				fmt.Print(body)
				return nil
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
