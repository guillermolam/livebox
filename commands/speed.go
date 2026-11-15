package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

// SpeedCommand shows the Downstream and Upstream speeds.
func SpeedCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "speed",
		Short: "Show the Downstream and Upstream speeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			speed, err := client.Speed(cmd.Context())
			if err != nil {
				return err
			}

			fmt.Printf("\033[91m↓ %.1f Mbps\033[0m\n\033[92m↑ %.1f Mbps\033[0m\n",
				float64(speed.DownstreamKbps)/1000,
				float64(speed.UpstreamKbps)/1000)
			return nil
		},
	}
}
