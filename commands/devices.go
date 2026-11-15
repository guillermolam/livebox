package commands

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/guillermolam/livebox/api"
	"github.com/guillermolam/livebox/utils"
	"github.com/spf13/cobra"
)

// DevicesCommand lists all devices known to the router and their IPs.
func DevicesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all devices known and their IPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			devices, err := client.Devices(cmd.Context())
			if err != nil {
				return err
			}
			sortDevicesByIP(devices)

			rows := make([][]string, 0, len(devices))
			for _, device := range devices {
				rows = append(rows, []string{device.Name, device.IP, device.MAC})
			}
			utils.PrintTable([]string{"Name", "IP Address", "MAC Address"}, rows)
			return nil
		},
	}
}

// sortDevicesByIP sorts devices by their IPv4 address.
func sortDevicesByIP(devices []api.Device) {
	slices.SortFunc(devices, func(a, b api.Device) int {
		aAddr, aErr := netip.ParseAddr(a.IP)
		bAddr, bErr := netip.ParseAddr(b.IP)
		if aErr != nil || bErr != nil {
			return strings.Compare(a.IP, b.IP)
		}
		return aAddr.Compare(bAddr)
	})
}
