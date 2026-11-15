package commands

import (
	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// WiFiCommand views and manages the Wi-Fi configuration.
func WiFiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wifi",
		Short: "View and manage the Wi-Fi configuration",
		Example: undent.Undent(`
			wifi
			wifi status
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return wifiStatus(cmd)
		},
	}

	cmd.AddCommand(
		wifiStatusCmd(),
		writeStub("enable", "Enable WLAN"),
		writeStub("disable", "Disable WLAN"),
		writeStub("config", "Configure WLAN settings"),
	)

	return cmd
}

func wifiStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the Wi-Fi configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			return wifiStatus(cmd)
		},
	}
}

func wifiStatus(cmd *cobra.Command) error {
	client, err := clientFromConfig(cmd)
	if err != nil {
		return err
	}

	wlan, err := client.WLAN(cmd.Context())
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(wlan.SSIDs))
	for _, ssid := range wlan.SSIDs {
		enabled := "no"
		if ssid.Enabled {
			enabled = "yes"
		}
		hidden := "no"
		if ssid.Hidden {
			hidden = "yes"
		}
		rows = append(rows, []string{ssid.Band, ssid.SSID, enabled, hidden, ssid.Security, ssid.Key})
	}
	utils.PrintTable([]string{"Band", "SSID", "Enabled", "Hidden", "Security", "Key"}, rows)
	return nil
}
