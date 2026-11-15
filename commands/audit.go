package commands

import (
	"fmt"
	"net"
	"strings"

	"github.com/guillermolam/livebox/api"
	"github.com/guillermolam/livebox/utils"
	"github.com/spf13/cobra"
)

// AuditCommand returns the "livebox audit" command tree.
//
// Without arguments or with "all", it prints a snapshot of every client seen
// by the router plus the current exposure surface (UPnP, DMZ, MAC filter, port
// forwards). With a target argument, the list is filtered by IP address, MAC
// address, or hostname substring.
func AuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [all|<ip|mac|name>]",
		Short: "Audit clients and exposure surface",
		Long: `Audit the devices seen by the router and the router's exposure surface.

Without arguments or with "all", the command lists every client and prints a
short exposure summary (UPnP, DMZ, Wi-Fi MAC filter, and port forwarding rules).

With a target, only clients whose IP, MAC, or name matches are shown.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) > 0 && args[0] != "all" {
				target = args[0]
			}
			return runAudit(cmd, target)
		},
	}
	return cmd
}

// SniffCommand returns the "livebox sniff" command.
//
// It is currently a read-only network snapshot command. Future milestones will
// add local packet-capture helpers and wireless RF telemetry behind the same
// CLI shape.
func SniffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sniff [all|<ip|mac|name>]",
		Short: "Capture a network client snapshot",
		Long: `Capture a read-only snapshot of the clients currently visible to the router.

This is the CLI entry point for the sniffer engine. Today it reports the same
client list as "livebox audit" with extra interface details; later milestones
will add packet-capture and wireless RF telemetry behind the same command shape.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) > 0 && args[0] != "all" {
				target = args[0]
			}
			return runSniff(cmd, target)
		},
	}
	return cmd
}

func runAudit(cmd *cobra.Command, target string) error {
	client, err := clientFromConfig(cmd)
	if err != nil {
		return err
	}

	clients, extras, err := client.ClientDetails(cmd.Context())
	if err != nil {
		return err
	}
	filtered := filterClients(clients, target)

	rows := make([][]string, 0, len(filtered))
	for _, c := range filtered {
		rows = append(rows, []string{
			c.Name,
			c.IP,
			c.MAC,
			c.Interface,
			c.Status,
			c.Assignment,
		})
	}
	utils.PrintTable([]string{"Name", "IP", "MAC", "Interface", "Status", "Assignment"}, rows)

	if target == "" {
		fmt.Println()
		fmt.Println("Exposure surface:")
		fmt.Printf("  UPnP enabled:            %v\n", extras.UPnPEnabled)
		fmt.Printf("  Wi-Fi MAC filter enabled: %v\n", extras.MACFilterEnabled)

		if dmz, err := client.DMZ(cmd.Context()); err == nil {
			fmt.Printf("  DMZ enabled:             %v\n", dmz.Enabled)
			if dmz.Enabled {
				fmt.Printf("  DMZ host IP:             %s\n", dmz.HostIP)
			}
		}

		if forwards, err := client.PortForwards(cmd.Context()); err == nil {
			active := 0
			for _, f := range forwards {
				if f.Enabled {
					active++
				}
			}
			fmt.Printf("  Port forwarding rules:   %d (%d active)\n", len(forwards), active)
		}
	}

	return nil
}

func runSniff(cmd *cobra.Command, target string) error {
	client, err := clientFromConfig(cmd)
	if err != nil {
		return err
	}

	clients, _, err := client.ClientDetails(cmd.Context())
	if err != nil {
		return err
	}
	filtered := filterClients(clients, target)

	rows := make([][]string, 0, len(filtered))
	for _, c := range filtered {
		rows = append(rows, []string{
			c.Name,
			c.IP,
			c.MAC,
			c.Interface,
			c.Band,
			c.SSID,
		})
	}
	utils.PrintTable([]string{"Name", "IP", "MAC", "Interface", "Band", "SSID"}, rows)
	return nil
}

func filterClients(clients []api.ClientDetail, target string) []api.ClientDetail {
	if target == "" {
		return clients
	}
	target = strings.ToLower(target)
	var out []api.ClientDetail
	for _, c := range clients {
		if strings.EqualFold(c.IP, target) {
			out = append(out, c)
			continue
		}
		if sameMAC(c.MAC, target) {
			out = append(out, c)
			continue
		}
		if strings.Contains(strings.ToLower(c.Name), target) {
			out = append(out, c)
			continue
		}
	}
	return out
}

func sameMAC(a, b string) bool {
	a = normalize(a)
	b = normalize(b)
	return a != "" && b != "" && a == b
}

func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ":", "")
	if _, err := net.ParseMAC(s); err != nil {
		// Not a valid MAC, but keep the cleaned form so callers can still match
		// partial strings.
		return s
	}
	return s
}
