package commands

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/guillermolam/livebox/api"
	"github.com/guillermolam/livebox/audit"
	"github.com/guillermolam/livebox/utils"
	"github.com/spf13/cobra"
)

// AuditCommand returns the "livebox audit" command tree.
func AuditCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit [all|<ip|mac|name>]",
		Short: "Audit clients and exposure surface",
		Long: `Audit the devices seen by the router and the router's exposure surface.

Without arguments or with "all", the command lists every client and prints a
short exposure summary (UPnP, DMZ, Wi-Fi MAC filter, and port forwarding rules).

With a target, only clients whose IP, MAC, or name matches are shown.

Active TCP scanning and passive discovery require an approved scope manifest.
Create one with "livebox audit approve".`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) > 0 && args[0] != "all" {
				target = args[0]
			}
			return runAudit(cmd, target)
		},
	}

	cmd.PersistentFlags().String("manifest", defaultManifestPath(), "Path to the approved scope manifest")
	cmd.Flags().String("output", "table", "Output format: table, json, markdown")
	cmd.Flags().Bool("scan", false, "Run an active TCP port scan against approved devices")
	cmd.Flags().Duration("listen", 0, "Listen for multicast/broadcast discovery traffic (e.g. 10s)")

	cmd.AddCommand(auditApproveCommand())
	return cmd
}

func auditApproveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "approve [<ip|mac|name>]",
		Short: "Approve current LAN clients for active auditing",
		Long: `Build and save a scope manifest for the clients currently seen by the router.

Without a target, every online client is approved. With a target, only clients
whose IP, MAC, or name matches are added to the manifest.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := ""
			if len(args) > 0 {
				target = args[0]
			}
			return runApprove(cmd, target)
		},
	}
}

// SniffCommand returns the "livebox sniff" command.
func SniffCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sniff",
		Short: "Capture a passive network discovery snapshot",
		Long: `Listen for multicast/broadcast discovery traffic (mDNS, SSDP, LLMNR, NBNS)
for the configured duration and print the observed announcements.

This is the read-only entry point for the sniffer engine. It does not send any
packets and does not require root privileges for UDP discovery capture.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			duration, _ := cmd.Flags().GetDuration("duration")
			return runSniff(cmd, duration)
		},
	}
	cmd.Flags().Duration("duration", 10*time.Second, "Capture duration (0 = until Ctrl-C)")
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
	filtered := filterClientsDetail(clients, target)

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

	dmz, _ := client.DMZ(cmd.Context())
	forwards, _ := client.PortForwards(cmd.Context())
	dns, _ := client.DNSRecords(cmd.Context())
	static, _ := client.StaticLeases(cmd.Context())

	input := audit.RuleInput{
		Clients:      filtered,
		Extras:       extras,
		DMZ:          dmz,
		Forwards:     forwards,
		DNSRecords:   dns,
		StaticLeases: static,
	}

	manifestPath, _ := cmd.Flags().GetString("manifest")
	if manifestPath == "" {
		manifestPath = defaultManifestPath()
	}

	scan, _ := cmd.Flags().GetBool("scan")
	listen, _ := cmd.Flags().GetDuration("listen")

	if scan || listen > 0 {
		manifest, loadErr := audit.LoadManifest(manifestPath)
		if loadErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Note: active probing skipped: %v\n", loadErr)
		} else {
			if scan {
				input.ScanResults = runScan(cmd.Context(), manifest, filtered)
			}
			if listen > 0 {
				input.Discovery = runDiscovery(cmd.Context(), listen)
			}
		}
	}

	findings := audit.Evaluate(input)

	output, _ := cmd.Flags().GetString("output")
	switch output {
	case "json":
		return audit.RenderJSON(cmd.OutOrStdout(), findings)
	case "markdown":
		return audit.RenderMarkdown(cmd.OutOrStdout(), findings)
	default:
		if len(findings) > 0 {
			fmt.Println()
			fmt.Println(audit.RenderTable(findings))
		}
	}
	return nil
}

func runApprove(cmd *cobra.Command, target string) error {
	client, err := clientFromConfig(cmd)
	if err != nil {
		return err
	}

	clients, _, err := client.ClientDetails(cmd.Context())
	if err != nil {
		return err
	}
	filtered := filterClientsDetail(clients, target)
	if len(filtered) == 0 {
		return fmt.Errorf("no clients matched %q", target)
	}

	approvalID := fmt.Sprintf("scope-%d", time.Now().UTC().Unix())
	devices := make([]audit.Device, 0, len(filtered))
	for _, c := range filtered {
		devices = append(devices, audit.Device{
			Hostname: c.Name,
			MAC:      c.MAC,
			IPv4:     c.IP,
			Interface: c.Interface,
			SSID:     c.SSID,
			Band:     c.Band,
			Assignment: c.Assignment,
		})
	}

	manifest, err := audit.NewManifest(approvalID, devices)
	if err != nil {
		return err
	}

	path, _ := cmd.Flags().GetString("manifest")
	if path == "" {
		path = defaultManifestPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if err := audit.SaveManifest(path, manifest); err != nil {
		return err
	}

	fmt.Printf("Approved %d device(s) for active auditing.\n", len(devices))
	fmt.Printf("Manifest saved to: %s\n", path)
	return nil
}

func runScan(ctx context.Context, manifest *audit.Manifest, clients []api.ClientDetail) []audit.HostResult {
	scanner, err := audit.NewScanner(manifest, nil)
	if err != nil {
		return nil
	}

	targets := make([]audit.Target, 0, len(clients))
	for _, c := range clients {
		if c.Status != "Online" {
			continue
		}
		targets = append(targets, audit.Target{
			ID:       audit.DeviceIDFromMAC(c.MAC),
			Hostname: c.Name,
			IP:       c.IP,
			MAC:      c.MAC,
		})
	}

	results, err := scanner.ScanHosts(ctx, targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan warning: %v\n", err)
	}
	return results
}

func runDiscovery(ctx context.Context, duration time.Duration) []audit.DiscoveryRecord {
	sniffer := &audit.Sniffer{Duration: duration}
	records, errs, err := sniffer.Capture(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sniff warning: %v\n", err)
	}
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "Sniff listener error: %s\n", e)
	}
	return records
}

func runSniff(cmd *cobra.Command, duration time.Duration) error {
	records := runDiscovery(cmd.Context(), duration)

	rows := make([][]string, 0, len(records))
	for _, r := range records {
		rows = append(rows, []string{
			r.Timestamp.Format(time.RFC3339),
			r.Protocol,
			fmt.Sprintf("%s:%d", r.SourceIP, r.SourcePort),
			r.Payload,
		})
	}
	utils.PrintTable([]string{"Time", "Protocol", "Source", "Payload"}, rows)
	return nil
}

func filterClientsDetail(clients []api.ClientDetail, target string) []api.ClientDetail {
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
	a = normalizeMACForCompare(a)
	b = normalizeMACForCompare(b)
	return a != "" && b != "" && a == b
}

func normalizeMACForCompare(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, ":", "")
	if _, err := net.ParseMAC(s); err != nil {
		return s
	}
	return s
}

func defaultManifestPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "livebox-audit-scope.json"
	}
	return filepath.Join(home, ".config", "livebox-audit-scope.json")
}
