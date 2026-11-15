package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
	"github.com/charmbracelet/fang"
	"github.com/charmbracelet/huh"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

var (
	liveboxAddress  string
	liveboxUsername string
	liveboxPassword string
	debug           bool
)

type Config struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to find the home directory: %w", err)
	}
	return home + "/.config/livebox.yml", nil
}

func loadConfig() (Config, error) {
	config := Config{
		Address:  "192.168.1.1",
		Username: "admin",
	}

	path, err := configPath()
	if err != nil {
		return config, err
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return config, nil // Use default config if file doesn't exist
	}

	configFile, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}

func saveConfig(config Config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	configFile, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Create the necessary directories if they don't exist.
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to find the home directory: %w", err)
	}
	err = os.MkdirAll(home+"/.config", 0755)
	if err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	err = os.WriteFile(path, configFile, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "livebox",
		Short: "A CLI for interacting with a Livebox 6 (Orange)",

		// SilenceUsage prevents Cobra from displaying the command's and
		// subcommands' usage on errors. Most of the errors have nothing to do
		// with the usage of the flags, and it is more confusing than helpful.
		// In case of an issue the flags, the user will still see an helpful
		// error message, and they can use --help to get the usage information.
		// See: https://github.com/spf13/cobra/issues/340#issuecomment-243790200
		SilenceUsage: true,

		// SilenceErrors prevents Cobra from logging the error returned from the
		// subcommands' RunE functions since we want to log the error ourselves
		// once Execute returns.
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&liveboxAddress, "address", "", "IP or hostname of the livebox")
	rootCmd.PersistentFlags().StringVar(&liveboxUsername, "username", "", "Username to use for authentication")
	rootCmd.PersistentFlags().StringVar(&liveboxPassword, "password", "", "Password to use for authentication")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")

	rootCmd.AddCommand(
		loginCmd(),
		lsCmd(),
		rebootCmd(),
		phoneCmd(),
		speedCmd(),
		portForwardCmd(),
		pinholeCmd(),
		apiCmd(),
		staticLeaseCmd(),
		dmzCmd(),
		wifiCmd(),
		dnsCmd(),
	)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	err := fang.Execute(ctx, rootCmd)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func mergeFlagsWithConfig(config Config) (address, username, password string) {
	address = liveboxAddress
	if address == "" {
		address = config.Address
	}
	username = liveboxUsername
	if username == "" {
		username = config.Username
	}
	password = liveboxPassword
	if password == "" {
		password = config.Password
	}
	return address, username, password
}

// clientFromConfig logs in to the Livebox using the flags and configuration.
func clientFromConfig(ctx context.Context) (*livebox6Client, error) {
	config, err := loadConfig()
	if err != nil {
		return nil, err
	}
	address, username, password := mergeFlagsWithConfig(config)
	return newLivebox6Client(ctx, address, username, password)
}

// errLivebox6WriteNotImplemented is returned by every command that changes
// the router configuration: the apply_abstract.cgi payloads are not known yet.
var errLivebox6WriteNotImplemented = errors.New("this command is not yet implemented for Livebox 6/7; capture the browser action and send the HAR to add support")

func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to the livebox and save the information",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}

			var fields []huh.Field

			// Let's let the user know if the username and password already
			// work.
			c, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}
			_, err = newLivebox6Client(cmd.Context(), c.Address, c.Username, c.Password)
			if err == nil {
				fields = append(fields, huh.NewNote().
					Title("🎉 Your credentials are already working. You can still update them if you want."),
				)
			}

			fields = append(fields,
				huh.NewInput().
					Title("Livebox Address").
					Value(&c.Address).
					Placeholder(config.Address).
					Description("Enter the hostname or IP of the Livebox."),
				huh.NewInput().
					Title("Username").
					Value(&c.Username).
					Placeholder(config.Username).
					Description("Enter the username."),
				huh.NewInput().
					Title("Password").
					EchoMode(huh.EchoModePassword).
					Value(&c.Password).
					Description("Enter the password. By default, it is the 8 first chars of the Wi-Fi passcode."),
			)

			form := huh.NewForm(huh.NewGroup(fields...))
			err = form.Run()
			if err != nil {
				return fmt.Errorf("form failed: %w", err)
			}

			// Check that the new config works.
			_, err = newLivebox6Client(cmd.Context(), c.Address, c.Username, c.Password)
			if err != nil {
				return fmt.Errorf("failed to authenticate with new configuration: %w", err)
			}

			err = saveConfig(c)
			if err != nil {
				return err
			}

			fmt.Println("Configuration saved in ~/.config/livebox.yml.")
			return nil
		},
	}
}

func printTable(headers []string, rows [][]string) {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		Headers(headers...).
		Rows(rows...)
	fmt.Println(t.String())
}

// sortByIP sorts devices by their IPv4 address.
func sortDevicesByIP(devices []livebox6Device) {
	slices.SortFunc(devices, func(a, b livebox6Device) int {
		aAddr, aErr := netip.ParseAddr(a.IP)
		bAddr, bErr := netip.ParseAddr(b.IP)
		if aErr != nil || bErr != nil {
			return strings.Compare(a.IP, b.IP)
		}
		return aAddr.Compare(bAddr)
	})
}

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all devices known and their IPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
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
			printTable([]string{"Name", "IP Address", "MAC Address"}, rows)
			return nil
		},
	}
}

func rebootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reboot",
		Short: "Reboots the livebox",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func phoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "phone",
		Short: "Show recent phone calls",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func speedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "speed",
		Short: "Show the Downstream and Upstream speeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
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

func pinholeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pinhole",
		Short: "Manage IPv6 pinhole rules",
		Long: undent.Undent(`
			Manage IPv6 pinhole rules.
		`),
	}

	for _, use := range []string{"ls", "set", "rm"} {
		use := use
		cmd.AddCommand(&cobra.Command{
			Use:                use,
			Short:              "Not yet implemented for Livebox 6/7",
			FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
			RunE: func(cmd *cobra.Command, args []string) error {
				return errLivebox6WriteNotImplemented
			},
		})
	}

	return cmd
}

func portForwardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port-forward",
		Short: "Manage forwarding rules",
		Long: undent.Undent(`
			Manage IPv4 port forwarding rules.
		`),
		Example: undent.Undent(`
			port-forward ls
		`),
	}

	cmd.AddCommand(
		portForwardLsCmd(),
		portForwardWriteCmd("set", "Set a port forwarding rule"),
		portForwardWriteCmd("rm", "Remove a port forwarding rule"),
	)

	return cmd
}

func portForwardLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all port forwarding rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
			if err != nil {
				return err
			}

			rules, err := client.PortForwards(cmd.Context())
			if err != nil {
				return err
			}

			rows := make([][]string, 0, len(rules))
			for _, rule := range rules {
				rows = append(rows, []string{
					rule.ID,
					fmt.Sprintf("%s/%s", rule.PublicPort, rule.Protocol),
					rule.PrivateIP,
					rule.PrivatePort,
				})
			}
			printTable([]string{"ID", "from", "to IP", "to port"}, rows)
			return nil
		},
	}
}

func portForwardWriteCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func staticLeaseCmd() *cobra.Command {
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
		staticLeaseWriteCmd("set", "Set a static lease"),
		staticLeaseWriteCmd("rm", "Remove a static lease"),
	)

	return cmd
}

func staticLeaseLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all static leases",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
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
			printTable([]string{"Name", "MAC address", "IP address", "Active"}, rows)
			return nil
		},
	}
}

func staticLeaseWriteCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func dmzCmd() *cobra.Command {
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
		dmzWriteCmd("set", "Set the DMZ configuration"),
		dmzWriteCmd("rm", "Remove the DMZ configuration"),
	)

	return cmd
}

func dmzGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the current IP configured in the DMZ",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
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

func dmzWriteCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func apiCmd() *cobra.Command {
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
			client, err := clientFromConfig(cmd.Context())
			if err != nil {
				return err
			}

			data, err := client.getCGI(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			fmt.Print(data.raw)
			return nil
		},
	}
}

func wifiCmd() *cobra.Command {
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
		wifiWriteCmd("enable", "Enable WLAN"),
		wifiWriteCmd("disable", "Disable WLAN"),
		wifiWriteCmd("config", "Configure WLAN settings"),
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
	client, err := clientFromConfig(cmd.Context())
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
	printTable([]string{"Band", "SSID", "Enabled", "Hidden", "Security", "Key"}, rows)
	return nil
}

func wifiWriteCmd(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:                use,
		Short:              short,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}

func dnsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Manage static DNS entries",
		Example: undent.Undent(`
			dns ls
		`),
	}
	cmd.AddCommand(dnsLsCmd(), dnsSetCmd())
	return cmd
}

func dnsLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all static DNS entries",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd.Context())
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
			printTable([]string{"Hostname", "IP address"}, rows)
			return nil
		},
	}
}

func dnsSetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "set",
		Short: "Set the name of a device",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errLivebox6WriteNotImplemented
		},
	}
}
