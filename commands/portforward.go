package commands

import (
	"fmt"
	"strings"

	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// PortForwardCommand manages IPv4 port forwarding rules.
func PortForwardCommand() *cobra.Command {
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
		portForwardSetCmd(),
		portForwardRmCmd(),
	)

	return cmd
}

func portForwardLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all port forwarding rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
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
			utils.PrintTable([]string{"ID", "from", "to IP", "to port"}, rows)
			return nil
		},
	}
}

var (
	portFwdDescription string
	portFwdPublicPort  string
	portFwdProtocol    string
	portFwdPrivateIP   string
	portFwdPrivatePort string
)

func portForwardSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a port forwarding rule",
		Example: undent.Undent(`
			port-forward set --description ssh --public-port 22 --protocol tcp --ip 192.168.1.10 --private-port 22
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			udp := false
			switch strings.ToLower(portFwdProtocol) {
			case "udp":
				udp = true
			case "tcp":
			case "both", "tcp/udp":
				return fmt.Errorf("protocol %q not supported yet: no HAR capture for it (use tcp or udp)", portFwdProtocol)
			default:
				return fmt.Errorf("unknown protocol %q (want tcp or udp)", portFwdProtocol)
			}
			if portFwdPublicPort == "" || portFwdPrivateIP == "" {
				return fmt.Errorf("--public-port and --ip are required")
			}
			if portFwdPrivatePort == "" {
				portFwdPrivatePort = portFwdPublicPort
			}

			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.SetPortForward(cmd.Context(), portFwdDescription, portFwdPublicPort, portFwdPrivatePort, portFwdPrivateIP, udp)
		},
	}
	cmd.Flags().StringVar(&portFwdDescription, "description", "", "Rule description (also used as its ID)")
	cmd.Flags().StringVar(&portFwdPublicPort, "public-port", "", "External (WAN) port")
	cmd.Flags().StringVar(&portFwdProtocol, "protocol", "tcp", "Protocol: tcp, udp or both")
	cmd.Flags().StringVar(&portFwdPrivateIP, "ip", "", "Internal IP address to forward to")
	cmd.Flags().StringVar(&portFwdPrivatePort, "private-port", "", "Internal port (defaults to the public port)")
	return cmd
}

func portForwardRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <description>",
		Short: "Remove a port forwarding rule by its description",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.PortForwardRm(cmd.Context(), args[0])
		},
	}
}

// protoNumber maps a CLI protocol name to the router's protocol number.
// Kept for reference; the router numbers differ between the pcp_rule_ and
// nat_ tables, so SetPortForward takes the udp bool instead.
func protoNumber(name string) (string, error) {
	switch strings.ToLower(name) {
	case "tcp":
		return "6", nil
	case "udp":
		return "17", nil
	case "both", "tcp/udp":
		return "256", nil
	default:
		return "", fmt.Errorf("unknown protocol %q (want tcp, udp or both)", name)
	}
}
