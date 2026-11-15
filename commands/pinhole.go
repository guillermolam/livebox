package commands

import (
	"fmt"
	"strings"

	"github.com/guillermolam/livebox/utils"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

// PinholeCommand manages IPv4 pinhole (firewall customization) rules.
func PinholeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pinhole",
		Short: "Manage IPv4 pinhole rules",
		Long: undent.Undent(`
			Manage IPv4 pinhole (firewall customization) rules.
		`),
	}

	cmd.AddCommand(pinholeLsCmd(), pinholeSetCmd(), pinholeRmCmd())
	return cmd
}

func pinholeLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all pinhole rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			rules, err := client.Pinholes(cmd.Context())
			if err != nil {
				return err
			}
			rows := make([][]string, 0, len(rules))
			for _, r := range rules {
				from := r.SourceIP
				if r.SourceMask != "" {
					from += "/" + r.SourceMask
				}
				if r.SourcePort != "" {
					from += ":" + r.SourcePort
				}
				to := r.DestIP
				if r.DestPort != "" {
					to += ":" + r.DestPort
				}
				rows = append(rows, []string{r.ID, from, to, r.Protocol, r.Action})
			}
			utils.PrintTable([]string{"ID", "from", "to", "proto", "action"}, rows)
			return nil
		},
	}
}

var (
	pinholeName       string
	pinholeProtocol   string
	pinholeSourceIP   string
	pinholeSourceMask string
	pinholeSourcePort string
	pinholeDestIP     string
	pinholeDestMask   string
	pinholeDestPort   string
	pinholeAction     string
)

func pinholeSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Add a pinhole rule",
		Example: undent.Undent(`
			pinhole set --name web --protocol tcp --dest-ip 192.168.1.10 --dest-port 8080
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if pinholeDestIP == "" {
				return fmt.Errorf("--dest-ip is required")
			}
			switch strings.ToLower(pinholeProtocol) {
			case "tcp", "udp":
			default:
				return fmt.Errorf("unknown protocol %q (want tcp or udp)", pinholeProtocol)
			}
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.PinholeSet(cmd.Context(),
				pinholeName, strings.ToLower(pinholeProtocol),
				pinholeSourceIP, pinholeSourceMask, pinholeSourcePort,
				pinholeDestIP, pinholeDestMask, pinholeDestPort,
				pinholeAction)
		},
	}
	cmd.Flags().StringVar(&pinholeName, "name", "", "Rule name")
	cmd.Flags().StringVar(&pinholeProtocol, "protocol", "tcp", "Protocol: tcp or udp")
	cmd.Flags().StringVar(&pinholeSourceIP, "source-ip", "", "Source IP (optional)")
	cmd.Flags().StringVar(&pinholeSourceMask, "source-mask", "", "Source mask: 255.255.255.255, 255.255.255.0, 255.255.0.0 or 255.0.0.0")
	cmd.Flags().StringVar(&pinholeSourcePort, "source-port", "", "Source port or range (optional)")
	cmd.Flags().StringVar(&pinholeDestIP, "dest-ip", "", "Destination IP (required)")
	cmd.Flags().StringVar(&pinholeDestMask, "dest-mask", "255.255.255.255", "Destination mask")
	cmd.Flags().StringVar(&pinholeDestPort, "dest-port", "", "Destination port")
	cmd.Flags().StringVar(&pinholeAction, "action", "ACCEPT", "Rule action")
	return cmd
}

func pinholeRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Remove a pinhole rule by its name",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}
			return client.PinholeRm(cmd.Context(), args[0])
		},
	}
}
