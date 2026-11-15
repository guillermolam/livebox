package commands

import (
	"github.com/guillermolam/livebox/utils"
	"github.com/spf13/cobra"
)

// FiberCommand shows the GPON/ONT diagnostics: transceiver optics and the
// ONT password needed when bypassing the Livebox with third-party equipment.
func FiberCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "fiber",
		Aliases: []string{"ont"},
		Short:   "Show the fiber (GPON/ONT) transceiver diagnostics",
		RunE: func(cmd *cobra.Command, args []string) error {
			client, err := clientFromConfig(cmd)
			if err != nil {
				return err
			}

			ftth, err := client.FTTH(cmd.Context())
			if err != nil {
				return err
			}

			link := "down"
			if ftth.PhyLink == 1 {
				link = "up"
			}
			utils.PrintTable(
				[]string{"PHY link", "RX power (dBm)", "TX power (dBm)", "Temp (°C)", "Voltage (V)", "Bias (mA)", "ONT password"},
				[][]string{{link, ftth.RxPower, ftth.TxPower, ftth.Temp, ftth.Volt, ftth.Bias, ftth.ONTPassword}},
			)
			return nil
		},
	}
}
