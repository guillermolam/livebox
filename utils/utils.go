// Package utils provides small helpers shared by the CLI commands.
package utils

import (
	"fmt"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

// PrintTable renders a bordered table with the given headers and rows.
func PrintTable(headers []string, rows [][]string) {
	t := table.New().
		Border(lipgloss.NormalBorder()).
		Headers(headers...).
		Rows(rows...)
	fmt.Println(t.String())
}
