package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"charm.land/lipgloss/v2"
	"charm.land/lipgloss/v2/table"
)

// RenderTable returns a terminal table string for the given findings.
func RenderTable(findings []Finding) string {
	if len(findings) == 0 {
		return "No findings."
	}

	severityColor := map[Severity]string{
		Critical: "#FF0000",
		High:     "#FF8800",
		Medium:   "#FFCC00",
		Low:      "#00CCFF",
		Info:     "#888888",
	}

	rows := make([][]string, 0, len(findings))
	for _, f := range findings {
		sev := lipgloss.NewStyle().Foreground(lipgloss.Color(severityColor[f.Severity])).Bold(true).Render(string(f.Severity))
		affected := strings.Join(f.Affected, ", ")
		if len(affected) > 60 {
			affected = affected[:57] + "..."
		}
		rows = append(rows, []string{sev, f.ID, f.Title, affected})
	}

	t := table.New().
		Border(lipgloss.NormalBorder()).
		Headers("Severity", "ID", "Finding", "Affected").
		Rows(rows...)
	return t.String()
}

// RenderMarkdown writes a standalone hardening report to w.
func RenderMarkdown(w io.Writer, findings []Finding) error {
	if _, err := fmt.Fprintln(w, "# livebox Hardening Report"); err != nil {
		return err
	}
	fmt.Fprintln(w)
	if len(findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}

	counts := map[Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintln(w, "## Summary")
	for _, s := range []Severity{Critical, High, Medium, Low, Info} {
		if counts[s] > 0 {
			fmt.Fprintf(w, "- **%s**: %d\n", s, counts[s])
		}
	}
	fmt.Fprintln(w)

	for _, f := range findings {
		fmt.Fprintf(w, "## %s — %s\n\n", f.ID, f.Title)
		fmt.Fprintf(w, "- **Severity**: %s\n", f.Severity)
		fmt.Fprintf(w, "- **Source**: %s\n", f.Source)
		if len(f.Affected) > 0 {
			fmt.Fprintf(w, "- **Affected**: %s\n", strings.Join(f.Affected, ", "))
		}
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s\n\n", f.Description)
		fmt.Fprintf(w, "**Remediation:** %s\n\n", f.Remediation)
	}
	return nil
}

// RenderJSON writes findings as newline-delimited or pretty-printed JSON.
func RenderJSON(w io.Writer, findings []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}
