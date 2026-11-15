package audit

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderTable(t *testing.T) {
	findings := []Finding{
		{ID: "LIV-0001", Title: "UPnP enabled", Severity: High, Description: "desc", Remediation: "fix", Source: "cgi"},
	}
	out := RenderTable(findings)
	if !strings.Contains(out, "UPnP") {
		t.Fatalf("expected table to contain finding title, got:\n%s", out)
	}
}

func TestRenderMarkdown(t *testing.T) {
	findings := []Finding{
		{ID: "LIV-0001", Title: "UPnP enabled", Severity: High, Description: "desc", Remediation: "fix", Source: "cgi"},
	}
	var buf bytes.Buffer
	if err := RenderMarkdown(&buf, findings); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "# livebox Hardening Report") {
		t.Fatal("expected markdown header")
	}
	if !strings.Contains(out, "**Severity**: HIGH") {
		t.Fatalf("expected severity line, got:\n%s", out)
	}
}

func TestRenderJSON(t *testing.T) {
	findings := []Finding{
		{ID: "LIV-0001", Title: "UPnP enabled", Severity: High, Description: "desc", Remediation: "fix", Source: "cgi"},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, findings); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "UPnP enabled") {
		t.Fatal("expected JSON to contain finding title")
	}
}
