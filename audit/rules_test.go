package audit

import (
	"testing"

	"github.com/guillermolam/livebox/api"
)

func TestEvaluateExposure(t *testing.T) {
	in := RuleInput{
		Extras: api.ClientDetailsExtras{UPnPEnabled: true, MACFilterEnabled: false},
		DMZ:    api.DMZ{Enabled: true, HostIP: "192.168.1.10"},
		Forwards: []api.PortForward{
			{Enabled: true},
			{Enabled: true},
			{Enabled: false},
		},
	}
	findings := Evaluate(in)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	wantTitles := map[string]Severity{
		"Global UPnP is enabled":       High,
		"Wi-Fi MAC filter is not enabled": Low,
		"DMZ host configured":          High,
		"2 active port forwarding rule(s)": Low,
	}
	got := make(map[string]Severity)
	for _, f := range findings {
		got[f.Title] = f.Severity
	}
	for title, sev := range wantTitles {
		if got[title] != sev {
			t.Fatalf("%s: got %v, want %v", title, got[title], sev)
		}
	}
}

func TestEvaluateClients(t *testing.T) {
	in := RuleInput{
		Clients: []api.ClientDetail{
			{Name: "NVR", IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:ff", VendorClass: "udhcp 1.27.2"},
			{Name: "laptop", IP: "192.168.1.20", MAC: "11:22:33:44:55:66"},
		},
		DNSRecords: []api.DNSRecord{{Hostname: "", IP: "192.168.1.87"}},
	}
	findings := Evaluate(in)
	var titles []string
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	if !contains(titles, "1 IoT/camera device(s) on the main LAN") {
		t.Fatalf("expected IoT finding, got %v", titles)
	}
	if !contains(titles, "1 device(s) with legacy DHCP/firmware fingerprints") {
		t.Fatalf("expected legacy DHCP finding, got %v", titles)
	}
	if !contains(titles, "Blank or incomplete static DNS record") {
		t.Fatalf("expected DNS finding, got %v", titles)
	}
}

func TestEvaluateScans(t *testing.T) {
	in := RuleInput{
		ScanResults: []HostResult{
			{
				Target: Target{IP: "192.168.1.5"},
				Ports: []PortResult{
					{Port: 23, Protocol: "telnet", Open: true},
					{Port: 554, Protocol: "rtsp", Open: true},
					{Port: 80, Protocol: "http", Open: true},
				},
			},
		},
	}
	findings := Evaluate(in)
	var titles []string
	for _, f := range findings {
		titles = append(titles, f.Title)
	}
	if !contains(titles, "Telnet port open") {
		t.Fatalf("expected telnet finding, got %v", titles)
	}
	if !contains(titles, "RTSP port open") {
		t.Fatalf("expected rtsp finding, got %v", titles)
	}
	if !contains(titles, "Web management port 80 open") {
		t.Fatalf("expected http finding, got %v", titles)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
