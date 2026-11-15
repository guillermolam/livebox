package audit

import (
	"fmt"
	"strings"

	"github.com/guillermolam/livebox/api"
)

// Severity levels for findings.
type Severity string

const (
	Critical Severity = "CRITICAL"
	High     Severity = "HIGH"
	Medium   Severity = "MEDIUM"
	Low      Severity = "LOW"
	Info     Severity = "INFO"
)

// Finding is one concrete weakness or hardening recommendation.
type Finding struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Severity     Severity `json:"severity"`
	Description  string   `json:"description"`
	Remediation  string   `json:"remediation"`
	Affected     []string `json:"affected,omitempty"`
	Source       string   `json:"source"`
}

// RuleInput is the data collected from router CGIs, active scans, and passive
// discovery that the rule engine evaluates.
type RuleInput struct {
	Clients     []api.ClientDetail
	Extras      api.ClientDetailsExtras
	DMZ         api.DMZ
	Forwards    []api.PortForward
	DNSRecords  []api.DNSRecord
	StaticLeases []api.StaticLease
	ScanResults []HostResult
	Discovery   []DiscoveryRecord
}

// Evaluate runs all static rules against the collected input and returns the
// findings sorted by severity.
func Evaluate(in RuleInput) []Finding {
	var findings []Finding
	findings = append(findings, evaluateExposure(in)...)
	findings = append(findings, evaluateClients(in)...)
	findings = append(findings, evaluateScans(in)...)
	findings = append(findings, evaluateDiscovery(in)...)

	severityRank := map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}
	for i := range findings {
		findings[i].ID = fmt.Sprintf("LIV-%04d", i+1)
	}

	// Sort by severity, then title.
	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			ri := severityRank[findings[i].Severity]
			rj := severityRank[findings[j].Severity]
			if ri > rj || (ri == rj && findings[i].Title > findings[j].Title) {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
	return findings
}

func evaluateExposure(in RuleInput) []Finding {
	var f []Finding
	if in.Extras.UPnPEnabled {
		f = append(f, Finding{
			Title:       "Global UPnP is enabled",
			Severity:    High,
			Description: "The router allows LAN devices to automatically punch inbound holes through the firewall. This is a common source of unintended internet exposure for IoT and camera devices.",
			Remediation: "Disable UPnP in the router web UI and replace automatic rules with explicit `livebox port-forward set` rules only where required.",
			Source:      "cgi/upnp_osp.js",
		})
	}
	if !in.Extras.MACFilterEnabled {
		f = append(f, Finding{
			Title:       "Wi-Fi MAC filter is not enabled",
			Severity:    Low,
			Description: "Any device that knows the Wi-Fi passphrase can associate. A MAC filter adds a small additional layer for known-device networks.",
			Remediation: "If you run a fixed-device network, enable the Wi-Fi MAC filter and allow-list known devices; otherwise ensure a strong WPA3/WPA2 passphrase and monitor connected clients.",
			Source:      "cgi/firewall_mac_filter.js",
		})
	}
	if in.DMZ.Enabled && in.DMZ.HostIP != "" {
		f = append(f, Finding{
			Title:       "DMZ host configured",
			Severity:    High,
			Description: fmt.Sprintf("The DMZ forwards all unsolicited inbound traffic to %s.", in.DMZ.HostIP),
			Remediation: "Remove the DMZ unless the target host is a deliberately exposed bastion; prefer targeted port forwarding rules.",
			Affected:    []string{in.DMZ.HostIP},
			Source:      "cgi/fw_dmz_osp.js",
		})
	}
	active := 0
	for _, pf := range in.Forwards {
		if pf.Enabled {
			active++
		}
	}
	if active > 0 {
		sev := Low
		if active >= 10 {
			sev = Medium
		}
		f = append(f, Finding{
			Title:       fmt.Sprintf("%d active port forwarding rule(s)", active),
			Severity:    sev,
			Description: fmt.Sprintf("The router has %d active IPv4 port forwarding rule(s). Each one increases the inbound attack surface.", active),
			Remediation: "Review each rule with `livebox port-forward`. Remove any that are unused and restrict source IPs where the router supports it.",
			Source:      "cgi/nat_osp.js",
		})
	}
	return f
}

func evaluateClients(in RuleInput) []Finding {
	var f []Finding
	var iot []string
	var legacy []string
	for _, c := range in.Clients {
		label := fmt.Sprintf("%s (%s / %s)", c.Name, c.IP, c.MAC)
		if isIoTDevice(c) {
			iot = append(iot, label)
		}
		if isLegacyDHCP(c.VendorClass) {
			legacy = append(legacy, label)
		}
	}
	if len(iot) > 0 {
		f = append(f, Finding{
			Title:       fmt.Sprintf("%d IoT/camera device(s) on the main LAN", len(iot)),
			Severity:    Medium,
			Description: "These devices share the same L2 broadcast domain as laptops and phones. A compromise of one device can be used to attack others.",
			Remediation: "Move IoT and cameras to a segmented guest SSID, pin NVR/camera static leases, and restrict their internet access to required endpoints only.",
			Affected:    iot,
			Source:      "cgi/cgi_clients.js",
		})
	}
	if len(legacy) > 0 {
		f = append(f, Finding{
			Title:       fmt.Sprintf("%d device(s) with legacy DHCP/firmware fingerprints", len(legacy)),
			Severity:    Medium,
			Description: "The vendor class string suggests an older embedded Linux/BusyBox DHCP client. These devices often miss security updates.",
			Remediation: "Identify the device, check the vendor for firmware updates, and monitor its open ports with `livebox audit <ip>`.",
			Affected:    legacy,
			Source:      "cgi/cgi_clients.js",
		})
	}

	for _, rec := range in.DNSRecords {
		if rec.Hostname == "" || rec.IP == "" {
			f = append(f, Finding{
				Title:       "Blank or incomplete static DNS record",
				Severity:    Low,
				Description: fmt.Sprintf("A static DNS entry has hostname=%q IP=%q.", rec.Hostname, rec.IP),
				Remediation: "Remove or complete the DNS record in the router UI to avoid confusion and accidental resolution.",
				Affected:    []string{rec.IP},
				Source:      "cgi/dns.js",
			})
		}
	}
	return f
}

func evaluateScans(in RuleInput) []Finding {
	var f []Finding
	for _, hr := range in.ScanResults {
		for _, pr := range hr.Ports {
			if !pr.Open {
				continue
			}
			switch pr.Port {
			case 23:
				f = append(f, Finding{
					Title:       "Telnet port open",
					Severity:    Critical,
					Description: fmt.Sprintf("%s is listening on TCP/23 (Telnet). Credentials and commands are sent in plaintext.", hr.IP),
					Remediation: "Disable Telnet and switch to SSH or the device's encrypted management interface.",
					Affected:    []string{hr.IP},
					Source:      "active scan",
				})
			case 554:
				f = append(f, Finding{
					Title:       "RTSP port open",
					Severity:    High,
					Description: fmt.Sprintf("%s is listening on TCP/554 (RTSP). Camera/NVR streams may be accessible without authentication.", hr.IP),
					Remediation: "Ensure authentication is enabled, rotate default credentials, and restrict access to trusted clients.",
					Affected:    []string{hr.IP},
					Source:      "active scan",
				})
			case 80, 443, 8000, 8008, 8080, 8081, 8443:
				f = append(f, Finding{
					Title:       fmt.Sprintf("Web management port %d open", pr.Port),
					Severity:    Low,
					Description: fmt.Sprintf("%s is listening on TCP/%d (%s).", hr.IP, pr.Port, pr.Protocol),
					Remediation: "Verify the service needs to be reachable from the LAN, keep firmware updated, and use strong credentials.",
					Affected:    []string{hr.IP},
					Source:      "active scan",
				})
			}
		}
	}
	return f
}

func evaluateDiscovery(in RuleInput) []Finding {
	var f []Finding
	ssdp := 0
	for _, r := range in.Discovery {
		if r.Protocol == "ssdp" {
			ssdp++
		}
	}
	if ssdp > 0 {
		f = append(f, Finding{
			Title:       fmt.Sprintf("%d SSDP announcement(s) observed", ssdp),
			Severity:    Info,
			Description: "UPnP/SSDP discovery traffic was observed on the LAN, indicating devices that may request or offer services.",
			Remediation: "If UPnP is disabled at the router, these announcements are limited to the local segment. Review the source devices individually.",
			Source:      "passive sniff",
		})
	}
	return f
}

func isIoTDevice(c api.ClientDetail) bool {
	s := strings.ToLower(c.Name + " " + c.DeviceType + " " + c.VendorClass)
	keywords := []string{"nvr", "camera", "cam", "c210", "esp_", "wiz_", "cozylife", "smart", "iot", "bridge", "hue", "sonoff"}
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

func isLegacyDHCP(vendor string) bool {
	return strings.Contains(strings.ToLower(vendor), "udhcp 1.27")
}
