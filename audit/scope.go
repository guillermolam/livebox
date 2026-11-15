// Package audit implements the multi-layer per-device security audit engine
// for livebox-cli: scope manifest, scanner, sniffer, rules, and reports.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// ApprovalStatus indicates whether a device is authorized for auditing.
type ApprovalStatus string

const (
	Approved      ApprovalStatus = "approved"
	Unclassified  ApprovalStatus = "unclassified"
)

// Device is one entry in the audit scope manifest.
// MAC is the stable correlation key; IPv4/IPv6 are the router-observed
// addresses at the time of approval.
type Device struct {
	ID                     string         `json:"device_id"`
	Hostname               string         `json:"hostname"`
	MAC                    string         `json:"mac_address"`
	IPv4                   string         `json:"ipv4"`
	IPv6                   IPv6Addrs      `json:"ipv6"`
	Interface              string         `json:"interface"`
	SSID                   string         `json:"ssid"`
	Band                   string         `json:"band"`
	Assignment             string         `json:"assignment"`
	LastSeenByRouterUTC    time.Time      `json:"last_seen_by_router_utc"`
	ApprovalStatus         ApprovalStatus `json:"approval_status"`
	ApprovalID             string         `json:"scope_approval_id"`
	ApprovedIPAtApproval   string         `json:"approved_ip_at_approval"`
	ApprovedAtUTC          time.Time      `json:"approved_at_utc"`
}

// IPv6Addrs holds the three address families the router may report.
type IPv6Addrs struct {
	GUA []string `json:"gua"`
	LLA []string `json:"lla"`
	ULA []string `json:"ula"`
}

// Manifest is the allowlist of devices that may be actively probed.
type Manifest struct {
	Actor                string    `json:"actor"`
	SourceOfAuthority    string    `json:"source_of_authority"`
	ScopeApprovalID      string    `json:"scope_approval_id"`
	ApprovedAtUTC        time.Time `json:"approved_at_utc"`
	Devices              []Device  `json:"devices"`
	SnapshotHash         string    `json:"config_snapshot_hash"`
	SecretsRedacted      bool      `json:"secrets_redacted"`
	// lookup indexes loaded from Devices; not serialized.
	byMAC map[string]int
	byIP  map[string]int
}

// NormalizeMAC returns the canonical aa:bb:cc:dd:ee:ff form for a valid
// EUI-48 or EUI-64 address. If the input is not a valid MAC, it returns the
// original string trimmed and lowercased, preserving its separators.
func NormalizeMAC(s string) string {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	candidate := strings.ReplaceAll(trimmed, "-", ":")
	m, err := net.ParseMAC(candidate)
	if err != nil {
		return trimmed
	}
	if len(m) != 6 && len(m) != 8 {
		return trimmed
	}
	return m.String()
}

// IsValidMAC reports whether s parses as a valid EUI-48 or EUI-64 MAC.
func IsValidMAC(s string) bool {
	m, err := net.ParseMAC(strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "-", ":"))
	return err == nil && (len(m) == 6 || len(m) == 8)
}

// DeviceIDFromMAC returns a stable opaque identifier derived from a normalized
// MAC address. It intentionally does not expose the MAC in reports.
func DeviceIDFromMAC(mac string) string {
	m := NormalizeMAC(mac)
	sum := sha256.Sum256([]byte(m))
	return hex.EncodeToString(sum[:])[:16]
}

// NewManifest builds a manifest from a list of approved devices, assigning
// normalized MACs, stable IDs, and approval metadata.
func NewManifest(approvalID string, devices []Device) (*Manifest, error) {
	if approvalID == "" {
		return nil, fmt.Errorf("scope_approval_id is required")
	}
	now := time.Now().UTC()
	m := &Manifest{
		Actor:             "authenticated_router_admin",
		SourceOfAuthority: "router_admin_session",
		ScopeApprovalID:   approvalID,
		ApprovedAtUTC:     now,
		SecretsRedacted:   true,
		byMAC:             make(map[string]int),
		byIP:              make(map[string]int),
	}
	for i, d := range devices {
		d.MAC = NormalizeMAC(d.MAC)
		if d.MAC == "" {
			return nil, fmt.Errorf("device at index %d has no MAC address", i)
		}
		if !IsValidMAC(d.MAC) {
			return nil, fmt.Errorf("device at index %d has invalid MAC address %q", i, devices[i].MAC)
		}
		d.ID = DeviceIDFromMAC(d.MAC)
		if d.ApprovalStatus == "" {
			d.ApprovalStatus = Approved
		}
		if d.ApprovedIPAtApproval == "" {
			d.ApprovedIPAtApproval = d.IPv4
		}
		if d.ApprovedAtUTC.IsZero() {
			d.ApprovedAtUTC = now
		}
		if d.LastSeenByRouterUTC.IsZero() {
			d.LastSeenByRouterUTC = now
		}
		m.Devices = append(m.Devices, d)
		m.byMAC[d.MAC] = i
		if d.IPv4 != "" {
			m.byIP[d.IPv4] = i
		}
	}
	return m, nil
}

// LoadManifest reads a manifest from a JSON file and rebuilds its indexes.
func LoadManifest(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	m.byMAC = make(map[string]int)
	m.byIP = make(map[string]int)
	for i, d := range m.Devices {
		m.byMAC[d.MAC] = i
		if d.IPv4 != "" {
			m.byIP[d.IPv4] = i
		}
	}
	return &m, nil
}

// SaveManifest writes the manifest to a JSON file with stable formatting.
func SaveManifest(path string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding manifest: %w", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0600); err != nil {
		return fmt.Errorf("writing manifest: %w", err)
	}
	return nil
}

// Check reports whether the given IP or MAC is currently approved for active
// probing. If a MAC is approved but the supplied IP does not match the
// router-observed IP at approval time, the device is rejected so stale leases
// cannot be probed.
func (m *Manifest) Check(ip, mac string) (Device, error) {
	if m == nil {
		return Device{}, fmt.Errorf("scope manifest is nil")
	}
	mac = NormalizeMAC(mac)
	if mac == "" && ip == "" {
		return Device{}, fmt.Errorf("both IP and MAC are empty")
	}

	// MAC is the stable key. If we know the MAC, the IP must still match the
	// currently approved address to prevent stale-lease targeting.
	if mac != "" {
		idx, ok := m.byMAC[mac]
		if !ok {
			return Device{}, fmt.Errorf("MAC %s is not in the approved scope manifest", mac)
		}
		d := m.Devices[idx]
		if d.ApprovalStatus != Approved {
			return Device{}, fmt.Errorf("device %s (%s) is %s, not approved", d.ID, mac, d.ApprovalStatus)
		}
		if ip != "" && ip != d.IPv4 {
			return Device{}, fmt.Errorf("IP %s does not match approved IP %s for device %s; reconfirm lease before probing", ip, d.IPv4, d.ID)
		}
		return d, nil
	}

	// IP-only lookup is allowed but only if the IP is currently approved and
	// the device record is approved. This still relies on the manifest being
	// built from authoritative router data.
	idx, ok := m.byIP[ip]
	if !ok {
		return Device{}, fmt.Errorf("IP %s is not in the approved scope manifest", ip)
	}
	d := m.Devices[idx]
	if d.ApprovalStatus != Approved {
		return Device{}, fmt.Errorf("device %s (%s) is %s, not approved", d.ID, ip, d.ApprovalStatus)
	}
	return d, nil
}

// IsApproved reports whether an IP is in the manifest and approved.
func (m *Manifest) IsApproved(ip string) bool {
	_, err := m.Check(ip, "")
	return err == nil
}
