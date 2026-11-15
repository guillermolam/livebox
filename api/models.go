package api

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var trailingIndexRe = regexp.MustCompile(`^(.+?)(\d+)$`)

// staticIndexRe matches keys of the form static_<field>_<pool>_<idx>,
// e.g. static_name_0_3. The pools are the LANs: 0 is the main LAN, 1 the
// guest LAN (see lan.js).
var staticIndexRe = regexp.MustCompile(`^static_([a-z]+)_(\d+)_(\d+)$`)

// groupByTrailingIndex groups keys of the form <prefix><name><idx> where idx
// is a decimal integer at the very end of the key. It returns a map from index
// to a map of full-key -> value.
func groupByTrailingIndex(d Data, prefix string) map[int]map[string]string {
	groups := make(map[int]map[string]string)
	for k, v := range d.entries {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		m := trailingIndexRe.FindStringSubmatch(k)
		if m == nil {
			continue
		}
		idx, err := strconv.Atoi(m[2])
		if err != nil {
			continue
		}
		if groups[idx] == nil {
			groups[idx] = make(map[string]string)
		}
		groups[idx][k] = v
	}
	return groups
}

// maxKey returns the largest key in the map, or -1 if empty.
func maxKey(m map[int]map[string]string) int {
	max := -1
	for k := range m {
		if k > max {
			max = k
		}
	}
	return max
}

// Device represents a DHCP lease entry from the infoLan cgi file.
type Device struct {
	Name      string
	IP        string
	MAC       string
	LeaseTime string
	Interface string
}

// deviceArrays are the JavaScript array names known to hold the DHCP lease
// table, in order of preference. The array is laid out as:
//
//	[name, ip, mac, leaseTime, interface, name, ip, mac, ...]
var deviceArrays = []string{"dhcp_leaseTime", "dhcp_client"}

// parseDevices parses the DHCP lease array of an infoLan.js or clients.js
// response into device records.
func parseDevices(raw string) ([]Device, error) {
	for _, name := range deviceArrays {
		devices, err := parseDeviceArray(raw, name)
		if err == nil {
			return devices, nil
		}
	}
	return nil, fmt.Errorf("no DHCP lease array (%s) found", strings.Join(deviceArrays, ", "))
}

func parseDeviceArray(raw, varName string) ([]Device, error) {
	marker := "var " + varName + "=["
	start := strings.Index(raw, marker)
	if start == -1 {
		return nil, fmt.Errorf("%s array not found", varName)
	}
	start += len(marker)
	end := strings.Index(raw[start:], "]")
	if end == -1 {
		return nil, fmt.Errorf("%s array not terminated", varName)
	}
	tokens, err := parseJSStringList(raw[start : start+end])
	if err != nil {
		return nil, fmt.Errorf("%s array: %w", varName, err)
	}

	const fieldsPerRecord = 5
	if len(tokens)%fieldsPerRecord != 0 {
		return nil, fmt.Errorf("%s array: expected a multiple of %d fields, got %d", varName, fieldsPerRecord, len(tokens))
	}
	devices := make([]Device, 0, len(tokens)/fieldsPerRecord)
	for i := 0; i < len(tokens); i += fieldsPerRecord {
		devices = append(devices, Device{
			Name:      strings.TrimSpace(tokens[i]),
			IP:        tokens[i+1],
			MAC:       normalizeMAC(tokens[i+2]),
			LeaseTime: tokens[i+3],
			Interface: tokens[i+4],
		})
	}
	return devices, nil
}

// parseJSStringList parses a comma-separated list of single-quoted strings
// and null entries, as found in the router's JavaScript data files. Backslash
// escapes are resolved and null entries become empty strings.
func parseJSStringList(s string) ([]string, error) {
	var tokens []string
	i := 0
	for i < len(s) {
		switch c := s[i]; {
		case c == ',' || c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		case c == '\'':
			i++
			var tok strings.Builder
			closed := false
			for i < len(s) {
				if s[i] == '\\' && i+1 < len(s) {
					tok.WriteByte(s[i+1])
					i += 2
					continue
				}
				if s[i] == '\'' {
					closed = true
					i++
					break
				}
				tok.WriteByte(s[i])
				i++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string at offset %d", i)
			}
			tokens = append(tokens, tok.String())
		case strings.HasPrefix(s[i:], "null"):
			tokens = append(tokens, "")
			i += len("null")
		default:
			return nil, fmt.Errorf("unexpected character %q at offset %d", s[i], i)
		}
	}
	return tokens, nil
}

// PortForward represents a NAT rule from nat_osp.js.
type PortForward struct {
	ID          string
	Description string
	Enabled     bool
	Protocol    string
	PublicPort  string
	PrivateIP   string
	PrivatePort string
	MAC         string
}

func parsePortForwards(data Data) []PortForward {
	groups := groupByTrailingIndex(data, "nat_")
	rules := []PortForward{}
	for i := 0; i <= maxKey(groups); i++ {
		g, ok := groups[i]
		if !ok {
			continue
		}
		if g[fmt.Sprintf("nat_enable%d", i)] == "" {
			continue
		}
		description := g[fmt.Sprintf("nat_description%d", i)]
		// The nat_* table numbers protocols 0=tcp, 1=udp (the pcp_rule_*
		// table uses IP protocol numbers 6/17); translate for display.
		proto := g[fmt.Sprintf("nat_protocol%d", i)]
		switch proto {
		case "0":
			proto = "6"
		case "1":
			proto = "17"
		}
		rules = append(rules, PortForward{
			ID:          description,
			Description: description,
			Enabled:     g[fmt.Sprintf("nat_enable%d", i)] == "1",
			Protocol:    protocolName(proto),
			PublicPort:  g[fmt.Sprintf("nat_public_port%d", i)],
			PrivateIP:   g[fmt.Sprintf("nat_private_ip%d", i)],
			PrivatePort: g[fmt.Sprintf("nat_private_port%d", i)],
			MAC:         normalizeMAC(g[fmt.Sprintf("nat_mac%d", i)]),
		})
	}
	return rules
}

// DMZ holds the DMZ configuration from fw_dmz_osp.js.
type DMZ struct {
	Enabled bool
	HostIP  string
}

func parseDMZ(data Data) DMZ {
	return DMZ{
		Enabled: data.Get("dmz_enable") == "1",
		HostIP:  data.Get("host_ip"),
	}
}

// DNSRecord represents a static DNS entry from dns.js.
type DNSRecord struct {
	Hostname string
	IP       string
}

func parseDNS(data Data) []DNSRecord {
	groups := groupByTrailingIndex(data, "dns_")
	records := []DNSRecord{}
	for i := 0; i <= maxKey(groups); i++ {
		g, ok := groups[i]
		if !ok {
			continue
		}
		host := g[fmt.Sprintf("dns_hostname%d", i)]
		ip := g[fmt.Sprintf("dns_ip%d", i)]
		if host == "" && ip == "" {
			continue
		}
		records = append(records, DNSRecord{Hostname: host, IP: ip})
	}
	return records
}

// StaticLease represents a static DHCP lease from lan_dhcp_static.js.
type StaticLease struct {
	Name   string
	MAC    string
	IP     string
	Active bool
}

func parseStaticLeases(data Data) []StaticLease {
	// Keys are static_<field>_<pool>_<idx>; pool 0 is the main LAN.
	byIdx := make(map[int]map[string]string)
	maxIdx := -1
	for k, v := range data.entries {
		m := staticIndexRe.FindStringSubmatch(k)
		if m == nil || m[2] != "0" {
			continue
		}
		idx, _ := strconv.Atoi(m[3])
		if byIdx[idx] == nil {
			byIdx[idx] = make(map[string]string)
		}
		byIdx[idx][m[1]] = v
		if idx > maxIdx {
			maxIdx = idx
		}
	}

	leases := []StaticLease{}
	for i := 0; i <= maxIdx; i++ {
		g, ok := byIdx[i]
		if !ok {
			continue
		}
		name := g["name"]
		mac := normalizeMAC(g["mac"])
		ip := g["ip"]
		if name == "" && mac == "" && ip == "" {
			continue
		}
		leases = append(leases, StaticLease{
			Name:   name,
			MAC:    mac,
			IP:     ip,
			Active: g["active"] == "1",
		})
	}
	return leases
}

// WLAN holds a snapshot of the Wi-Fi configuration from wlan_combine.js.
type WLAN struct {
	Band24Enabled bool
	Band5Enabled  bool
	Band6Enabled  bool
	SSIDs         []SSID
}

// SSID represents the primary BSS of one band from wlan_combine.js.
// Guest BSSes (wl_ssid24G1, wl_ssid24G3, ...) are not parsed.
type SSID struct {
	Band     string
	SSID     string
	Enabled  bool
	Hidden   bool
	Security string
	Key      string
}

func parseWLAN(data Data) WLAN {
	wlan := WLAN{
		Band24Enabled: data.Get("wl_enable24G") == "1",
		Band5Enabled:  data.Get("wl_enable5G") == "1",
		Band6Enabled:  data.Get("wl_enable6G") == "1",
	}

	for _, band := range []string{"24G", "5G", "6G"} {
		ssid := data.Get(fmt.Sprintf("wl_ssid%s", band))
		enabled := data.Get(fmt.Sprintf("wl_enable%s", band)) == "1"
		if ssid == "" && !enabled {
			// 6 GHz may not be present on all models.
			continue
		}
		wlan.SSIDs = append(wlan.SSIDs, SSID{
			Band:     band,
			SSID:     ssid,
			Enabled:  enabled,
			Hidden:   data.Get(fmt.Sprintf("wl_ssid_hide%s", band)) == "1",
			Security: data.Get(fmt.Sprintf("security_type%s", band)),
			Key:      data.Get(fmt.Sprintf("sharedkey%s", band)),
		})
	}
	return wlan
}

// Speed holds the WAN sync rates from infoInternet.js.
type Speed struct {
	DownstreamKbps int
	UpstreamKbps   int
}

func parseSpeed(data Data) (Speed, error) {
	if !data.Has("DownstreamCurrRate") || !data.Has("UpstreamCurrRate") {
		return Speed{}, fmt.Errorf("WAN sync rates not available; the router may be connected through fiber (GPON)")
	}
	down, err := strconv.Atoi(data.Get("DownstreamCurrRate"))
	if err != nil {
		return Speed{}, fmt.Errorf("parsing DownstreamCurrRate: %w", err)
	}
	up, err := strconv.Atoi(data.Get("UpstreamCurrRate"))
	if err != nil {
		return Speed{}, fmt.Errorf("parsing UpstreamCurrRate: %w", err)
	}
	return Speed{DownstreamKbps: down, UpstreamKbps: up}, nil
}

// normalizeMAC tries to turn a router MAC string into the canonical
// aa:bb:cc:dd:ee:ff form.
func normalizeMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, "-", ":")
	m, err := net.ParseMAC(s)
	if err != nil {
		return s
	}
	return m.String()
}

// protocolName maps the router protocol number to a readable name.
func protocolName(p string) string {
	switch p {
	case "1":
		return "icmp"
	case "6":
		return "tcp"
	case "17":
		return "udp"
	case "256":
		return "tcp/udp"
	default:
		if p == "" {
			return ""
		}
		return "proto(" + p + ")"
	}
}
