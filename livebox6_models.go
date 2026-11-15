package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var livebox6TrailingIndexRe = regexp.MustCompile(`^(.+?)(\d+)$`)

// livebox6StaticIndexRe matches keys of the form static_<field>_<pool>_<idx>,
// e.g. static_name_0_3. The pools are the LANs: 0 is the main LAN, 1 the
// guest LAN (see lan.js).
var livebox6StaticIndexRe = regexp.MustCompile(`^static_([a-z]+)_(\d+)_(\d+)$`)

// groupByTrailingIndex groups keys of the form <prefix><name><idx> where idx
// is a decimal integer at the very end of the key. It returns a map from index
// to a map of full-key -> value.
func groupByTrailingIndex(d cgiData, prefix string) map[int]map[string]string {
	groups := make(map[int]map[string]string)
	for k, v := range d.entries {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		m := livebox6TrailingIndexRe.FindStringSubmatch(k)
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

// livebox6Device represents a DHCP lease entry from the infoLan cgi file.
type livebox6Device struct {
	Name      string
	IP        string
	MAC       string
	LeaseTime string
	Interface string
}

// livebox6DeviceArrays are the JavaScript array names known to hold the DHCP
// lease table, in order of preference. The array is laid out as:
//
//	[name, ip, mac, leaseTime, interface, name, ip, mac, ...]
var livebox6DeviceArrays = []string{"dhcp_leaseTime", "dhcp_client"}

// livebox6ParseDevices parses the DHCP lease array of an infoLan.js or
// clients.js response into device records.
func livebox6ParseDevices(raw string) ([]livebox6Device, error) {
	for _, name := range livebox6DeviceArrays {
		devices, err := parseDeviceArray(raw, name)
		if err == nil {
			return devices, nil
		}
	}
	return nil, fmt.Errorf("no DHCP lease array (%s) found", strings.Join(livebox6DeviceArrays, ", "))
}

func parseDeviceArray(raw, varName string) ([]livebox6Device, error) {
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
	devices := make([]livebox6Device, 0, len(tokens)/fieldsPerRecord)
	for i := 0; i < len(tokens); i += fieldsPerRecord {
		devices = append(devices, livebox6Device{
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

// livebox6PortForward represents a NAT rule from nat_osp.js.
type livebox6PortForward struct {
	ID          string
	Description string
	Enabled     bool
	Protocol    string
	PublicPort  string
	PrivateIP   string
	PrivatePort string
	MAC         string
}

func livebox6ParsePortForwards(data cgiData) []livebox6PortForward {
	groups := groupByTrailingIndex(data, "nat_")
	rules := []livebox6PortForward{}
	for i := 0; i <= maxKey(groups); i++ {
		g, ok := groups[i]
		if !ok {
			continue
		}
		if g[fmt.Sprintf("nat_enable%d", i)] == "" {
			continue
		}
		description := g[fmt.Sprintf("nat_description%d", i)]
		rules = append(rules, livebox6PortForward{
			ID:          description,
			Description: description,
			Enabled:     g[fmt.Sprintf("nat_enable%d", i)] == "1",
			Protocol:    livebox6ProtocolName(g[fmt.Sprintf("nat_protocol%d", i)]),
			PublicPort:  g[fmt.Sprintf("nat_public_port%d", i)],
			PrivateIP:   g[fmt.Sprintf("nat_private_ip%d", i)],
			PrivatePort: g[fmt.Sprintf("nat_private_port%d", i)],
			MAC:         normalizeMAC(g[fmt.Sprintf("nat_mac%d", i)]),
		})
	}
	return rules
}

// livebox6DMZ holds the DMZ configuration from fw_dmz_osp.js.
type livebox6DMZ struct {
	Enabled bool
	HostIP  string
}

func livebox6ParseDMZ(data cgiData) livebox6DMZ {
	return livebox6DMZ{
		Enabled: data.get("dmz_enable") == "1",
		HostIP:  data.get("host_ip"),
	}
}

// livebox6DNSRecord represents a static DNS entry from dns.js.
type livebox6DNSRecord struct {
	Hostname string
	IP       string
}

func livebox6ParseDNS(data cgiData) []livebox6DNSRecord {
	groups := groupByTrailingIndex(data, "dns_")
	records := []livebox6DNSRecord{}
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
		records = append(records, livebox6DNSRecord{Hostname: host, IP: ip})
	}
	return records
}

// livebox6StaticLease represents a static DHCP lease from lan_dhcp_static.js.
type livebox6StaticLease struct {
	Name   string
	MAC    string
	IP     string
	Active bool
}

func livebox6ParseStaticLeases(data cgiData) []livebox6StaticLease {
	// Keys are static_<field>_<pool>_<idx>; pool 0 is the main LAN.
	byIdx := make(map[int]map[string]string)
	maxIdx := -1
	for k, v := range data.entries {
		m := livebox6StaticIndexRe.FindStringSubmatch(k)
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

	leases := []livebox6StaticLease{}
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
		leases = append(leases, livebox6StaticLease{
			Name:   name,
			MAC:    mac,
			IP:     ip,
			Active: g["active"] == "1",
		})
	}
	return leases
}

// livebox6WLAN holds a snapshot of the Wi-Fi configuration from wlan_combine.js.
type livebox6WLAN struct {
	Band24Enabled bool
	Band5Enabled  bool
	Band6Enabled  bool
	SSIDs         []livebox6SSID
}

// livebox6SSID represents the primary BSS of one band from wlan_combine.js.
// Guest BSSes (wl_ssid24G1, wl_ssid24G3, ...) are not parsed.
type livebox6SSID struct {
	Band     string
	SSID     string
	Enabled  bool
	Hidden   bool
	Security string
	Key      string
}

func livebox6ParseWLAN(data cgiData) livebox6WLAN {
	wlan := livebox6WLAN{
		Band24Enabled: data.get("wl_enable24G") == "1",
		Band5Enabled:  data.get("wl_enable5G") == "1",
		Band6Enabled:  data.get("wl_enable6G") == "1",
	}

	for _, band := range []string{"24G", "5G", "6G"} {
		ssid := data.get(fmt.Sprintf("wl_ssid%s", band))
		enabled := data.get(fmt.Sprintf("wl_enable%s", band)) == "1"
		if ssid == "" && !enabled {
			// 6 GHz may not be present on all models.
			continue
		}
		wlan.SSIDs = append(wlan.SSIDs, livebox6SSID{
			Band:     band,
			SSID:     ssid,
			Enabled:  enabled,
			Hidden:   data.get(fmt.Sprintf("wl_ssid_hide%s", band)) == "1",
			Security: data.get(fmt.Sprintf("security_type%s", band)),
			Key:      data.get(fmt.Sprintf("sharedkey%s", band)),
		})
	}
	return wlan
}

// livebox6Speed holds the WAN sync rates from infoInternet.js.
type livebox6Speed struct {
	DownstreamKbps int
	UpstreamKbps   int
}

func livebox6ParseSpeed(data cgiData) (livebox6Speed, error) {
	if !data.has("DownstreamCurrRate") || !data.has("UpstreamCurrRate") {
		return livebox6Speed{}, fmt.Errorf("WAN sync rates not available; the router may be connected through fiber (GPON)")
	}
	down, err := strconv.Atoi(data.get("DownstreamCurrRate"))
	if err != nil {
		return livebox6Speed{}, fmt.Errorf("parsing DownstreamCurrRate: %w", err)
	}
	up, err := strconv.Atoi(data.get("UpstreamCurrRate"))
	if err != nil {
		return livebox6Speed{}, fmt.Errorf("parsing UpstreamCurrRate: %w", err)
	}
	return livebox6Speed{DownstreamKbps: down, UpstreamKbps: up}, nil
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

// livebox6ProtocolName maps the router protocol number to a readable name.
func livebox6ProtocolName(p string) string {
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
