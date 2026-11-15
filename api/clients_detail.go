package api

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ClientDetail is the richer 19-field client record from cgi_clients.js
// (var online_client), enriched with related router telemetry.
type ClientDetail struct {
	Name             string    `json:"name"`
	IP               string    `json:"ip"`
	MAC              string    `json:"mac"`
	Band             string    `json:"band"`
	Status           string    `json:"status"`
	SSID             string    `json:"ssid"`
	VendorClass      string    `json:"vendor_class"`
	LastSeen         time.Time `json:"last_seen"`
	Assignment       string    `json:"assignment"`
	Interface        string    `json:"interface"`
	LeaseDurationSec int       `json:"lease_duration_sec"`
	DeviceType       string    `json:"device_type,omitempty"`
	RawFields        []string  `json:"raw_fields,omitempty"`
}

// ClientDetailsExtras holds router-level exposure data that applies to the
// whole LAN rather than to a single device.
type ClientDetailsExtras struct {
	UPnPEnabled      bool
	MACFilterEnabled bool
}

// ParseOnlineClients parses the 19-field `var online_client=[...]` array from
// cgi_clients.js. The firmware layout observed on Livebox 6 is:
//
//	[0]  name/hostname
//	[1]  IPv4
//	[2]  MAC
//	[3]  ?
//	[4]  band (24G/5G/LAN)
//	[5]  ?
//	[6]  ?
//	[7]  ?
//	[8]  assignment (DHCP/Static)
//	[9]  status (Online/Offline)
//	[10] SSID (empty for wired)
//	[11] DHCP vendor class, e.g. "udhcp 1.27.2", "android-dhcp-14", "MSFT 5.0"
//	[12] last seen timestamp "YYYY/MM/DD HH:MM:SS"
//	[13] lease duration in seconds
//	[14] interface (wl0.1, wl1.1, eth1.0, ...)
//	[15] BSSID / physical address
//	[16] repeated or physical MAC
//	[17] alternate name (sometimes empty)
//	[18] ?
//
// Records with fewer than the expected number of fields are still returned,
// with missing fields left empty.
func ParseOnlineClients(raw string) ([]ClientDetail, error) {
	records, err := parseNestedJSStringArray(raw, "online_client")
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("online_client array is empty")
	}

	var clients []ClientDetail
	for _, rec := range records {
		c := ClientDetail{
			Name:      strings.TrimSpace(rec[0]),
			IP:        safe(rec, 1),
			MAC:       normalizeMAC(safe(rec, 2)),
			Band:      safe(rec, 4),
			Status:    safe(rec, 9),
			SSID:      safe(rec, 10),
			VendorClass: safe(rec, 11),
			Assignment:  safe(rec, 8),
			Interface:   safe(rec, 14),
			RawFields:   append([]string(nil), rec...),
		}
		if ts := safe(rec, 12); ts != "" {
			if t, err := time.ParseInLocation("2006/01/02 15:04:05", ts, time.Local); err == nil {
				c.LastSeen = t
			}
		}
		if dur := safe(rec, 13); dur != "" {
			if n, err := strconv.Atoi(dur); err == nil {
				c.LeaseDurationSec = n
			}
		}
		// Prefer the alternate name only when the primary name is empty.
		if c.Name == "" {
			c.Name = strings.TrimSpace(safe(rec, 17))
		}
		// If still unnamed, use the device type as a fallback display label
		// (e.g. "smartphone") rather than leaving it blank.
		if c.Name == "" && c.DeviceType != "" {
			c.Name = c.DeviceType
		}
		clients = append(clients, c)
	}
	return clients, nil
}

// safe returns the i-th element of s, or the empty string if out of range.
func safe(s []string, i int) string {
	if i < 0 || i >= len(s) {
		return ""
	}
	return s[i]
}

// parseJSStringArray parses a flat `var name=[...]` JavaScript array of single-
// quoted strings and null entries. It reuses the same tokenization rules as
// parseJSStringList.
func parseJSStringArray(raw, varName string) ([]string, error) {
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
	return parseJSStringList(raw[start : start+end])
}

// parseNestedJSStringArray parses a `var name=[[...],[...]]` JavaScript array
// of arrays. It returns one slice per outer record; each record is a flat list
// of string tokens.
func parseNestedJSStringArray(raw, varName string) ([][]string, error) {
	marker := "var " + varName + "=["
	start := strings.Index(raw, marker)
	if start == -1 {
		return nil, fmt.Errorf("%s array not found", varName)
	}
	start += len(marker)
	// Walk to the matching ']' that closes the outer array, accounting for
	// nested arrays inside each record.
	depth := 1
	end := start
	for end < len(raw) && depth > 0 {
		switch raw[end] {
		case '[':
			depth++
		case ']':
			depth--
		}
		end++
	}
	if depth != 0 {
		return nil, fmt.Errorf("%s array not terminated", varName)
	}
	// end now points just past the matching ']'.
	body := raw[start : end-1]
	if len(strings.TrimSpace(body)) == 0 {
		return nil, nil
	}

	records := strings.Split(body, "],[")
	out := make([][]string, 0, len(records))
	for _, rec := range records {
		rec = strings.TrimSpace(rec)
		rec = strings.Trim(rec, "[]")
		if rec == "" {
			continue
		}
		tokens, err := parseJSStringList(rec)
		if err != nil {
			return nil, fmt.Errorf("%s record: %w", varName, err)
		}
		out = append(out, tokens)
	}
	return out, nil
}

// ParseClientDeviceTypes returns a map from normalized MAC to device type by
// correlating the `client_mac` and `client_deviceType` arrays in cgi_clients.js.
func ParseClientDeviceTypes(raw string) map[string]string {
	macs, _ := parseJSStringArray(raw, "client_mac")
	types, _ := parseJSStringArray(raw, "client_deviceType")
	out := make(map[string]string)
	for i := 0; i < len(macs) && i < len(types); i++ {
		mac := normalizeMAC(macs[i])
		typ := strings.TrimSpace(types[i])
		if mac != "" && typ != "" {
			out[mac] = typ
		}
	}
	return out
}

// ParseUPnPStatus reports whether global UPnP is enabled from upnp_osp.js.
func ParseUPnPStatus(data Data) bool {
	return data.Get("upnp_enable") == "1"
}

// ParseMACFilterStatus reports whether the Wi-Fi MAC filter is enabled from
// firewall_mac_filter.js.
func ParseMACFilterStatus(data Data) bool {
	// The exact key varies by firmware; accept either spelling.
	return data.Get("mac_filter_enable") == "1" || data.Get("macfilter_enable") == "1"
}

// ClientDetails fetches cgi_clients.js and the related exposure CGIs and
// returns the full client list plus router-level exposure flags.
func (c *Client) ClientDetails(ctx context.Context) ([]ClientDetail, ClientDetailsExtras, error) {
	var extras ClientDetailsExtras
	clientsRaw, err := c.Get(ctx, "/cgi/cgi_clients.js")
	if err != nil {
		return nil, extras, fmt.Errorf("fetching clients.js: %w", err)
	}
	clients, err := ParseOnlineClients(clientsRaw)
	if err != nil {
		return nil, extras, fmt.Errorf("parsing online_client: %w", err)
	}

	deviceTypes := ParseClientDeviceTypes(clientsRaw)
	for i := range clients {
		if t, ok := deviceTypes[clients[i].MAC]; ok && clients[i].DeviceType == "" {
			clients[i].DeviceType = t
		}
	}

	if upnp, err := c.CGI(ctx, "upnp_osp"); err == nil {
		extras.UPnPEnabled = ParseUPnPStatus(upnp)
	}
	if mf, err := c.CGI(ctx, "firewall_mac_filter"); err == nil {
		extras.MACFilterEnabled = ParseMACFilterStatus(mf)
	}

	return clients, extras, nil
}
