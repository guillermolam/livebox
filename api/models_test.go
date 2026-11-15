package api

import (
	"testing"
)

func TestParseDevices(t *testing.T) {
	// The lease table lives in clients.js as var dhcp_client=[...] (and in
	// infoLan.js as var dhcp_leaseTime=[...]).
	raw := loadTestData(t, "js_clients.js")
	devices, err := parseDevices(raw)
	if err != nil {
		t.Fatalf("parseDevices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}

	// Spot-check the first lease from the captured data.
	found := false
	for _, d := range devices {
		if d.IP == "192.168.1.76" && d.MAC == "74:04:f1:87:46:00" && d.Name == "Junior" {
			found = true
			if d.Interface != "LAN" {
				t.Errorf("interface = %q, want LAN", d.Interface)
			}
		}
	}
	if !found {
		t.Errorf("expected lease for Junior (192.168.1.76) not found: %+v", devices)
	}

	// Every device must have a MAC and an IP.
	for _, d := range devices {
		if d.IP == "" {
			t.Errorf("device %+v has no IP", d)
		}
		if d.MAC == "" {
			t.Errorf("device %+v has no MAC", d)
		}
	}
}

func TestParseDevicesInfoLan(t *testing.T) {
	raw := loadTestData(t, "js_infoLan.js")
	devices, err := parseDevices(raw)
	if err != nil {
		t.Fatalf("parseDevices: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}
	for _, d := range devices {
		if d.IP == "" {
			t.Errorf("device %+v has no IP", d)
		}
	}
}

func TestParsePortForwards(t *testing.T) {
	data := parseCGIBody(loadTestData(t, "js_nat_osp.js"))
	rules := parsePortForwards(data)

	// The captured file has a large table; we only assert structural sanity.
	for _, r := range rules {
		if r.Enabled && r.PublicPort == "" {
			t.Errorf("enabled rule %+v has no public port", r)
		}
		if r.Protocol == "" {
			t.Errorf("rule %+v has no protocol", r)
		}
	}
}

func TestParseDMZ(t *testing.T) {
	data := parseCGIBody(loadTestData(t, "js_fw_dmz_osp.js"))
	dmz := parseDMZ(data)

	// The capture shows DMZ disabled with host_ip 0.0.0.0.
	if dmz.HostIP == "" {
		t.Error("dmz host_ip is empty")
	}
}

func TestParseDNS(t *testing.T) {
	data := parseCGIBody(loadTestData(t, "js_dns.js"))
	records := parseDNS(data)

	// All captured dns_hostname/dns_ip pairs are empty in this file.
	// The parser must still return without panic.
	if records == nil {
		t.Error("expected non-nil records slice")
	}
}

func TestParseStaticLeases(t *testing.T) {
	data := parseCGIBody(loadTestData(t, "js_lan_dhcp_static.js"))
	leases := parseStaticLeases(data)

	// The captured static lease table is empty, but parsing must succeed.
	if leases == nil {
		t.Error("expected non-nil leases slice")
	}
}

func TestParseWLAN(t *testing.T) {
	data := parseCGIBody(loadTestData(t, "js_wlan_combine.js"))
	wlan := parseWLAN(data)

	if !wlan.Band24Enabled && !wlan.Band5Enabled {
		t.Error("expected at least one Wi-Fi band to be enabled")
	}

	for _, ssid := range wlan.SSIDs {
		if ssid.Band == "" {
			t.Errorf("SSID %+v has no band", ssid)
		}
	}
}

func TestParseSpeed(t *testing.T) {
	t.Run("fiber capture has no sync rates", func(t *testing.T) {
		// This capture is from a fiber (GPON) connection: infoInternet.js has
		// no sync rates, and the parser must fail loudly instead of returning
		// 0/0.
		data := parseCGIBody(loadTestData(t, "js_infoInternet.js"))
		if _, err := parseSpeed(data); err == nil {
			t.Error("expected an error for missing sync rates, got none")
		}
	})

	t.Run("sync rates", func(t *testing.T) {
		data := parseCGIBody(`
addCfg("DownstreamCurrRate", "1", "1000000");
addCfg("UpstreamCurrRate", "1", "600000");
`)
		speed, err := parseSpeed(data)
		if err != nil {
			t.Fatalf("parseSpeed: %v", err)
		}
		if speed.DownstreamKbps != 1000000 || speed.UpstreamKbps != 600000 {
			t.Errorf("speed = %+v", speed)
		}
	})
}

func TestParseJSStringList(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "simple",
			input: "'a','b','c'",
			want:  []string{"a", "b", "c"},
		},
		{
			name:  "with null",
			input: "'a',null,'c'",
			want:  []string{"a", "", "c"},
		},
		{
			name:  "escaped quote",
			input: "'it\\'s','ok'",
			want:  []string{"it's", "ok"},
		},
		{
			name:    "unterminated",
			input:   "'a",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseJSStringList(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseJSStringList(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("parseJSStringList(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("token %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
