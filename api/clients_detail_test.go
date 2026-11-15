package api

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseOnlineClients(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "livebox6", "js_clients.js"))
	require.NoError(t, err)

	clients, err := ParseOnlineClients(string(raw))
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(clients), 150, "fixture should contain many client records")

	// Spot-check the first record from the fixture.
	first := clients[0]
	require.Equal(t, "Redmi-Note-12-Pro-5G", first.Name)
	require.Equal(t, "192.168.1.89", first.IP)
	require.Equal(t, "3a:7c:67:9f:f6:49", first.MAC)
	require.Equal(t, "24G", first.Band)
	require.Equal(t, "Offline", first.Status)
	require.Equal(t, "Livebox6-729B-24G", first.SSID)
	require.Equal(t, "android-dhcp-14", first.VendorClass)
	require.Equal(t, "DHCP", first.Assignment)
	require.Equal(t, "wl1.1", first.Interface)
	require.Equal(t, 283253, first.LeaseDurationSec)
	require.False(t, first.LastSeen.IsZero())
	require.Equal(t, "2026/11/15 11:22:35", first.LastSeen.Format("2006/01/02 15:04:05"))

	// Find a wired/LAN record.
	var wired *ClientDetail
	for i := range clients {
		if clients[i].Interface == "eth1.0" {
			wired = &clients[i]
			break
		}
	}
	require.NotNil(t, wired, "expected at least one eth1.0 wired record")
	require.Equal(t, "LAN", wired.Band)
}

func TestParseOnlineClients_Synthetic(t *testing.T) {
	raw := `var online_client=[['Phone','192.168.1.10','aa:bb:cc:dd:ee:01','0','5G','0','0','0','DHCP','Online','Home-5G','android-dhcp-14','2026/11/20 10:00:00','12345','wl0.1','00:00:00:00:00:00','aa:bb:cc:dd:ee:01','','0']];`
	clients, err := ParseOnlineClients(raw)
	require.NoError(t, err)
	require.Len(t, clients, 1)
	c := clients[0]
	require.Equal(t, "Phone", c.Name)
	require.Equal(t, "192.168.1.10", c.IP)
	require.Equal(t, "aa:bb:cc:dd:ee:01", c.MAC)
	require.Equal(t, "5G", c.Band)
	require.Equal(t, "Online", c.Status)
	require.Equal(t, "Home-5G", c.SSID)
	require.Equal(t, "android-dhcp-14", c.VendorClass)
	require.Equal(t, "DHCP", c.Assignment)
	require.Equal(t, "wl0.1", c.Interface)
	require.Equal(t, 12345, c.LeaseDurationSec)
	require.Equal(t, time.Date(2026, 11, 20, 10, 0, 0, 0, time.Local), c.LastSeen)
}

func TestParseClientDeviceTypes(t *testing.T) {
	raw := `var client_mac=['aa:bb:cc:dd:ee:01','','AA:BB:CC:DD:EE:02'];
var client_deviceType=['smartphone','','tablet'];`
	types := ParseClientDeviceTypes(raw)
	require.Len(t, types, 2)
	require.Equal(t, "smartphone", types["aa:bb:cc:dd:ee:01"])
	require.Equal(t, "tablet", types["aa:bb:cc:dd:ee:02"])
}

func TestParseUPnPStatus(t *testing.T) {
	require.True(t, ParseUPnPStatus(Data{entries: map[string]string{"upnp_enable": "1"}}))
	require.False(t, ParseUPnPStatus(Data{entries: map[string]string{"upnp_enable": "0"}}))
	require.False(t, ParseUPnPStatus(Data{entries: map[string]string{}}))
}

func TestParseMACFilterStatus(t *testing.T) {
	require.True(t, ParseMACFilterStatus(Data{entries: map[string]string{"mac_filter_enable": "1"}}))
	require.True(t, ParseMACFilterStatus(Data{entries: map[string]string{"macfilter_enable": "1"}}))
	require.False(t, ParseMACFilterStatus(Data{entries: map[string]string{"mac_filter_enable": "0"}}))
}
