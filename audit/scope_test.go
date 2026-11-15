package audit

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
		{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"},
		{"  aa-bb-cc-dd-ee-ff  ", "aa:bb:cc:dd:ee:ff"},
		{"", ""},
		{"not-a-mac", "not-a-mac"},
		{"aa-bb-cc", "aa-bb-cc"},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			require.Equal(t, tc.want, NormalizeMAC(tc.in))
		})
	}
}

func TestDeviceIDFromMAC(t *testing.T) {
	id1 := DeviceIDFromMAC("AA:BB:CC:DD:EE:FF")
	id2 := DeviceIDFromMAC("aa:bb:cc:dd:ee:ff")
	require.Equal(t, id1, id2, "device id must be stable regardless of case or separator")
	require.Equal(t, 16, len(id1))
}

func TestNewManifest(t *testing.T) {
	devs := []Device{
		{
			Hostname:            "test-phone",
			MAC:                 "AA-BB-CC-DD-EE-01",
			IPv4:                "192.168.1.42",
			Interface:           "wl0.1",
			SSID:                "Home",
			Band:                "5G",
			Assignment:          "dhcp",
			LastSeenByRouterUTC: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		},
	}
	m, err := NewManifest("scope-2026-11-20-001", devs)
	require.NoError(t, err)
	require.Equal(t, "authenticated_router_admin", m.Actor)
	require.Equal(t, "router_admin_session", m.SourceOfAuthority)
	require.True(t, m.SecretsRedacted)
	require.Len(t, m.Devices, 1)
	require.Equal(t, "aa:bb:cc:dd:ee:01", m.Devices[0].MAC)
	require.Equal(t, "192.168.1.42", m.Devices[0].IPv4)
	require.Equal(t, Approved, m.Devices[0].ApprovalStatus)
	require.Equal(t, "192.168.1.42", m.Devices[0].ApprovedIPAtApproval)
	require.NotEmpty(t, m.Devices[0].ID)
}

func TestManifest_Check(t *testing.T) {
	m, err := NewManifest("scope-001", []Device{
		{Hostname: "phone", MAC: "aa:bb:cc:dd:ee:01", IPv4: "192.168.1.10"},
		{Hostname: "laptop", MAC: "aa:bb:cc:dd:ee:02", IPv4: "192.168.1.11", ApprovalStatus: Approved},
		{Hostname: "unclassified", MAC: "aa:bb:cc:dd:ee:03", IPv4: "192.168.1.12", ApprovalStatus: Unclassified},
	})
	require.NoError(t, err)

	t.Run("approved exact match", func(t *testing.T) {
		d, err := m.Check("192.168.1.10", "aa:bb:cc:dd:ee:01")
		require.NoError(t, err)
		require.Equal(t, "phone", d.Hostname)
	})

	t.Run("approved mac only lookup", func(t *testing.T) {
		d, err := m.Check("", "aa:bb:cc:dd:ee:01")
		require.NoError(t, err)
		require.Equal(t, "phone", d.Hostname)
	})

	t.Run("approved ip only lookup", func(t *testing.T) {
		d, err := m.Check("192.168.1.10", "")
		require.NoError(t, err)
		require.Equal(t, "phone", d.Hostname)
	})

	t.Run("unknown mac rejected", func(t *testing.T) {
		_, err := m.Check("192.168.1.99", "aa:bb:cc:dd:ee:99")
		require.Error(t, err)
	})

	t.Run("unknown ip rejected", func(t *testing.T) {
		_, err := m.Check("192.168.1.99", "")
		require.Error(t, err)
	})

	t.Run("stale lease rejected", func(t *testing.T) {
		_, err := m.Check("192.168.1.50", "aa:bb:cc:dd:ee:01")
		require.Error(t, err)
	})

	t.Run("unclassified device rejected", func(t *testing.T) {
		_, err := m.Check("192.168.1.12", "aa:bb:cc:dd:ee:03")
		require.Error(t, err)
	})

	t.Run("nil manifest errors", func(t *testing.T) {
		var nilM *Manifest
		_, err := nilM.Check("192.168.1.10", "")
		require.Error(t, err)
	})
}

func TestManifest_SaveLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.json")

	m, err := NewManifest("scope-002", []Device{
		{
			Hostname:            "iot",
			MAC:                 "aa:bb:cc:dd:ee:04",
			IPv4:                "192.168.1.13",
			Interface:           "wl1.1",
			SSID:                "IoT",
			Band:                "2.4G",
			Assignment:          "static-lease",
			LastSeenByRouterUTC: time.Date(2026, 11, 20, 11, 0, 0, 0, time.UTC),
			IPv6:                IPv6Addrs{LLA: []string{"fe80::1"}},
		},
	})
	require.NoError(t, err)
	m.SnapshotHash = "sha256:abc123"
	require.NoError(t, SaveManifest(path, m))

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(b), "scope-002")

	loaded, err := LoadManifest(path)
	require.NoError(t, err)
	require.Equal(t, m.ScopeApprovalID, loaded.ScopeApprovalID)
	require.Equal(t, m.SnapshotHash, loaded.SnapshotHash)
	require.Len(t, loaded.Devices, 1)
	require.Equal(t, "iot", loaded.Devices[0].Hostname)
	require.Equal(t, "fe80::1", loaded.Devices[0].IPv6.LLA[0])

	d, err := loaded.Check("192.168.1.13", "aa:bb:cc:dd:ee:04")
	require.NoError(t, err)
	require.Equal(t, "iot", d.Hostname)
}
