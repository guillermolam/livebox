package audit

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestCommonPortsSortedAndUnique(t *testing.T) {
	ports := CommonPorts()
	seen := make(map[int]bool)
	for i, p := range ports {
		if seen[p] {
			t.Fatalf("port %d appears more than once", p)
		}
		seen[p] = true
		if i > 0 && ports[i-1] >= p {
			t.Fatalf("ports are not sorted: %d before %d", ports[i-1], p)
		}
	}
	if len(ports) < 40 {
		t.Fatalf("expected at least 40 common ports, got %d", len(ports))
	}
}

func TestNewScannerRequiresManifest(t *testing.T) {
	_, err := NewScanner(nil, []int{80})
	if err == nil {
		t.Fatal("expected error when manifest is nil")
	}
}

func TestScanHostRequiresApproval(t *testing.T) {
	m, err := NewManifest("test-approval", []Device{
		{MAC: "aa:bb:cc:dd:ee:ff", IPv4: "192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewScanner(m, []int{80})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ScanHost(context.Background(), Target{IP: "192.0.2.99", MAC: "00:11:22:33:44:55"})
	if err == nil {
		t.Fatal("expected rejection for unapproved target")
	}
}

func TestScanHostFindsOpenPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Accept one connection so the port is "open".
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		fmt.Fprintf(conn, "SSH-2.0-test\r\n")
		conn.Close()
	}()

	ip, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		port = 0
	}
	// net.SplitHostPort returns numeric port string; parse it manually.
	fmt.Sscanf(portStr, "%d", &port)

	m, _ := NewManifest("test-approval", []Device{{MAC: "aa:bb:cc:dd:ee:ff", IPv4: ip}})
	s, _ := NewScanner(m, []int{port})
	s.Timeout = 2 * time.Second

	hr, err := s.ScanHost(context.Background(), Target{IP: ip, MAC: "aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Ports) != 1 {
		t.Fatalf("expected 1 port result, got %d", len(hr.Ports))
	}
	pr := hr.Ports[0]
	if pr.Port != port {
		t.Fatalf("expected port %d, got %d", port, pr.Port)
	}
	if !pr.Open {
		t.Fatalf("expected port %d to be open", port)
	}
	if pr.Protocol != inferProtocol(port) {
		t.Fatalf("unexpected protocol %q", pr.Protocol)
	}
}

func TestScanHostSkipsClosedPort(t *testing.T) {
	m, _ := NewManifest("test-approval", []Device{{MAC: "aa:bb:cc:dd:ee:ff", IPv4: "127.0.0.1"}})
	s, _ := NewScanner(m, []int{54321})
	s.Timeout = 100 * time.Millisecond

	hr, err := s.ScanHost(context.Background(), Target{IP: "127.0.0.1", MAC: "aa:bb:cc:dd:ee:ff"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Ports) != 1 || hr.Ports[0].Open {
		t.Fatal("expected closed port to be reported as closed")
	}
}

func TestParseARPTableWindows(t *testing.T) {
	input := "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic\n" +
		"  192.168.1.20          11-22-33-44-55-66     static"
	entries := parseARPTable(input)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].IP != "192.168.1.1" || entries[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("unexpected first entry: %+v", entries[0])
	}
}

func TestParseARPTableLinux(t *testing.T) {
	input := "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n" +
		"192.168.1.20 dev eth0 lladdr 11:22:33:44:55:66 STALE"
	entries := parseARPTable(input)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[1].MAC != "11:22:33:44:55:66" {
		t.Fatalf("unexpected second entry: %+v", entries[1])
	}
}

func TestParseARPTableMacOS(t *testing.T) {
	input := "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0\n" +
		"? (192.168.1.20) at 11:22:33:44:55:66 on en0"
	entries := parseARPTable(input)
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
}
