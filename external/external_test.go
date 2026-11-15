package external

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/guillermolam/livebox/audit"
)

func testManifest(t *testing.T) *audit.Manifest {
	t.Helper()
	m, err := audit.NewManifest("scope-test", []audit.Device{
		{MAC: "aa:bb:cc:dd:ee:ff", IPv4: "192.168.1.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRunnerRejectsUnapprovedIP(t *testing.T) {
	r, err := NewRunner(testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateIP("192.168.1.99"); err == nil {
		t.Fatal("expected unapproved IP to be rejected")
	}
}

func TestRunnerAcceptsApprovedIP(t *testing.T) {
	r, err := NewRunner(testManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateIP("192.168.1.10"); err != nil {
		t.Fatalf("expected approved IP to pass: %v", err)
	}
}

func TestNaabuParse(t *testing.T) {
	out := `{"host":"router","ip":"192.168.1.1","port":80,"url":"http://192.168.1.1:80"}
{"host":"router","ip":"192.168.1.1","port":443}
`
	records := parseNaabuOutput("192.168.1.1", "scope-test", []byte(out))
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].Stage != StageNaabu {
		t.Fatalf("expected stage naabu, got %s", records[0].Stage)
	}
}

func TestHttpxParse(t *testing.T) {
	out := `{"url":"http://192.168.1.1:80","status_code":200,"title":"Login","webserver":"lighttpd"}`
	rec, err := parseHttpxOutput("192.168.1.1:80", "scope-test", []byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if rec.Stage != StageHttpx {
		t.Fatalf("expected stage httpx, got %s", rec.Stage)
	}
	if rec.Observation["status_code"].(float64) != 200 {
		t.Fatalf("unexpected status code: %v", rec.Observation["status_code"])
	}
}

func TestNmapParse(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="lighttpd" version="1.4.59"/></port>
      <port protocol="tcp" portid="443"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>`
	records, err := parseNmapXML("192.168.1.1", "scope-test", []byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 open port record, got %d", len(records))
	}
	if records[0].Observation["port"] != 80 {
		t.Fatalf("unexpected port: %v", records[0].Observation["port"])
	}
}

func TestNaabuFakeBinary(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "naabu")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho '{\"host\":\"router\",\"ip\":\"192.168.1.10\",\"port\":80}'\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	r, _ := NewRunner(testManifest(t))
	records, err := NaabuScan(context.Background(), r, "192.168.1.10", []int{80})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

func TestKatanaParse(t *testing.T) {
	out := `{"url":"http://192.168.1.10/login","method":"GET"}` + "\n"
	records := parseKatanaOutput("http://192.168.1.10", "scope-test", []byte(out))
	if len(records) != 1 || records[0].Stage != StageKatana {
		t.Fatalf("unexpected katana records: %+v", records)
	}
}

func TestNucleiParse(t *testing.T) {
	out := `{"host":"192.168.1.10","template-id":"test-template","info":{"severity":"high"}}` + "\n"
	records := parseNucleiOutput([]string{"192.168.1.10"}, "scope-test", []string{"test-template"}, []byte(out))
	if len(records) != 1 || records[0].Stage != StageNuclei {
		t.Fatalf("unexpected nuclei records: %+v", records)
	}
	if records[0].FindingID == "" {
		t.Fatal("expected finding ID")
	}
}

func TestSubfinderParse(t *testing.T) {
	out := `{"host":"www.example.com","source":"crtsh","input":"example.com"}` + "\n"
	records := parseSubfinderOutput("example.com", "scope-test", []byte(out))
	if len(records) != 1 || records[0].Stage != StageSubfinder {
		t.Fatalf("unexpected subfinder records: %+v", records)
	}
}

func TestUncoverParse(t *testing.T) {
	out := `{"ip":"192.168.1.1","port":"80"}` + "\n"
	records := parseUncoverOutput("example.com", "scope-test", []byte(out))
	if len(records) != 1 || records[0].Confidence != Inconclusive {
		t.Fatalf("unexpected uncover records: %+v", records)
	}
}

func TestInteractshParse(t *testing.T) {
	out := `{"protocol":"http","unique-id":"abc","full-id":"abc.example","remote-address":"192.168.1.1","timestamp":"2026-01-01T00:00:00Z"}` + "\n"
	records := parseInteractshOutput("scope-test", []byte(out))
	if len(records) != 1 || records[0].Stage != StageInteract {
		t.Fatalf("unexpected interactsh records: %+v", records)
	}
}
