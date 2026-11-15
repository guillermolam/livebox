package audit

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

func TestSnifferCaptureLocalUDP(t *testing.T) {
	orig := defaultListeners
	defer func() { defaultListeners = orig }()

	addr := freeUDPAddr(t)
	defaultListeners = map[string]string{"test": addr}

	sniffer := &Sniffer{Duration: 500 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	done := make(chan struct{})
	var records []DiscoveryRecord
	var errs []string
	var capErr error
	go func() {
		records, errs, capErr = sniffer.Capture(ctx)
		close(done)
	}()

	// Wait for the listener to bind.
	time.Sleep(50 * time.Millisecond)

	sender, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Write([]byte("hello-livebox-audit")); err != nil {
		t.Fatal(err)
	}
	sender.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sniffer did not finish in time")
	}

	if capErr != nil {
		t.Fatalf("capture returned error: %v", capErr)
	}

	found := false
	for _, r := range records {
		if strings.Contains(r.Payload, "hello-livebox-audit") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to capture the test payload, got %d records and errors %v", len(records), errs)
	}
}

func TestSanitizePayload(t *testing.T) {
	in := []byte("abc\x00\x01def")
	got := sanitizePayload(in, 100)
	if got != "abc..def" {
		t.Fatalf("sanitizePayload = %q", got)
	}
}
