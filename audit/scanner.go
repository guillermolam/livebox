package audit

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Target identifies a single host that may be scanned.
type Target struct {
	ID       string
	Hostname string
	IP       string
	MAC      string
}

// ServiceBanner captures a short, non-destructive banner or fingerprint from a
// listening service. Type is one of ssh, http, https, rtsp, smb, telnet, or raw.
type ServiceBanner struct {
	Type string `json:"type"`
	Info string `json:"info"`
}

// PortResult is the outcome of probing one TCP port.
type PortResult struct {
	Port     int           `json:"port"`
	Protocol string        `json:"protocol"`
	Open     bool          `json:"open"`
	Banner   ServiceBanner `json:"banner,omitempty"`
}

// HostResult aggregates all port findings for one host.
type HostResult struct {
	Target
	Ports  []PortResult `json:"ports"`
	Errors []string     `json:"errors,omitempty"`
}

// Scanner performs bounded, manifest-gated TCP connect scans against approved
// LAN devices. It never sends exploit payloads; banner grabs are limited to
// handshake/headers only.
type Scanner struct {
	Ports       []int
	Timeout     time.Duration
	Concurrency int
	Manifest    *Manifest
}

// CommonPorts returns a sensible default port list for home-network audits.
// It covers administration, IoT/camera, and common services without scanning
// the entire 65k range.
func CommonPorts() []int {
	ports := []int{
		21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 143, 443, 445,
		515, 554, 631, 993, 995, 1723, 1883, 1900, 3000, 3128,
		3268, 3306, 3389, 5000, 5060, 5353, 5432, 5900, 5985,
		6379, 8000, 8008, 8080, 8081, 8443, 8883, 9100,
	}
	// Add 8200-8205 (common camera/NVR ranges).
	for p := 8200; p <= 8205; p++ {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	return ports
}

// NewScanner builds a scanner with defaults and validates the manifest.
func NewScanner(manifest *Manifest, ports []int) (*Scanner, error) {
	if manifest == nil {
		return nil, errors.New("a scope manifest is required for active scanning")
	}
	if len(ports) == 0 {
		ports = CommonPorts()
	}
	return &Scanner{
		Ports:       ports,
		Timeout:     400 * time.Millisecond,
		Concurrency: 64,
		Manifest:    manifest,
	}, nil
}

// ScanHost scans a single host after checking the scope manifest.
func (s *Scanner) ScanHost(ctx context.Context, t Target) (HostResult, error) {
	if _, err := s.Manifest.Check(t.IP, t.MAC); err != nil {
		return HostResult{Target: t}, err
	}

	result := HostResult{Target: t}
	sem := make(chan struct{}, s.Concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, port := range s.Ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			pr := s.probePort(ctx, t.IP, port)
			mu.Lock()
			result.Ports = append(result.Ports, pr)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(result.Ports, func(i, j int) bool {
		return result.Ports[i].Port < result.Ports[j].Port
	})
	return result, nil
}

// ScanHosts scans multiple approved hosts concurrently.
func (s *Scanner) ScanHosts(ctx context.Context, targets []Target) ([]HostResult, error) {
	var mu sync.Mutex
	var out []HostResult
	var scanErrs []error
	var wg sync.WaitGroup

	for _, t := range targets {
		t := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			hr, err := s.ScanHost(ctx, t)
			mu.Lock()
			defer mu.Unlock()
			out = append(out, hr)
			if err != nil {
				scanErrs = append(scanErrs, fmt.Errorf("%s (%s): %w", t.IP, t.ID, err))
			}
		}()
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool {
		return out[i].IP < out[j].IP
	})
	return out, errors.Join(scanErrs...)
}

func (s *Scanner) probePort(ctx context.Context, ip string, port int) PortResult {
	proto := inferProtocol(port)
	pr := PortResult{Port: port, Protocol: proto, Open: false}

	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return pr
	}
	defer conn.Close()
	pr.Open = true

	// Set a short deadline for the banner exchange so one slow service cannot
	// stall the whole scan.
	_ = conn.SetDeadline(time.Now().Add(s.Timeout))

	switch proto {
	case "http":
		pr.Banner = grabHTTPBanner(ctx, conn)
	case "https":
		pr.Banner = ServiceBanner{Type: "https", Info: "TLS service (no cert details requested)"}
	case "ssh":
		pr.Banner = readLineBanner(conn, "ssh")
	case "rtsp":
		pr.Banner = grabRTSPBanner(conn)
	case "smb":
		pr.Banner = readBytesBanner(conn, "smb", 32)
	case "telnet":
		pr.Banner = readBytesBanner(conn, "telnet", 64)
	default:
		pr.Banner = readBytesBanner(conn, "raw", 128)
	}
	return pr
}

func inferProtocol(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25, 465, 587:
		return "smtp"
	case 53:
		return "dns"
	case 80:
		return "http"
	case 110:
		return "pop3"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 554:
		return "rtsp"
	case 631:
		return "ipp"
	case 1723:
		return "pptp"
	case 1883, 8883:
		return "mqtt"
	case 1900:
		return "ssdp"
	case 5353:
		return "mdns"
	case 3389:
		return "rdp"
	case 5060:
		return "sip"
	case 5900:
		return "vnc"
	case 5985:
		return "winrm"
	case 6379:
		return "redis"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 9100:
		return "printer"
	default:
		if port >= 8000 && port <= 9000 {
			return "http-alt"
		}
		return "unknown"
	}
}

var (
	serverHeaderRe = regexp.MustCompile(`(?i)\r\nServer:\s*([^\r\n]+)`)
	titleRe        = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
)

func grabHTTPBanner(ctx context.Context, conn net.Conn) ServiceBanner {
	req, err := http.NewRequestWithContext(ctx, "GET", "/", nil)
	if err != nil {
		return ServiceBanner{Type: "http", Info: "error building request"}
	}
	req.Header.Set("Host", "livebox-audit")
	req.Header.Set("User-Agent", "livebox-audit/1.0 (local scan)")
	req.Header.Set("Accept", "*/*")
	if err := req.Write(conn); err != nil {
		return ServiceBanner{Type: "http", Info: "error sending request"}
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, req)
	if err != nil {
		// A raw HTTP-like service may still return headers; fall back to line reading.
		return readLineBanner(conn, "http")
	}
	defer resp.Body.Close()

	parts := []string{fmt.Sprintf("status=%d", resp.StatusCode)}
	if s := resp.Header.Get("Server"); s != "" {
		parts = append(parts, "server="+strings.TrimSpace(s))
	}
	// Read up to 4 KiB of body looking for a title.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if m := titleRe.FindSubmatch(body); m != nil {
		parts = append(parts, "title="+strings.TrimSpace(string(m[1])))
	}
	return ServiceBanner{Type: "http", Info: strings.Join(parts, " ")}
}

func grabRTSPBanner(conn net.Conn) ServiceBanner {
	fmt.Fprintf(conn, "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: livebox-audit/1.0\r\n\r\n", conn.RemoteAddr().String())
	return readLineBanner(conn, "rtsp")
}

func readLineBanner(conn net.Conn, typ string) ServiceBanner {
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || line == "" {
		return ServiceBanner{Type: typ}
	}
	return ServiceBanner{Type: typ, Info: strings.TrimSpace(line)}
}

func readBytesBanner(conn net.Conn, typ string, n int) ServiceBanner {
	b := make([]byte, n)
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	nr, err := conn.Read(b)
	if err != nil && nr == 0 {
		return ServiceBanner{Type: typ}
	}
	return ServiceBanner{Type: typ, Info: strconv.Quote(strings.TrimSpace(string(b[:nr])))}
}

// ARPEntry is one row from the OS ARP table.
type ARPEntry struct {
	IP  string `json:"ip"`
	MAC string `json:"mac"`
}

// LocalARPTable returns the OS ARP/neighbor table as best-effort enrichment
// data. It uses OS-native commands because Go does not expose the ARP cache.
func LocalARPTable() ([]ARPEntry, error) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "arp", "-a"}
	case "darwin":
		cmd = "arp"
		args = []string{"-an"}
	default: // linux and other unixes
		cmd = "ip"
		args = []string{"neigh", "show"}
	}

	out, err := execCommand(cmd, args...)
	if err != nil {
		return nil, fmt.Errorf("running arp command: %w", err)
	}
	return parseARPTable(string(out)), nil
}

func parseARPTable(s string) []ARPEntry {
	var entries []ARPEntry
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Windows: "  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic"
		// Linux ip neigh: "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
		// macOS: "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0"
		f := strings.Fields(line)
		for i, tok := range f {
			tok = strings.Trim(tok, "()")
			if net.ParseIP(tok) == nil {
				continue
			}
			ip := tok
			mac := ""
			// Look ahead for a MAC or the "at"/"lladdr" keyword.
			for j := i + 1; j < len(f); j++ {
				w := f[j]
				if strings.EqualFold(w, "at") || strings.EqualFold(w, "lladdr") {
					if j+1 < len(f) {
						mac = NormalizeMAC(f[j+1])
					}
					break
				}
				if IsValidMAC(w) {
					mac = NormalizeMAC(w)
					break
				}
			}
			if mac != "" {
				entries = append(entries, ARPEntry{IP: ip, MAC: mac})
			}
			break
		}
	}
	return entries
}

// execCommand is a test seam for OS command execution.
var execCommand = func(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}
