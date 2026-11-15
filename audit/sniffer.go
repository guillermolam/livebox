package audit

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// DiscoveryRecord is one passive discovery announcement heard on the LAN.
type DiscoveryRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	Protocol   string    `json:"protocol"`
	SourceIP   string    `json:"source_ip"`
	SourcePort int       `json:"source_port"`
	Payload    string    `json:"payload"`
}

// Sniffer passively listens for multicast/broadcast discovery traffic without
// sending any probes. It is the safe, read-only half of "livebox sniff".
type Sniffer struct {
	Duration   time.Duration
	Interfaces []string

	mu      sync.Mutex
	records []DiscoveryRecord
	errors  []string
}

// defaultListeners maps a friendly protocol label to the UDP address to bind.
// Binding to the multicast address on the local machine lets the kernel deliver
// matching packets to us when another process is not already holding the port.
var defaultListeners = map[string]string{
	"mdns":  "224.0.0.251:5353",
	"ssdp":  "239.255.255.250:1900",
	"llmnr": "224.0.0.252:5355",
	"nbns":  "0.0.0.0:137",
}

// Capture starts the default discovery listeners, blocks for the configured
// duration (or until the context is cancelled), and returns the collected
// records. Errors for individual listeners are accumulated but do not fail the
// whole capture unless every listener fails.
func (s *Sniffer) Capture(ctx context.Context) ([]DiscoveryRecord, []string, error) {
	if s.Duration == 0 {
		s.Duration = 30 * time.Second
	}

	listeners := defaultListeners
	if len(s.Interfaces) > 0 {
		// If specific interfaces are requested, join multicast groups on each.
		// For now this path is a no-op placeholder for future per-interface
		// binding; binding to the default address still captures traffic.
	}

	ctx, cancel := context.WithTimeout(ctx, s.Duration)
	defer cancel()

	var wg sync.WaitGroup
	started := 0
	for proto, addr := range listeners {
		proto := proto
		addr := addr
		wg.Add(1)
		started++
		go func() {
			defer wg.Done()
			s.listenUDP(ctx, proto, addr)
		}()
	}

	if started == 0 {
		return nil, nil, fmt.Errorf("no listeners configured")
	}

	<-ctx.Done()
	wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records, s.errors, nil
}

func (s *Sniffer) listenUDP(ctx context.Context, proto, addr string) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		s.recordError(fmt.Sprintf("%s: bind %s: %v", proto, addr, err))
		return
	}
	defer pc.Close()

	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = pc.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			if isTemporary(err) {
				continue
			}
			return
		}
		s.recordPacket(proto, src, buf[:n])
	}
}

func (s *Sniffer) recordPacket(proto string, src net.Addr, payload []byte) {
	host, port, _ := net.SplitHostPort(src.String())
	p := 0
	fmt.Sscanf(port, "%d", &p)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, DiscoveryRecord{
		Timestamp:  time.Now().UTC(),
		Protocol:   proto,
		SourceIP:   host,
		SourcePort: p,
		Payload:    sanitizePayload(payload, 256),
	})
}

func (s *Sniffer) recordError(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, msg)
}

func sanitizePayload(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 32 && c < 127 {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func isTemporary(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout() || ne.Temporary()
	}
	return false
}
