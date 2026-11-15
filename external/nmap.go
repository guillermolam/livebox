package external

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"
)

// nmapXML is the subset of nmap -oX output we need.
type nmapXML struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    nmapState `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

// NmapScan runs a bounded nmap scan against an approved host.
func NmapScan(ctx context.Context, r *Runner, host string, ports []int) ([]Record, error) {
	if err := r.ValidateIP(host); err != nil {
		return nil, fmt.Errorf("scope check failed for %s: %w", host, err)
	}

	args := []string{"-oX", "-", "-Pn"}
	if len(ports) > 0 {
		args = append(args, "-p", joinPorts(ports))
	}
	args = append(args, host)

	out, err := r.Run(ctx, "nmap", args...)
	if err != nil {
		return nil, fmt.Errorf("nmap failed: %w", err)
	}

	return parseNmapXML(host, r.ScopeApprovalID(), out)
}

func parseNmapXML(host, scopeID string, out []byte) ([]Record, error) {
	var run nmapXML
	if err := xml.Unmarshal(out, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap XML: %w", err)
	}

	var records []Record
	for _, h := range run.Hosts {
		ip := host
		for _, a := range h.Addresses {
			if a.Type == "ipv4" {
				ip = a.Addr
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			records = append(records, Record{
				Stage:           StageNmap,
				Tool:            "nmap",
				ScopeApprovalID: scopeID,
				Target:          ip,
				Observation: map[string]any{
					"protocol": p.Protocol,
					"port":     p.PortID,
					"service":  p.Service.Name,
					"product":  p.Service.Product,
					"version":  p.Service.Version,
				},
				Confidence:   Detected,
				TimestampUTC: time.Now().UTC(),
			})
		}
	}
	return records, nil
}

func joinPorts(ports []int) string {
	var buf bytes.Buffer
	for i, p := range ports {
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.WriteString(strconv.Itoa(p))
	}
	return buf.String()
}
