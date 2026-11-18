package main

import (
	"fmt"
	"strings"
)

// final.md: inspect_packet_capture.
func init() {
	registerOp(op{
		name:  "inspect_packet_capture",
		route: "L",
		desc:  "count every frame in a pcap/pcapng capture and report link type, time span, protocol hints and the first DNS, TLS SNI and HTTP targets (single-segment payloads only)",
		needs: true,
		run:   runInspectPacketCapture,
	})
}

// captureSummary is the traffic view of one capture, read from the same fields
// Probe fills: nothing here is decoded twice.
type captureSummary struct {
	Format   string   `json:"format"`
	Packets  int      `json:"packets"`
	LinkType string   `json:"link_type"`
	Span     string   `json:"span"`
	Protos   []string `json:"protocols"`
	DNS      []string `json:"dns"`
	SNI      []string `json:"sni"`
	URIs     []string `json:"uris"`
	Notes    []string `json:"notes,omitempty"`
}

func runInspectPacketCapture(path string) (any, error) {
	d, err := Probe(path)
	if err != nil {
		return nil, err
	}
	if d.Kind != "pcap" {
		return skipf("%s: %s is not a packet capture", path, d.Kind), nil
	}
	if d.PcapPackets == 0 {
		if len(d.Notes) > 0 {
			return nil, fmt.Errorf("%s is a %s file but has no readable packets: %s", path, d.Format, strings.Join(d.Notes, "; "))
		}
		return nil, fmt.Errorf("%s is a %s file but has no packets", path, d.Format)
	}
	return captureSummary{
		Format:   d.Format,
		Packets:  d.PcapPackets,
		LinkType: d.PcapLinkType,
		Span:     d.PcapSpan,
		Protos:   d.PcapProtos,
		DNS:      d.PcapDNS,
		SNI:      d.PcapSNI,
		URIs:     d.PcapURIs,
		Notes:    d.Notes,
	}, nil
}
