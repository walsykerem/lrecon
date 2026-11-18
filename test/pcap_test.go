package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPcapKind(t *testing.T) {
	classic := make([]byte, 24)
	ng := make([]byte, 12)
	cases := []struct {
		name string
		head []byte
		want string
	}{
		{"nil", nil, ""},
		{"short", []byte{0xd4, 0xc3, 0xb2}, ""},
		{"classic truncated head", []byte{0xd4, 0xc3, 0xb2, 0xa1, 0, 0}, ""},
		{"pcap", append([]byte{0xd4, 0xc3, 0xb2, 0xa1}, classic[4:]...), "pcap"},
		{"pcap-be", append([]byte{0xa1, 0xb2, 0xc3, 0xd4}, classic[4:]...), "pcap-be"},
		{"pcap-ns", append([]byte{0x4d, 0x3c, 0xb2, 0xa1}, classic[4:]...), "pcap-ns"},
		{"pcap-ns-be", append([]byte{0xa1, 0xb2, 0x3c, 0x4d}, classic[4:]...), "pcap-ns-be"},
		{"pcapng", append([]byte{0x0a, 0x0d, 0x0d, 0x0a}, ng[4:]...), "pcapng"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := pcapKind(c.head); got != c.want {
				t.Fatalf("pcapKind = %q, want %q", got, c.want)
			}
		})
	}
}

// ethIPv4TCP builds a 34-byte ethernet frame carrying a bare IPv4/TCP header.
func ethIPv4TCP() []byte {
	f := make([]byte, 14+20)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	f[14] = 0x45
	f[14+9] = 6
	return f
}

// pcapLE builds a little-endian microsecond capture with one record per packet.
func pcapLE(linkType uint32, pkts ...[]byte) []byte {
	h := make([]byte, 24)
	copy(h, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(h[4:6], 2)
	binary.LittleEndian.PutUint16(h[6:8], 4)
	binary.LittleEndian.PutUint32(h[16:20], 65535)
	binary.LittleEndian.PutUint32(h[20:24], linkType)
	for i, p := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], 1714557600+uint32(i))
		binary.LittleEndian.PutUint32(rec[4:8], 431000+uint32(i)*100000)
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(p)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(p)))
		h = append(h, rec...)
		h = append(h, p...)
	}
	return h
}

func TestPcapClassicDigest(t *testing.T) {
	frame := ethIPv4TCP()
	path := writeTemp(t, "three.pcap", pcapLE(1, frame, frame, frame))
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pcap" || d.Format != "pcap" {
		t.Fatalf("kind/format = %q/%q, want pcap/pcap", d.Kind, d.Format)
	}
	if d.PcapPackets != 3 {
		t.Fatalf("PcapPackets = %d, want 3", d.PcapPackets)
	}
	if d.PcapLinkType != "ethernet" {
		t.Fatalf("PcapLinkType = %q, want ethernet", d.PcapLinkType)
	}
	if d.PcapSpan != "2024-05-01T10:00:00Z (+2.2s)" {
		t.Fatalf("PcapSpan = %q", d.PcapSpan)
	}
	want := []string{"ipv4", "tcp"}
	if strings.Join(d.PcapProtos, ",") != strings.Join(want, ",") {
		t.Fatalf("PcapProtos = %v, want %v", d.PcapProtos, want)
	}
}

func TestPcapTruncatedRecord(t *testing.T) {
	frame := ethIPv4TCP()
	b := pcapLE(1, frame)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[8:12], 100)
	b = append(b, rec...)
	b = append(b, frame[:10]...)
	d, err := Probe(writeTemp(t, "truncated.pcap", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.PcapPackets != 1 {
		t.Fatalf("PcapPackets = %d, want 1", d.PcapPackets)
	}
	if len(d.Notes) == 0 || !strings.Contains(strings.Join(d.Notes, "; "), "truncated") {
		t.Fatalf("Notes = %v, want truncation note", d.Notes)
	}
	if !d.Truncated {
		t.Fatal("Truncated = false, want a cut capture to gate absence claims")
	}
}

// pcapngBlock wraps a body in a little-endian pcapng block with length trailer.
func pcapngBlock(btype uint32, body []byte) []byte {
	pad := (4 - len(body)%4) % 4
	n := 12 + len(body) + pad
	b := make([]byte, n)
	binary.LittleEndian.PutUint32(b[0:4], btype)
	binary.LittleEndian.PutUint32(b[4:8], uint32(n))
	copy(b[8:], body)
	binary.LittleEndian.PutUint32(b[n-4:], uint32(n))
	return b
}

func TestPcapngDigest(t *testing.T) {
	var b []byte
	b = append(b, pcapngBlock(0x0a0d0d0a, []byte{
		0x4d, 0x3c, 0x2b, 0x1a, // little-endian byte-order magic
		1, 0, 0, 0, // version 1.0
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // section length unknown
	})...)
	b = append(b, pcapngBlock(1, []byte{
		1, 0, // linktype ethernet
		0, 0, // reserved
		0xff, 0xff, 0, 0, // snaplen
	})...)
	frame := ethIPv4TCP()
	for i := range 2 {
		epb := make([]byte, 20)
		us := uint64(1714557600000000 + int64(i)*1000000)
		binary.LittleEndian.PutUint32(epb[4:8], uint32(us>>32))
		binary.LittleEndian.PutUint32(epb[8:12], uint32(us))
		binary.LittleEndian.PutUint32(epb[12:16], uint32(len(frame)))
		binary.LittleEndian.PutUint32(epb[16:20], uint32(len(frame)))
		epb = append(epb, frame...)
		b = append(b, pcapngBlock(6, epb)...)
	}
	d, err := Probe(writeTemp(t, "two.pcapng", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pcap" || d.Format != "pcapng" {
		t.Fatalf("kind/format = %q/%q, want pcap/pcapng", d.Kind, d.Format)
	}
	if d.PcapPackets != 2 {
		t.Fatalf("PcapPackets = %d, want 2", d.PcapPackets)
	}
	if d.PcapLinkType != "ethernet" {
		t.Fatalf("PcapLinkType = %q, want ethernet", d.PcapLinkType)
	}
	if d.PcapSpan != "2024-05-01T10:00:00Z (+1s)" {
		t.Fatalf("PcapSpan = %q", d.PcapSpan)
	}
}

// frameIPv4 wraps an L4 segment in ethernet + a bare 20-byte IPv4 header.
func frameIPv4(proto byte, l4 []byte) []byte {
	f := make([]byte, 14+20)
	binary.BigEndian.PutUint16(f[12:14], 0x0800)
	ip := f[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(l4)))
	ip[9] = proto
	ip[12], ip[16], ip[19] = 10, 10, 1
	return append(f, l4...)
}

func udpSegment(dst uint16, payload []byte) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[2:4], dst)
	binary.BigEndian.PutUint16(b[4:6], uint16(8+len(payload)))
	return append(b, payload...)
}

func tcpSegment(dst uint16, payload []byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[2:4], dst)
	b[12] = 5 << 4
	return append(b, payload...)
}

// dnsQuery builds a single-question DNS message with QTYPE A / QCLASS IN.
func dnsQuery(name string) []byte {
	b := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for label := range strings.SplitSeq(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0, 0, 1, 0, 1)
}

// tlsClientHello builds a one-record TLS 1.2 ClientHello carrying server_name.
func tlsClientHello(sni string) []byte {
	host := []byte(sni)
	list := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, host...)
	extData := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
	ext := append([]byte{0, 0, byte(len(extData) >> 8), byte(len(extData))}, extData...)
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = append(body, 0, 2, 0x13, 0x01)
	body = append(body, 1, 0)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func TestPcapAppLayer(t *testing.T) {
	b := pcapLE(1,
		frameIPv4(17, udpSegment(53, dnsQuery("Example.COM"))),
		frameIPv4(6, tcpSegment(443, tlsClientHello("api.example.com"))),
		frameIPv4(6, tcpSegment(80, []byte("GET /index.html?x=1 HTTP/1.1\r\nHost: example.com\r\n\r\n"))),
		frameIPv4(6, tcpSegment(80, []byte("POST /submit HTTP/1.1\r\n\r\n"))),
		frameIPv4(17, udpSegment(53, dnsQuery("example.com"))),
		frameIPv4(17, udpSegment(53, []byte{0xff, 0x01})), // malformed, ignored
	)
	d, err := Probe(writeTemp(t, "app.pcap", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := strings.Join(d.PcapDNS, ","); got != "example.com" {
		t.Fatalf("PcapDNS = %q, want example.com", got)
	}
	if got := strings.Join(d.PcapSNI, ","); got != "api.example.com" {
		t.Fatalf("PcapSNI = %q, want api.example.com", got)
	}
	if got := strings.Join(d.PcapURIs, ","); got != "/index.html?x=1,/submit" {
		t.Fatalf("PcapURIs = %q", got)
	}
}

func TestPcapAppRawIPLinkType(t *testing.T) {
	pkt := frameIPv4(17, udpSegment(53, dnsQuery("raw.example")))[14:]
	d, err := Probe(writeTemp(t, "raw.pcap", pcapLE(101, pkt)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := strings.Join(d.PcapDNS, ","); got != "raw.example" {
		t.Fatalf("PcapDNS = %q, want raw.example", got)
	}
}

func TestPcapAppListCap(t *testing.T) {
	pkts := make([][]byte, 40)
	for i := range pkts {
		pkts[i] = frameIPv4(17, udpSegment(53, dnsQuery(fmt.Sprintf("h%d.example", i))))
	}
	d, err := Probe(writeTemp(t, "cap.pcap", pcapLE(1, pkts...)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.PcapDNS) != 32 || d.PcapDNS[0] != "h0.example" {
		t.Fatalf("PcapDNS len/first = %d/%q, want 32/h0.example", len(d.PcapDNS), d.PcapDNS[0])
	}
}

// pcapFwToolNameBlacklist are program/product names that must never reach a
// user-facing note: a note names the capability to use, never the tool.
var pcapFwToolNameBlacklist = []string{
	"tshark", "wireshark", "tcpdump", "binwalk", "unblob", "gunzip", "7z",
	"jadx", "apktool", "ilspy", "ghidra", "frida", "objdump", "otool",
	"sqlite3", "unzip",
}

// pcapFwAssertNoToolNames fails when any note names a tool.
func pcapFwAssertNoToolNames(t *testing.T, d Digest) {
	t.Helper()
	for _, n := range d.Notes {
		low := strings.ToLower(n)
		for _, bad := range pcapFwToolNameBlacklist {
			if strings.Contains(low, bad) {
				t.Errorf("note names a tool (%q): %q", bad, n)
			}
		}
	}
}

// TestPcapDeepNoteHandoff checks the capture handoff note names the next
// capability (link type, transport headers, stream reassembly) and no tool.
func TestPcapDeepNoteHandoff(t *testing.T) {
	d, err := Probe(writeTemp(t, "deep.pcap", pcapLE(1, ethIPv4TCP())))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pcap" {
		t.Fatalf("kind = %q, want pcap", d.Kind)
	}
	var deep string
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep: ") {
			deep = n
		}
	}
	if deep == "" {
		t.Fatalf("notes = %v, want a deep: note", d.Notes)
	}
	for _, want := range []string{"link type", "transport headers", "reassemble"} {
		if !strings.Contains(deep, want) {
			t.Fatalf("deep note = %q, want it to mention %q", deep, want)
		}
	}
	pcapFwAssertNoToolNames(t, d)
}

// TestPcapListCapNotes: a cut application-layer list says it was cut.
func TestPcapListCapNotes(t *testing.T) {
	pkts := make([][]byte, 40)
	for i := range pkts {
		pkts[i] = frameIPv4(17, udpSegment(53, dnsQuery(fmt.Sprintf("h%d.example", i))))
	}
	d, err := Probe(writeTemp(t, "cap.pcap", pcapLE(1, pkts...)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(d.PcapDNS) != pcapListCap {
		t.Fatalf("PcapDNS len = %d, want %d", len(d.PcapDNS), pcapListCap)
	}
	if !notesContain(d, "pcap dns names truncated to 32 of 40") {
		t.Fatalf("no truncation note: %v", d.Notes)
	}
}

// TestPcapProtoCapNote: the protocol hint list reports its own cut.
func TestPcapProtoCapNote(t *testing.T) {
	d := Digest{PcapPackets: 1, PcapProtos: []string{"vlan", "ipv4", "ipv6", "tcp", "udp", "icmp"}}
	pcapFinish(&d, time.Unix(0, 0), time.Unix(1, 0))
	if len(d.PcapProtos) != pcapProtoCap {
		t.Fatalf("PcapProtos = %v, want %d entries", d.PcapProtos, pcapProtoCap)
	}
	if !notesContain(d, "pcap protocols truncated to 5 of 6") {
		t.Fatalf("no truncation note: %v", d.Notes)
	}
}

// mergecap concatenates captures as pcapng sections. A later section must not
// inherit the previous section's link type and snaplen.
func TestPcapngSecondSectionResetsInterfaces(t *testing.T) {
	var b []byte
	shb := []byte{
		0x4d, 0x3c, 0x2b, 0x1a,
		1, 0, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	}
	epb := func(frame []byte) []byte {
		p := make([]byte, 20)
		binary.LittleEndian.PutUint32(p[4:8], uint32(1714557600))
		binary.LittleEndian.PutUint32(p[8:12], 0)
		binary.LittleEndian.PutUint32(p[12:16], uint32(len(frame)))
		binary.LittleEndian.PutUint32(p[16:20], uint32(len(frame)))
		return append(p, frame...)
	}
	idb := func(link uint16, snap uint32) []byte {
		p := make([]byte, 8)
		binary.LittleEndian.PutUint16(p[0:2], link)
		binary.LittleEndian.PutUint32(p[4:8], snap)
		return p
	}
	raw := ethIPv4TCP()[14:]
	b = append(b, pcapngBlock(0x0a0d0d0a, shb)...)
	b = append(b, pcapngBlock(1, idb(1, 65535))...)
	b = append(b, pcapngBlock(6, epb(ethIPv4TCP()))...)
	b = append(b, pcapngBlock(0x0a0d0d0a, shb)...)
	b = append(b, pcapngBlock(1, idb(101, 262144))...)
	b = append(b, pcapngBlock(6, epb(raw))...)

	d, err := Probe(writeTemp(t, "two-sections.pcapng", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.PcapPackets != 2 {
		t.Fatalf("PcapPackets = %d, want 2", d.PcapPackets)
	}
	if d.PcapLinkType != "raw-ip" {
		t.Fatalf("PcapLinkType = %q, want the last section's raw-ip", d.PcapLinkType)
	}
}

// TestPcapngUnreadEpbNotCounted: an EPB whose caplen runs past the block is not
// a packet the reader saw, so it must not inflate the count or the span.
func TestPcapngUnreadEpbNotCounted(t *testing.T) {
	var b []byte
	b = append(b, pcapngBlock(0x0a0d0d0a, []byte{
		0x4d, 0x3c, 0x2b, 0x1a,
		1, 0, 0, 0,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})...)
	b = append(b, pcapngBlock(1, []byte{
		1, 0,
		0, 0,
		0xff, 0xff, 0, 0,
	})...)
	corrupt := make([]byte, 20)
	binary.LittleEndian.PutUint32(corrupt[12:16], 100) // caplen past the block
	b = append(b, pcapngBlock(6, corrupt)...)

	frame := ethIPv4TCP()
	epb := make([]byte, 20)
	binary.LittleEndian.PutUint32(epb[8:12], 1714557600)
	binary.LittleEndian.PutUint32(epb[12:16], uint32(len(frame)))
	binary.LittleEndian.PutUint32(epb[16:20], uint32(len(frame)))
	epb = append(epb, frame...)
	b = append(b, pcapngBlock(6, epb)...)

	d, err := Probe(writeTemp(t, "skip.pcapng", b))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.PcapPackets != 1 {
		t.Fatalf("PcapPackets = %d, want 1", d.PcapPackets)
	}
}

func TestPcapAppLinuxSLLLinkType(t *testing.T) {
	hdr := make([]byte, 16) // pkttype, arphrd, halen, 8-byte addr, protocol
	binary.BigEndian.PutUint16(hdr[14:16], 0x0800)
	pkt := append(hdr, frameIPv4(17, udpSegment(53, dnsQuery("sll.example")))[14:]...)
	d, err := Probe(writeTemp(t, "sll.pcap", pcapLE(113, pkt)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := strings.Join(d.PcapDNS, ","); got != "sll.example" {
		t.Fatalf("PcapDNS = %q, want sll.example", got)
	}
}
