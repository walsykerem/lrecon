package main

// Shared plumbing for the capture and dylib items (final.md 30, 31, 43): one
// bounded pcap/pcapng reader, one L2-L4 decoder, the DNS/SNI/HTTP extractors
// both capture items share, and the Mach-O load-command reader that
// trace_dylib_resolution resolves against.
//
// The digest's pcap.go only aggregates hints into a Digest; it has no
// per-packet view, so this reader is the packet-level one and stays the only
// one. Names carry the netc prefix so the concurrently-added ops never collide.

import (
	"bytes"
	"crypto/md5"
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// netcFrameCap bounds how many packets one op decodes. A larger capture still
// reports its real packet count; only the decoded rows stop.
const netcFrameCap = 2000

// netcReadCap bounds bytes read from a capture: a 300 MB pcap must not become
// 300 MB of RSS. 32 MB holds far more than netcFrameCap frames of any snaplen.
const netcReadCap = 32 << 20

// netcCapInfo is the capture-level context every packet list is read against.
type netcCapInfo struct {
	Format    string `json:"format"`
	Link      uint32 `json:"link_type"`
	LinkName  string `json:"link_layer"`
	Snaplen   uint32 `json:"snaplen"`
	Packets   int    `json:"packets"`
	Decoded   int    `json:"decoded"`
	CapHit    bool   `json:"packet_cap_hit"`
	Truncated bool   `json:"file_truncated"`
	CapNote   string `json:"cap_note,omitempty"`
}

// netcFrame is one captured frame with the timestamp and link type it arrived
// under. data aliases the capture buffer and is only valid inside the callback.
type netcFrame struct {
	n    int
	ts   time.Time
	link uint32
	data []byte
}

// netcReadCapture walks a classic pcap or a pcapng file and hands the first
// limit frames to fn. In-file lengths are checked against the bytes actually
// left, never trusted.
func netcReadCapture(path string, limit int, fn func(netcFrame) error) (netcCapInfo, error) {
	var info netcCapInfo
	f, err := os.Open(path)
	if err != nil {
		return info, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return info, err
	}
	b, err := io.ReadAll(io.LimitReader(f, netcReadCap))
	if err != nil {
		return info, err
	}
	more := st.Size() > netcReadCap
	if more {
		info.Truncated = true
		info.CapNote = fmt.Sprintf("read capped at %d bytes of %d; later packets not decoded", netcReadCap, st.Size())
	}
	switch kind := pcapKind(b); {
	case kind == "pcapng":
		err = netcPcapng(b, limit, &info, fn, more)
	case strings.HasPrefix(kind, "pcap"):
		err = netcClassic(b, kind, limit, &info, fn, more)
	default:
		return info, fmt.Errorf("%s is neither a pcap nor a pcapng capture (%d bytes, magic % x)", path, len(b), head4(b))
	}
	return info, err
}

func head4(b []byte) []byte {
	if len(b) > 4 {
		return b[:4]
	}
	return b
}

func netcClassic(b []byte, kind string, limit int, info *netcCapInfo, fn func(netcFrame) error, capOnly bool) error {
	bo := binary.ByteOrder(binary.LittleEndian)
	nano := false
	switch kind {
	case "pcap-be":
		bo = binary.BigEndian
	case "pcap-ns":
		nano = true
	case "pcap-ns-be":
		bo, nano = binary.BigEndian, true
	}
	info.Format, info.Snaplen, info.Link = "pcap", bo.Uint32(b[16:20]), bo.Uint32(b[20:24])
	info.LinkName = pcapLinkName(info.Link)
	off := 24
	for off < len(b) {
		if off+16 > len(b) {
			info.Truncated = true
			if capOnly {
				return nil
			}
			return fmt.Errorf("pcap record header at offset %#x is truncated (%d bytes left)", off, len(b)-off)
		}
		sec, frac := bo.Uint32(b[off:]), bo.Uint32(b[off+4:])
		incl := int(bo.Uint32(b[off+8:]))
		hdrOff := off
		off += 16
		if info.Snaplen > 0 && uint32(incl) > info.Snaplen {
			return fmt.Errorf("pcap record at offset %#x claims %d captured bytes, over snaplen %d", hdrOff, incl, info.Snaplen)
		}
		if incl > len(b)-off {
			info.Truncated = true
			if capOnly {
				return nil
			}
			return fmt.Errorf("pcap record at offset %#x claims %d bytes, only %d left in the file", hdrOff, incl, len(b)-off)
		}
		nanos := int64(frac) * 1000
		if nano {
			nanos = int64(frac)
		}
		info.Packets++
		if info.Decoded < limit {
			info.Decoded++
			if err := fn(netcFrame{n: info.Packets, ts: time.Unix(int64(sec), nanos).UTC(), link: info.Link, data: b[off : off+incl]}); err != nil {
				return err
			}
		} else {
			info.CapHit = true
		}
		off += incl
	}
	return nil
}

// netcPcapng walks the block chain: SHB fixes the byte order, IDB adds an
// interface (link type, snaplen, timestamp resolution), EPB/SPB carry frames.
func netcPcapng(b []byte, limit int, info *netcCapInfo, fn func(netcFrame) error, capOnly bool) error {
	info.Format = "pcapng"
	var bo binary.ByteOrder
	var links []uint32
	var snaplens []uint32
	var resol []int // 10^-resol seconds per tick, interface default 6 (microseconds)
	off := 0
	for off < len(b) {
		if off+12 > len(b) {
			info.Truncated = true
			if capOnly {
				return nil
			}
			return fmt.Errorf("pcapng block header at offset %#x is truncated (%d bytes left)", off, len(b)-off)
		}
		btype := binary.LittleEndian.Uint32(b[off:])
		// A section header carries the byte order of its own length field and
		// of every block that follows, so read its BOM before the length is
		// trusted. Without this a big-endian SHB reads as 0x1c000000 bytes.
		if btype == 0x0a0d0d0a {
			if o := pcapngOrder(b[off+8 : off+12]); o != nil {
				bo = o
			}
		}
		if bo != nil {
			btype = bo.Uint32(b[off:])
		}
		blen := binary.LittleEndian.Uint32(b[off+4:])
		if bo != nil {
			blen = bo.Uint32(b[off+4:])
		}
		if blen < 12 || blen%4 != 0 {
			return fmt.Errorf("pcapng block at offset %#x declares length %d (must be >=12 and a multiple of 4)", off, blen)
		}
		if int64(blen) > int64(len(b)-off) {
			info.Truncated = true
			if capOnly {
				return nil
			}
			return fmt.Errorf("pcapng block at offset %#x declares %d bytes, only %d left in the file", off, blen, len(b)-off)
		}
		body := b[off+8 : off+int(blen)-4]
		switch btype {
		case 0x0a0d0d0a: // section header: fixes the byte order for what follows
			if len(body) < 16 {
				return fmt.Errorf("pcapng section header at offset %#x is %d bytes, need 16", off, len(body))
			}
			o := pcapngOrder(body[:4])
			if o == nil {
				return fmt.Errorf("pcapng section header at offset %#x has byte-order magic % x", off, body[:4])
			}
			bo = o
			links, snaplens, resol = nil, nil, nil
		case 0x00000001: // interface description
			if bo == nil {
				return fmt.Errorf("pcapng interface block at offset %#x precedes any section header", off)
			}
			if len(body) < 8 {
				return fmt.Errorf("pcapng interface block at offset %#x is %d bytes, need 8", off, len(body))
			}
			links = append(links, uint32(bo.Uint16(body[:2])))
			snaplens = append(snaplens, bo.Uint32(body[4:8]))
			resol = append(resol, netcTSResol(body[8:], bo))
			if info.Link == 0 && len(links) == 1 {
				info.Link = links[0]
				info.LinkName = pcapLinkName(links[0])
				info.Snaplen = snaplens[0]
			}
		case 0x00000006: // enhanced packet
			if bo == nil || len(links) == 0 {
				return fmt.Errorf("pcapng packet block at offset %#x has no interface to belong to", off)
			}
			if len(body) < 20 {
				return fmt.Errorf("pcapng packet block at offset %#x is %d bytes, need 20", off, len(body))
			}
			id := bo.Uint32(body[:4])
			if int(id) >= len(links) && id != 0xffffffff {
				return fmt.Errorf("pcapng packet block at offset %#x names interface %d of %d", off, id, len(links))
			}
			if id == 0xffffffff {
				id = 0
			}
			capLen := int(bo.Uint32(body[12:16]))
			if capLen > len(body)-20 {
				return fmt.Errorf("pcapng packet block at offset %#x captures %d bytes over its %d-byte payload", off, capLen, len(body)-20)
			}
			if snaplens[id] > 0 && uint32(capLen) > snaplens[id] {
				return fmt.Errorf("pcapng packet block at offset %#x captures %d bytes, over interface snaplen %d", off, capLen, snaplens[id])
			}
			ts := netcEpbTime(uint64(bo.Uint32(body[4:8]))<<32|uint64(bo.Uint32(body[8:12])), resol[id])
			info.Packets++
			if info.Decoded < limit {
				info.Decoded++
				if err := fn(netcFrame{n: info.Packets, ts: ts, link: links[id], data: body[20 : 20+capLen]}); err != nil {
					return err
				}
			} else {
				info.CapHit = true
			}
		case 0x00000003: // simple packet, interface 0 only
			if bo == nil || len(links) == 0 {
				return fmt.Errorf("pcapng simple packet block at offset %#x has no interface to belong to", off)
			}
			if len(body) < 4 {
				return fmt.Errorf("pcapng simple packet block at offset %#x is %d bytes, need 4", off, len(body))
			}
			orig := int(bo.Uint32(body[:4]))
			data := body[4:]
			if orig < len(data) { // the padding up to the 4-byte boundary is not frame data
				data = data[:orig]
			}
			info.Link, info.LinkName, info.Snaplen = links[0], pcapLinkName(links[0]), snaplens[0]
			info.Packets++
			if info.Decoded < limit {
				info.Decoded++
				if err := fn(netcFrame{n: info.Packets, ts: time.Time{}, link: links[0], data: data}); err != nil {
					return err
				}
			} else {
				info.CapHit = true
			}
		}
		off += int(blen)
	}
	return nil
}

// netcTSResol reads the if_tsresol option (code 9) of an interface block; the
// default is 6 (microseconds). Values above 18 would overflow the nanosecond
// conversion, so they are clamped.
func netcTSResol(opts []byte, bo binary.ByteOrder) int {
	for len(opts) >= 4 {
		code, olen := bo.Uint16(opts[:2]), int(bo.Uint16(opts[2:4]))
		opts = opts[4:]
		if code == 0 || olen > len(opts) {
			break
		}
		if code == 9 && olen == 1 {
			r := min(int(opts[0]&0x7f), 18)
			return r
		}
		pad := (4 - olen%4) % 4
		if olen+pad > len(opts) {
			break
		}
		opts = opts[olen+pad:]
	}
	return 6
}

func netcEpbTime(ticks uint64, resol int) time.Time {
	var ns int64
	if resol <= 9 {
		ns = int64(ticks) * int64(pow10(9-resol))
	} else {
		ns = int64(ticks / pow10(resol-9))
	}
	return time.Unix(0, ns).UTC()
}

func pow10(n int) uint64 {
	v := uint64(1)
	for range n {
		v *= 10
	}
	return v
}

// --- packet fields ---

type netcL2 struct {
	Kind      string   `json:"kind"`
	Src       string   `json:"src,omitempty"`
	Dst       string   `json:"dst,omitempty"`
	EtherType string   `json:"ethertype,omitempty"`
	VLAN      []uint16 `json:"vlan,omitempty"`
}

type netcIP struct {
	Version    int    `json:"version"`
	Src        string `json:"src"`
	Dst        string `json:"dst"`
	TTL        int    `json:"ttl"`
	Protocol   string `json:"protocol"`
	HeaderLen  int    `json:"header_len"`
	TotalLen   int    `json:"total_len"`
	ID         uint16 `json:"id,omitempty"`
	Fragmented bool   `json:"fragmented"`
}

type netcTCP struct {
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Seq       uint32 `json:"seq"`
	Ack       uint32 `json:"ack"`
	Flags     string `json:"flags"`
	HeaderLen int    `json:"header_len"`
	Window    int    `json:"window"`
}

type netcUDP struct {
	SrcPort int `json:"src_port"`
	DstPort int `json:"dst_port"`
	Length  int `json:"length"`
}

type netcICMP struct {
	Type int `json:"type"`
	Code int `json:"code"`
}

type netcPayload struct {
	Offset int `json:"offset"` // byte offset of the L4 payload inside the frame
	Length int `json:"length"`
}

// netcPacket is one decoded frame: L2, best-effort L3/L4, then whatever
// application protocol the ports and payload actually carry.
type netcPacket struct {
	Frame   int          `json:"frame"`
	Time    string       `json:"time,omitempty"`
	Link    string       `json:"link"`
	L2      netcL2       `json:"l2"`
	IP      *netcIP      `json:"ip,omitempty"`
	TCP     *netcTCP     `json:"tcp,omitempty"`
	UDP     *netcUDP     `json:"udp,omitempty"`
	ICMP    *netcICMP    `json:"icmp,omitempty"`
	DNS     *netcDNSMsg  `json:"dns,omitempty"`
	TLS     *netcHello   `json:"tls,omitempty"`
	HTTP    *netcHTTPReq `json:"http,omitempty"`
	Payload *netcPayload `json:"payload,omitempty"`
	Note    string       `json:"note,omitempty"`
}

var netcEtherTypes = map[uint16]string{
	0x0800: "ipv4", 0x86dd: "ipv6", 0x0806: "arp", 0x8100: "vlan",
	0x88cc: "lldp", 0x8847: "mpls",
}

func netcMAC(b []byte) string { return net.HardwareAddr(b).String() }

// netcDecode dissects one frame down to L4 and the first application message.
// A frame shorter than the layer it claims gets a note, not a silent drop.
func netcDecode(f netcFrame) netcPacket {
	p := netcPacket{Frame: f.n, Link: pcapLinkName(f.link)}
	if !f.ts.IsZero() {
		p.Time = f.ts.Format(time.RFC3339Nano)
	}
	data, off := f.data, 0
	switch f.link {
	case 1: // ethernet
		if len(data) < 14 {
			p.Note = fmt.Sprintf("frame is %d bytes, shorter than the 14-byte ethernet header", len(data))
			return p
		}
		p.L2 = netcL2{Kind: "ethernet", Dst: netcMAC(data[0:6]), Src: netcMAC(data[6:12])}
		et := binary.BigEndian.Uint16(data[12:14])
		off = 14
		for et == 0x8100 && off+4 <= len(data) {
			p.L2.VLAN = append(p.L2.VLAN, binary.BigEndian.Uint16(data[off:off+2])&0x0fff)
			et = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
		p.L2.EtherType = netcEtherName(et)
		switch et {
		case 0x0800, 0x86dd:
		default:
			return p
		}
	case 113: // linux cooked v1
		if len(data) < 16 {
			p.Note = "frame shorter than the 16-byte linux-sll header"
			return p
		}
		p.L2 = netcL2{Kind: "linux-sll", Src: netcMAC(data[6:12]), EtherType: netcEtherName(binary.BigEndian.Uint16(data[14:16]))}
		off = 16
		if et := binary.BigEndian.Uint16(data[14:16]); et != 0x0800 && et != 0x86dd {
			return p
		}
	case 101, 228, 229: // raw ip
		p.L2 = netcL2{Kind: "raw-ip"}
	default:
		p.Note = fmt.Sprintf("link type %s is not dissected (ethernet, linux-sll and raw-ip are)", pcapLinkName(f.link))
		return p
	}
	if off >= len(data) {
		p.Note = "frame ends before the network header"
		return p
	}
	// every layer is bounded by the IP total length, never by the frame: an
	// ethernet frame pads short packets to 60 bytes and that padding is not
	// segment data
	switch data[off] >> 4 {
	case 4:
		ip, l4, end, note := netcIPv4(data, off)
		p.IP, p.Note = ip, note
		if ip == nil {
			return p
		}
		return netcL4(p, data[:end], l4, ip.Protocol)
	case 6:
		ip, l4, end, note := netcIPv6(data, off)
		p.IP, p.Note = ip, note
		if ip == nil {
			return p
		}
		return netcL4(p, data[:end], l4, ip.Protocol)
	default:
		p.Note = fmt.Sprintf("network header version nibble %d is neither 4 nor 6", data[off]>>4)
		return p
	}
}

func netcEtherName(et uint16) string {
	if n, ok := netcEtherTypes[et]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", et)
}

func netcIPv4(data []byte, off int) (*netcIP, int, int, string) {
	if off+20 > len(data) {
		return nil, 0, 0, "frame ends inside the 20-byte ipv4 header"
	}
	ihl := int(data[off]&0x0f) * 4
	if ihl < 20 {
		return nil, 0, 0, fmt.Sprintf("ipv4 IHL %d is below the 20-byte minimum", ihl)
	}
	if off+ihl > len(data) {
		return nil, 0, 0, "frame ends inside the ipv4 options"
	}
	total := int(binary.BigEndian.Uint16(data[off+2 : off+4]))
	ip := &netcIP{
		Version:   4,
		Src:       net.IP(data[off+12 : off+16]).String(),
		Dst:       net.IP(data[off+16 : off+20]).String(),
		TTL:       int(data[off+8]),
		Protocol:  netcProtoName(data[off+9]),
		HeaderLen: ihl,
		TotalLen:  total,
		ID:        binary.BigEndian.Uint16(data[off+4 : off+6]),
	}
	if frag := binary.BigEndian.Uint16(data[off+6 : off+8]); frag&0x3fff != 0 {
		ip.Fragmented = true
	}
	end := len(data)
	if total >= ihl && off+total <= len(data) {
		end = off + total
	}
	return ip, off + ihl, end, ""
}

func netcIPv6(data []byte, off int) (*netcIP, int, int, string) {
	if off+40 > len(data) {
		return nil, 0, 0, "frame ends inside the 40-byte ipv6 header"
	}
	ip := &netcIP{
		Version:   6,
		Src:       net.IP(data[off+8 : off+24]).String(),
		Dst:       net.IP(data[off+24 : off+40]).String(),
		TTL:       int(data[off+7]),
		HeaderLen: 40,
		TotalLen:  40 + int(binary.BigEndian.Uint16(data[off+4:off+6])),
	}
	next := data[off+6]
	p := off + 40
	for range 8 { // bound the extension chain
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if p+2 > len(data) {
				return ip, 0, 0, "frame ends inside an ipv6 extension header"
			}
			next, p = data[p], p+(int(data[p+1])+1)*8
		case 44: // fragment header
			if p >= len(data) {
				return ip, 0, 0, "frame ends inside the ipv6 fragment header"
			}
			ip.Fragmented = true
			next, p = data[p], p+8
		case 51: // authentication header
			if p+2 > len(data) {
				return ip, 0, 0, "frame ends inside the ipv6 authentication header"
			}
			next, p = data[p], p+(int(data[p+1])+2)*4
		default:
			ip.Protocol = netcProtoName(next)
			if p > len(data) {
				return ip, 0, 0, "ipv6 extension chain runs past the frame"
			}
			end := len(data)
			if ip.TotalLen > 0 && off+ip.TotalLen <= len(data) {
				end = off + ip.TotalLen
			}
			return ip, p, end, ""
		}
		if p > len(data) {
			return ip, 0, 0, "ipv6 extension chain runs past the frame"
		}
	}
	return ip, 0, 0, "ipv6 extension chain is longer than 8 headers"
}

func netcProtoName(p byte) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmp6"
	case 2:
		return "igmp"
	default:
		return fmt.Sprintf("ip-%d", p)
	}
}

func netcL4(p netcPacket, data []byte, off int, proto string) netcPacket {
	if off <= 0 || off > len(data) {
		if p.Note == "" {
			p.Note = "L4 header offset is past the frame"
		}
		return p
	}
	switch proto {
	case "tcp":
		if off+20 > len(data) {
			p.Note = "frame ends inside the 20-byte tcp header"
			return p
		}
		hlen := int(data[off+12]>>4) * 4
		if hlen < 20 || off+hlen > len(data) {
			p.Note = fmt.Sprintf("tcp data offset %d is outside the frame", hlen)
			return p
		}
		p.TCP = &netcTCP{
			SrcPort:   int(binary.BigEndian.Uint16(data[off : off+2])),
			DstPort:   int(binary.BigEndian.Uint16(data[off+2 : off+4])),
			Seq:       binary.BigEndian.Uint32(data[off+4 : off+8]),
			Ack:       binary.BigEndian.Uint32(data[off+8 : off+12]),
			Flags:     netcTCPFlags(data[off+13]),
			HeaderLen: hlen,
			Window:    int(binary.BigEndian.Uint16(data[off+14 : off+16])),
		}
		pay := data[off+hlen:]
		p.Payload = &netcPayload{Offset: off + hlen, Length: len(pay)}
		if len(pay) == 0 {
			return p
		}
		if h := netcClientHello(pay); h != nil {
			p.TLS = h
			return p
		}
		if r := netcParseHTTPReq(pay); r != nil {
			p.HTTP = r
			return p
		}
	case "udp":
		if off+8 > len(data) {
			p.Note = "frame ends inside the 8-byte udp header"
			return p
		}
		ulen := int(binary.BigEndian.Uint16(data[off+4 : off+6]))
		p.UDP = &netcUDP{
			SrcPort: int(binary.BigEndian.Uint16(data[off : off+2])),
			DstPort: int(binary.BigEndian.Uint16(data[off+2 : off+4])),
			Length:  ulen,
		}
		pay := data[off+8:]
		if ulen >= 8 && ulen-8 < len(pay) {
			pay = pay[:ulen-8] // the UDP length, not the frame, bounds the datagram
		}
		p.Payload = &netcPayload{Offset: off + 8, Length: len(pay)}
		if (p.UDP.SrcPort == 53 || p.UDP.DstPort == 53) && len(pay) > 0 {
			p.DNS = netcDNS(pay)
		} else if len(pay) > 2 && (p.UDP.SrcPort == 443 || p.UDP.DstPort == 443) && pay[0] == 0x16 {
			p.Note = "quic initial is not decrypted"
		}
	case "icmp", "icmp6":
		if off+4 > len(data) {
			p.Note = "frame ends inside the 4-byte icmp header"
			return p
		}
		p.ICMP = &netcICMP{Type: int(data[off]), Code: int(data[off+1])}
		p.Payload = &netcPayload{Offset: off + 4, Length: len(data) - off - 4}
	default:
		p.Payload = &netcPayload{Offset: off, Length: len(data) - off}
	}
	return p
}

// netcTCPFlags renders the flag byte as the set flags in a fixed order.
func netcTCPFlags(f byte) string {
	var b strings.Builder
	for _, f2 := range [...]struct {
		bit byte
		c   byte
	}{{0x02, 'S'}, {0x01, 'F'}, {0x04, 'R'}, {0x08, 'P'}, {0x10, 'A'}, {0x20, 'U'}, {0x40, 'E'}, {0x80, 'C'}} {
		if f&f2.bit != 0 {
			b.WriteByte(f2.c)
		}
	}
	return b.String()
}

// --- application protocols ---

type netcDNSQ struct {
	Name  string `json:"name"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

type netcDNSMsg struct {
	ID        uint16     `json:"id"`
	Response  bool       `json:"response"`
	Opcode    int        `json:"opcode"`
	Rcode     int        `json:"rcode"`
	Questions []netcDNSQ `json:"questions"`
	Answers   int        `json:"answers"`
}

var netcDNSTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
	16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 43: "DS", 65: "HTTPS",
}

// netcDNS parses the question section and the answer count. Compression
// pointers are skipped, never followed, so a hostile packet cannot loop.
func netcDNS(msg []byte) *netcDNSMsg {
	if len(msg) < 12 {
		return nil
	}
	m := &netcDNSMsg{
		ID:       binary.BigEndian.Uint16(msg[:2]),
		Response: msg[2]&0x80 != 0,
		Opcode:   int(msg[2] >> 3 & 0x0f),
		Rcode:    int(msg[3] & 0x0f),
		Answers:  int(binary.BigEndian.Uint16(msg[6:8])),
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for i := 0; i < qd && i < 16; i++ {
		name, next, ok := dnsQName(msg, off)
		if !ok || next+4 > len(msg) {
			break
		}
		m.Questions = append(m.Questions, netcDNSQ{
			Name:  strings.ToLower(name),
			Type:  binary.BigEndian.Uint16(msg[next : next+2]),
			Class: binary.BigEndian.Uint16(msg[next+2 : next+4]),
		})
		off = next + 4
	}
	return m
}

// netcHello is the TLS ClientHello fingerprint: server name, ALPN, and the JA3
// string with its MD5, which is what actually distinguishes one client stack.
type netcHello struct {
	Version    uint16   `json:"version"`
	SNI        string   `json:"sni,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	Ciphers    []uint16 `json:"ciphers"`
	Extensions []uint16 `json:"extensions"`
	JA3        string   `json:"ja3"`
	JA3MD5     string   `json:"ja3_md5"`
}

// netcGrease reports the reserved 0x?a?a values clients may inject at random;
// JA3 excludes them so a fingerprint stays stable across connections.
func netcGrease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func netcClientHello(seg []byte) *netcHello {
	if len(seg) < 6 || seg[0] != 0x16 || seg[1] != 0x03 {
		return nil
	}
	recLen := min(int(binary.BigEndian.Uint16(seg[3:5])), len(seg)-5)
	hs := seg[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 1 {
		return nil
	}
	hl := min(int(hs[1])<<16|int(hs[2])<<8|int(hs[3]), len(hs)-4)
	body := hs[4 : 4+hl]
	if len(body) < 35 {
		return nil
	}
	h := &netcHello{Version: binary.BigEndian.Uint16(body[:2])}
	p := 2 + 32
	sid := int(body[p])
	p++
	if p+sid > len(body) {
		return nil
	}
	p += sid
	if p+2 > len(body) {
		return nil
	}
	csl := int(binary.BigEndian.Uint16(body[p : p+2]))
	p += 2
	if p+csl > len(body) || csl%2 != 0 {
		return nil
	}
	for i := 0; i < csl; i += 2 {
		v := binary.BigEndian.Uint16(body[p+i : p+i+2])
		if !netcGrease(v) {
			h.Ciphers = append(h.Ciphers, v)
		}
	}
	p += csl
	if p >= len(body) {
		return nil
	}
	comp := int(body[p])
	p++
	if p+comp > len(body) {
		return nil
	}
	p += comp
	var groups []uint16
	var points []uint8
	if p+2 <= len(body) {
		end := p + 2 + int(binary.BigEndian.Uint16(body[p:p+2]))
		p += 2
		if end > len(body) {
			end = len(body)
		}
		for p+4 <= end {
			et := binary.BigEndian.Uint16(body[p : p+2])
			el := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
			p += 4
			if p+el > end {
				break
			}
			ext := body[p : p+el]
			if !netcGrease(et) {
				h.Extensions = append(h.Extensions, et)
			}
			switch et {
			case 0:
				h.SNI = netcSNI(ext)
			case 16:
				h.ALPN = netcALPN(ext)
			case 10:
				if len(ext) >= 2 {
					n := int(binary.BigEndian.Uint16(ext[:2]))
					if n <= len(ext)-2 {
						for i := 0; i+2 <= n; i += 2 {
							g := binary.BigEndian.Uint16(ext[2+i : 4+i])
							if !netcGrease(g) {
								groups = append(groups, g)
							}
						}
					}
				}
			case 11:
				if len(ext) >= 1 && int(ext[0]) <= len(ext)-1 {
					points = append(points, ext[1:1+int(ext[0])]...)
				}
			}
			p += el
		}
	}
	h.JA3 = fmt.Sprintf("%d,%s,%s,%s,%s",
		h.Version, netcJoinU16(h.Ciphers, "-"), netcJoinU16(h.Extensions, "-"),
		netcJoinU16(groups, "-"), netcJoinBytes(points, "-"))
	sum := md5.Sum([]byte(h.JA3)) // NOSONAR: JA3 specifies MD5 for this public, non-security fingerprint.
	h.JA3MD5 = hex.EncodeToString(sum[:])
	return h
}

func netcJoinU16(v []uint16, sep string) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, sep)
}

func netcJoinBytes(v []uint8, sep string) string {
	s := make([]string, len(v))
	for i, x := range v {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, sep)
}

func netcSNI(ext []byte) string {
	if len(ext) < 2 {
		return ""
	}
	listLen := min(int(binary.BigEndian.Uint16(ext[:2])), len(ext)-2)
	for p := 2; p+3 <= 2+listLen; {
		nt := ext[p]
		nl := int(binary.BigEndian.Uint16(ext[p+1 : p+3]))
		p += 3
		if p+nl > 2+listLen {
			return ""
		}
		if nt == 0 {
			return strings.ToLower(string(ext[p : p+nl]))
		}
		p += nl
	}
	return ""
}

func netcALPN(ext []byte) []string {
	if len(ext) < 2 {
		return nil
	}
	listLen := min(int(binary.BigEndian.Uint16(ext[:2])), len(ext)-2)
	var out []string
	for p := 2; p < 2+listLen; {
		n := int(ext[p])
		p++
		if n == 0 || p+n > 2+listLen {
			break
		}
		out = append(out, string(ext[p:p+n]))
		p += n
	}
	return out
}

type netcHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type netcHTTPReq struct {
	Method      string       `json:"method"`
	Target      string       `json:"target"`
	Version     string       `json:"version"`
	Headers     []netcHeader `json:"headers"`
	HeaderOrder []string     `json:"header_order"`
}

func (r *netcHTTPReq) header(name string) string {
	for _, h := range r.Headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

// netcHTTPReq reads an HTTP/1.x request head from one segment. The header list
// keeps its wire order because that order is part of the client fingerprint.
func netcParseHTTPReq(seg []byte) *netcHTTPReq {
	eol := bytes.Index(seg, []byte("\r\n"))
	if eol <= 0 || eol > 8192 {
		return nil
	}
	line := seg[:eol]
	sp1 := bytes.IndexByte(line, ' ')
	sp2 := bytes.LastIndexByte(line, ' ')
	if sp1 <= 0 || sp2 <= sp1 || !bytes.HasPrefix(line[sp2:], []byte(" HTTP/1.")) {
		return nil
	}
	for _, c := range line[:sp1] {
		if c < 'A' || c > 'Z' {
			return nil
		}
	}
	r := &netcHTTPReq{
		Method:  string(line[:sp1]),
		Target:  string(line[sp1+1 : sp2]),
		Version: string(line[sp2+1:]),
	}
	rest := seg[eol+2:]
	for range 64 {
		end := bytes.Index(rest, []byte("\r\n"))
		if end < 0 {
			return nil
		}
		if end == 0 {
			return r
		}
		h := rest[:end]
		colon := bytes.IndexByte(h, ':')
		if colon <= 0 {
			return r
		}
		name := string(h[:colon])
		value := strings.TrimLeft(string(h[colon+1:]), " \t")
		r.Headers = append(r.Headers, netcHeader{Name: name, Value: value})
		r.HeaderOrder = append(r.HeaderOrder, name)
		rest = rest[end+2:]
	}
	return r
}

// netcDylibCmd is one LC_*_DYLIB or LC_RPATH load command, read raw so the
// weak/reexport/upward variants debug/macho does not type still show up.
type netcDylibCmd struct {
	Kind string `json:"kind"` // load, weak, reexport, upward, id, rpath
	Path string `json:"path"`
}

const (
	lcLoadDylib     = 0xc
	lcIDDylib       = 0xd
	lcLoadWeakDylib = 0x80000018
	lcRpathCMD      = 0x8000001c
	lcReexportDylib = 0x8000001f
	lcUpwardDylib   = 0x80000023
)

// netcMachOLoadCommands reads every dylib and rpath command of one slice.
func netcMachOLoadCommands(mf *macho.File) ([]netcDylibCmd, error) {
	var out []netcDylibCmd
	bo := mf.ByteOrder
	for _, l := range mf.Loads {
		raw := l.Raw()
		if len(raw) < 12 {
			continue
		}
		cmd := bo.Uint32(raw[:4])
		var kind string
		switch cmd {
		case lcLoadDylib:
			kind = "load"
		case lcLoadWeakDylib:
			kind = "weak"
		case lcReexportDylib:
			kind = "reexport"
		case lcUpwardDylib:
			kind = "upward"
		case lcIDDylib:
			kind = "id"
		case lcRpathCMD:
			kind = "rpath"
		default:
			continue
		}
		noff := int(bo.Uint32(raw[8:12]))
		if noff < 12 || noff >= len(raw) {
			return nil, fmt.Errorf("%s command has a name offset %#x outside its %d-byte body", kind, noff, len(raw))
		}
		name, ok := cstr(raw, noff)
		if !ok {
			return nil, fmt.Errorf("%s command carries no NUL-terminated path", kind)
		}
		out = append(out, netcDylibCmd{Kind: kind, Path: name})
	}
	return out, nil
}

// netcExpandPath resolves dyld's three tokens. loaderDir is the directory of
// the image holding the command; exeDir is the main executable's directory.
func netcExpandPath(p, exeDir, loaderDir string) string {
	switch {
	case strings.HasPrefix(p, "@executable_path/"):
		return filepath.Join(exeDir, p[len("@executable_path/"):])
	case strings.HasPrefix(p, "@loader_path/"):
		return filepath.Join(loaderDir, p[len("@loader_path/"):])
	}
	return p
}

// netcDylibCandidates is dyld's search order: @rpath fans out over the image's
// own LC_RPATH list in link order, each rpath expanded for its own tokens.
// Anything else is one absolute (or cwd-relative) path and is not rewritten.
func netcDylibCandidates(name, exeDir, loaderDir string, rpaths []string) []string {
	if strings.HasPrefix(name, "@rpath/") {
		rest := name[len("@rpath/"):]
		var out []string
		for _, rp := range rpaths {
			out = append(out, filepath.Join(netcExpandPath(rp, exeDir, loaderDir), rest))
		}
		return out
	}
	return []string{netcExpandPath(name, exeDir, loaderDir)}
}

// netcFirstExisting reports the first candidate that names a regular file.
func netcFirstExisting(cands []string) string {
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return c
		}
	}
	return ""
}
