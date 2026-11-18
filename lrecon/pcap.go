package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"
)

const pcapPacketCap = 2000000

// pcapKind names the capture format from its magic, "" when it is not a capture.
// Classic pcap: micro/nanosecond magic in either endianness. pcapng: 0x0a0d0d0a.
func pcapKind(head []byte) string {
	if len(head) >= 12 && head[0] == 0x0a && head[1] == 0x0d && head[2] == 0x0d && head[3] == 0x0a {
		return "pcapng"
	}
	if len(head) < 24 {
		return ""
	}
	switch string(head[:4]) {
	case "\xd4\xc3\xb2\xa1":
		return "pcap"
	case "\xa1\xb2\xc3\xd4":
		return "pcap-be"
	case "\x4d\x3c\xb2\xa1":
		return "pcap-ns"
	case "\xa1\xb2\x3c\x4d":
		return "pcap-ns-be"
	}
	return ""
}

var pcapLinkTypes = map[uint32]string{
	1:   "ethernet",
	101: "raw-ip",
	105: "802.11",
	113: "linux-sll",
	127: "radiotap",
	228: "raw-ipv4",
	229: "raw-ipv6",
}

func pcapLinkName(lt uint32) string {
	if n, ok := pcapLinkTypes[lt]; ok {
		return n
	}
	return fmt.Sprintf("linktype-%d", lt)
}

// inspectPcap fills packet count, link type, time span and the first few
// protocol hints without dissecting payloads.
func inspectPcap(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	head, _ := r.Peek(24)
	switch kind := pcapKind(head); kind {
	case "pcapng":
		inspectPcapng(r, d)
	case "":
		return
	default:
		inspectClassic(r, kind, d)
	}
	if d.PcapPackets > 0 {
		deepNote(d, "capture holds link-layer frames with timestamps; decode the link type, then transport headers, and reassemble TCP streams so request/response pairs and payload bytes become readable")
	}
}

func inspectClassic(r *bufio.Reader, kind string, d *Digest) {
	var bo binary.ByteOrder = binary.LittleEndian
	nano := false
	switch kind {
	case "pcap-be":
		bo = binary.BigEndian
	case "pcap-ns":
		nano = true
	case "pcap-ns-be":
		bo, nano = binary.BigEndian, true
	}
	hdr := make([]byte, 24)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	lt := bo.Uint32(hdr[20:24])
	d.PcapLinkType = pcapLinkName(lt)
	// A record may not claim more captured bytes than the header's snaplen:
	// a larger caplen is a corrupt file, not a bigger packet.
	snap := bo.Uint32(hdr[16:20])

	rec := make([]byte, 16)
	buf := make([]byte, 1<<16)
	var first, last time.Time
	scanned := 0
	for d.PcapPackets < pcapPacketCap {
		if _, err := io.ReadFull(r, rec); err != nil {
			// a half record header at EOF is a truncated capture, plain EOF is the end
			if err != io.EOF {
				d.Truncated = true
			}
			if err == io.ErrUnexpectedEOF {
				d.Notes = append(d.Notes, "pcap truncated mid-record")
			}
			break
		}
		sec := bo.Uint32(rec[0:4])
		frac := int64(bo.Uint32(rec[4:8]))
		incl := bo.Uint32(rec[8:12])
		nanos := frac * 1000
		if nano {
			nanos = frac
		}
		if snap > 0 && incl > snap {
			d.Notes = append(d.Notes, "pcap caplen over snaplen")
			break
		}
		if uint32(cap(buf)) < incl {
			var ok bool
			buf, ok = allocCeil(d, "pcap", int64(incl), "pcap-too-big")
			if !ok {
				break
			}
		}
		payload := buf[:incl]
		if _, err := io.ReadFull(r, payload); err != nil {
			d.Truncated = true
			d.Notes = append(d.Notes, "pcap truncated mid-record")
			break
		}
		d.PcapPackets++
		t := time.Unix(int64(sec), nanos).UTC()
		if first.IsZero() {
			first = t
		}
		last = t
		if scanned < 200 {
			pcapProtos(lt, payload, d)
			scanned++
		}
		pcapApp(lt, payload, d)
	}
	pcapFinish(d, first, last)
}

func inspectPcapng(r *bufio.Reader, d *Digest) {
	shb := make([]byte, 12)
	if _, err := io.ReadFull(r, shb); err != nil {
		return
	}
	bo := pcapngOrder(shb[8:12])
	if bo == nil {
		return
	}
	total := bo.Uint32(shb[4:8])
	if total < 12 || total > 1<<28 {
		return
	}
	if _, err := io.CopyN(io.Discard, r, int64(total)-12); err != nil {
		return
	}

	var lt, snap uint32
	resol := 6 // interface timestamp resolution, 10^-resol seconds
	haveLT := false
	var first, last time.Time
	scanned := 0
	bh := make([]byte, 8)
blocks:
	for d.PcapPackets < pcapPacketCap {
		if _, err := io.ReadFull(r, bh); err != nil {
			if err == io.ErrUnexpectedEOF {
				d.Notes = append(d.Notes, "pcapng truncated mid-block")
			}
			break
		}
		// A section header carries the byte order for its own length and every
		// block after it. bh is the block type (palindromic for the SHB), so
		// peek at the byte-order magic before trusting the length field.
		if bom, err := r.Peek(4); err == nil {
			if binary.LittleEndian.Uint32(bh[0:4]) == 0x0a0d0d0a {
				if o := pcapngOrder(bom); o != nil {
					bo = o
				}
			}
		}
		btype := bo.Uint32(bh[0:4])
		total = bo.Uint32(bh[4:8])
		if total < 12 || total > 1<<28 {
			d.Notes = append(d.Notes, "pcapng truncated mid-block")
			break
		}
		// body, padding and the trailing copy of the total length
		raw, ok := allocCeil(d, "pcap", int64(total-8), "pcap-too-big")
		if !ok {
			break
		}
		if _, err := io.ReadFull(r, raw); err != nil {
			d.Truncated = true
			d.Notes = append(d.Notes, "pcapng truncated mid-block")
			break
		}
		body := raw[:len(raw)-4]
		switch btype {
		case 0x0a0d0d0a: // SHB: a new section brings its own interface table
			// mergecap concatenates captures as sections; carrying the previous
			// link type and snaplen over would decode this section's frames as
			// the wrong protocol.
			haveLT, snap, resol, lt = false, 0, 6, 0
		case 1: // IDB
			if !haveLT && len(body) >= 2 {
				lt = uint32(bo.Uint16(body[0:2]))
				haveLT = true
				d.PcapLinkType = pcapLinkName(lt)
			}
			if len(body) >= 8 {
				snap = bo.Uint32(body[4:8])
				// if_tsresol (option 9) fixes what one timestamp tick means;
				// without it a nanosecond capture reads 1000x too long.
				resol = netcTSResol(body[8:], bo)
			}
		case 6: // EPB
			if len(body) < 20 {
				continue
			}
			us := int64(bo.Uint32(body[4:8]))<<32 | int64(bo.Uint32(body[8:12]))
			capLen := int(bo.Uint32(body[12:16]))
			// Same rule as classic pcap: caplen over the interface snaplen is
			// corrupt, so the block walk stops instead of trusting the length.
			if snap > 0 && uint32(capLen) > snap {
				d.Notes = append(d.Notes, "pcapng caplen over snaplen")
				break blocks
			}
			if capLen <= len(body)-20 && haveLT {
				d.PcapPackets++
				t := netcEpbTime(uint64(us), resol)
				if first.IsZero() {
					first = t
				}
				last = t
				pkt := body[20 : 20+capLen]
				if scanned < 200 {
					scanned++
					pcapProtos(lt, pkt, d)
				}
				pcapApp(lt, pkt, d)
			}
		case 3: // SPB: timestamp-less, interface 0
			if len(body) < 4 || !haveLT {
				continue
			}
			orig := min(int(bo.Uint32(body[0:4])), len(body)-4)
			pkt := body[4 : 4+orig]
			d.PcapPackets++
			if scanned < 200 {
				scanned++
				pcapProtos(lt, pkt, d)
			}
			pcapApp(lt, pkt, d)
		}
	}
	pcapFinish(d, first, last)
}

// pcapngOrder reads the SHB byte-order magic, nil when it is not a capture.
func pcapngOrder(bom []byte) binary.ByteOrder {
	switch string(bom) {
	case "\x1a\x2b\x3c\x4d":
		return binary.BigEndian
	case "\x4d\x3c\x2b\x1a":
		return binary.LittleEndian
	}
	return nil
}

func pcapFinish(d *Digest, first, last time.Time) {
	if d.PcapPackets == 0 {
		return
	}
	// Simple packet blocks carry no timestamp, so a capture made only of them
	// has no span to report; an invented one would be a wrong answer.
	if !first.IsZero() {
		d.PcapSpan = fmt.Sprintf("%s (+%s)", first.Format(time.RFC3339), last.Sub(first))
	}
	// the scan collects past every reported cap so the cut is visible as a note
	d.PcapProtos = capped(d, "pcap protocols", d.PcapProtos, pcapProtoCap)
	d.PcapDNS = capped(d, "pcap dns names", d.PcapDNS, pcapListCap)
	d.PcapSNI = capped(d, "pcap sni names", d.PcapSNI, pcapListCap)
	d.PcapURIs = capped(d, "pcap uris", d.PcapURIs, pcapListCap)
	if d.PcapPackets >= pcapPacketCap {
		d.Notes = append(d.Notes, fmt.Sprintf("pcap packet count capped %d", pcapPacketCap))
	}
}

// pcapProtoCap bounds the reported protocol hints.
const pcapProtoCap = 5

// pcapProtos adds the distinct L2 and L3/L4 hints of one packet.
func pcapProtos(lt uint32, pkt []byte, d *Digest) {
	// the hint set is closed, so collecting all of it stays bounded
	add := func(s string) {
		if slices.Contains(d.PcapProtos, s) {
			return
		}
		d.PcapProtos = append(d.PcapProtos, s)
	}
	off := -1
	switch lt {
	case 1: // ethernet
		if len(pkt) < 14 {
			return
		}
		et := binary.BigEndian.Uint16(pkt[12:14])
		off = 14
		for et == 0x8100 && len(pkt) >= off+4 {
			add("vlan")
			et = binary.BigEndian.Uint16(pkt[off+2 : off+4])
			off += 4
		}
		switch et {
		case 0x0800:
			add("ipv4")
		case 0x86dd:
			add("ipv6")
		case 0x0806:
			add("arp")
			return
		default:
			return
		}
	case 113: // linux-sll v1: 16-byte header, protocol at 14
		if len(pkt) < 16 {
			return
		}
		off = 16
		switch binary.BigEndian.Uint16(pkt[14:16]) {
		case 0x0800:
			add("ipv4")
		case 0x86dd:
			add("ipv6")
		case 0x0806:
			add("arp")
			return
		default:
			return
		}
	case 101, 228, 229: // raw ip, version nibble decides
		off = 0
	default:
		return
	}
	if off < 0 || off >= len(pkt) {
		return
	}
	switch pkt[off] >> 4 {
	case 4:
		if off+9 >= len(pkt) {
			return
		}
		add("ipv4")
		switch pkt[off+9] {
		case 6:
			add("tcp")
		case 17:
			add("udp")
		case 1:
			add("icmp")
		}
	case 6:
		add("ipv6")
		if off+6 < len(pkt) {
			switch pkt[off+6] {
			case 6:
				add("tcp")
			case 17:
				add("udp")
			case 1:
				add("icmp")
			}
		}
	}
}

// pcapListCap bounds each application-layer list in the digest.
const pcapListCap = 32

// pcapScanCap bounds what the scan collects before the digest truncates it, so
// a truncated list still knows how many entries it dropped.
const pcapScanCap = 512

func pcapAdd(list *[]string, s string) {
	if s == "" || len(*list) >= pcapScanCap {
		return
	}
	if slices.Contains(*list, s) {
		return
	}
	*list = append(*list, s)
}

// pcapApp scans one packet payload for DNS query names, TLS SNI and HTTP
// request targets. No stream reassembly: a name split across segments is
// missed, and a ClientHello/request starting mid-segment is not seen.
// shortcut: single-segment payloads only, upgrade to TCP stream reassembly
// when captures with segmented handshakes/requests must be resolved.
func pcapApp(lt uint32, pkt []byte, d *Digest) {
	if len(d.PcapDNS) >= pcapScanCap && len(d.PcapSNI) >= pcapScanCap && len(d.PcapURIs) >= pcapScanCap {
		return
	}
	var off int
	switch lt {
	case 1:
		if len(pkt) < 14 {
			return
		}
		et := binary.BigEndian.Uint16(pkt[12:14])
		off = 14
		for et == 0x8100 && len(pkt) >= off+4 {
			et = binary.BigEndian.Uint16(pkt[off+2 : off+4])
			off += 4
		}
		if et != 0x0800 && et != 0x86dd {
			return
		}
	case 113: // linux-sll: 16-byte cooked header, protocol in the last two bytes
		if len(pkt) < 16 {
			return
		}
		if et := binary.BigEndian.Uint16(pkt[14:16]); et != 0x0800 && et != 0x86dd {
			return
		}
		off = 16
	case 101, 228, 229:
	default:
		return
	}
	if off+20 > len(pkt) {
		return
	}
	var proto byte
	var l4 int
	switch pkt[off] >> 4 {
	case 4:
		ihl := int(pkt[off]&0x0f) * 4
		if ihl < 20 || off+ihl > len(pkt) {
			return
		}
		proto, l4 = pkt[off+9], off+ihl
	case 6:
		proto, l4 = pkt[off+6], off+40
		if l4 > len(pkt) {
			return
		}
	default:
		return
	}
	pl := pkt[l4:]
	switch proto {
	case 17:
		if len(pl) < 8 || binary.BigEndian.Uint16(pl[2:4]) != 53 {
			return
		}
		pcapDNS(pl[8:], d)
	case 6:
		if len(pl) < 20 {
			return
		}
		hlen := int(pl[12]>>4) * 4
		if hlen < 20 || hlen > len(pl) {
			return
		}
		seg := pl[hlen:]
		pcapSNI(seg, d)
		pcapHTTP(seg, d)
	}
}

// pcapDNS collects query names from a DNS message, skipping compression
// pointers instead of following them.
func pcapDNS(msg []byte, d *Digest) {
	if len(msg) < 12 {
		return
	}
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	off := 12
	for range qd {
		name, next, ok := dnsQName(msg, off)
		if !ok {
			return
		}
		pcapAdd(&d.PcapDNS, strings.ToLower(name))
		if next+4 > len(msg) {
			return
		}
		off = next + 4
	}
}

func dnsQName(msg []byte, off int) (string, int, bool) {
	var b strings.Builder
	for range 128 {
		if off >= len(msg) {
			return "", 0, false
		}
		n := int(msg[off])
		if n&0xc0 == 0xc0 {
			if off+1 >= len(msg) {
				return "", 0, false
			}
			// compressed name: stop here, QNAMEs are stored in full
			return strings.TrimSuffix(b.String(), "."), off + 2, true
		}
		if n&0xc0 != 0 {
			return "", 0, false
		}
		off++
		if n == 0 {
			return strings.TrimSuffix(b.String(), "."), off, true
		}
		if off+n > len(msg) {
			return "", 0, false
		}
		b.Write(msg[off : off+n])
		b.WriteByte('.')
		off += n
	}
	return "", 0, false
}

// pcapSNI reads the first TLS record of a segment and takes server_name from
// the ClientHello extensions.
func pcapSNI(seg []byte, d *Digest) {
	if len(seg) < 6 || seg[0] != 0x16 || seg[1] != 0x03 {
		return
	}
	recLen := min(int(binary.BigEndian.Uint16(seg[3:5])), len(seg)-5)
	hs := seg[5 : 5+recLen]
	if len(hs) < 4 || hs[0] != 1 {
		return
	}
	hl := min(int(hs[1])<<16|int(hs[2])<<8|int(hs[3]), len(hs)-4)
	body := hs[4 : 4+hl]
	if len(body) < 38 { // version + random + session id len + cipher len + compression len
		return
	}
	p := 34 + 1 + int(body[34]) // skip session id
	if p+2 > len(body) {
		return
	}
	p += 2 + int(binary.BigEndian.Uint16(body[p:p+2])) // cipher suites
	if p >= len(body) {
		return
	}
	p += 1 + int(body[p]) // compression methods
	if p+2 > len(body) {
		return
	}
	end := min(p+2+int(binary.BigEndian.Uint16(body[p:p+2])), len(body))
	for p += 2; p+4 <= end; {
		etype := binary.BigEndian.Uint16(body[p : p+2])
		elen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
		p += 4
		if p+elen > end {
			return
		}
		if etype == 0 {
			pcapSNIExt(body[p:p+elen], d)
			return
		}
		p += elen
	}
}

func pcapSNIExt(ext []byte, d *Digest) {
	if len(ext) < 5 {
		return
	}
	for p := 2; p+3 <= len(ext); {
		nt := ext[p]
		nl := int(binary.BigEndian.Uint16(ext[p+1 : p+3]))
		p += 3
		if p+nl > len(ext) {
			return
		}
		if nt == 0 {
			pcapAdd(&d.PcapSNI, strings.ToLower(string(ext[p:p+nl])))
			return
		}
		p += nl
	}
}

// pcapHTTP takes the request target of an HTTP/1.x request line.
func pcapHTTP(seg []byte, d *Digest) {
	for _, m := range [...]string{"GET ", "POST ", "HEAD ", "PUT ", "DELETE "} {
		if !bytes.HasPrefix(seg, []byte(m)) {
			continue
		}
		rest := seg[len(m):]
		i := bytes.IndexByte(rest, ' ')
		if i <= 0 || !bytes.Contains(rest[i:], []byte(" HTTP/1.")) {
			return
		}
		target := rest[:i]
		for _, c := range target {
			if c < 0x21 || c > 0x7e {
				return
			}
		}
		pcapAdd(&d.PcapURIs, string(target))
		return
	}
}
