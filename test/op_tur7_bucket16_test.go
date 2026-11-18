package main

// Tur 7 bucket 16: prove inspect_pcap_client against a byte-level decode of a
// real capture that lives in the repo's env tree. Nothing here calls the
// package's own capture reader: the pcap records, Ethernet/IPv4/TCP/UDP, the
// HTTP request head and the TLS ClientHello are all parsed below, and every
// field the op reports is compared with what those bytes actually say.

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// t7b16PcapRel is the real capture under env/, resolved from the package dir
// so the test survives the repo moving.
const t7b16PcapRel = "../env/probe20/fixtures/native/probe.pcap"

type t7b16HTTP struct {
	frame                    int
	src, dst                 string
	sport, dport             int
	method, target, host     string
	agent, accept, lang, enc string
	order                    []string
}

type t7b16TLS struct {
	frame        int
	src, dst     string
	sport, dport int
	sni          string
	alpn         []string
	version      uint16
	ja3, sum     string
}

type t7b16Capture struct {
	format  string
	link    uint32
	snaplen uint32
	packets int
	dns     []string
	http    []t7b16HTTP
	tls     []t7b16TLS
}

// t7b16Grease drops the 0x?a?a reserved values JA3 excludes.
func t7b16Grease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func t7b16Join(vals []int, sep string) string {
	out := make([]string, len(vals))
	for i, v := range vals {
		out[i] = fmt.Sprint(v)
	}
	return strings.Join(out, sep)
}

func t7b16IPv4(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// t7b16DNSName reads an uncompressed QNAME and returns it with the offset past
// the closing root label.
func t7b16DNSName(msg []byte, off int) (string, int, error) {
	var b strings.Builder
	for {
		if off >= len(msg) {
			return "", 0, fmt.Errorf("dns name runs past the message")
		}
		n := int(msg[off])
		off++
		if n == 0 {
			return strings.TrimSuffix(b.String(), "."), off, nil
		}
		if off+n > len(msg) {
			return "", 0, fmt.Errorf("dns label %d at %d runs past the message", n, off)
		}
		b.Write(msg[off : off+n])
		b.WriteByte('.')
		off += n
	}
}

// t7b16HTTPHead parses an HTTP/1.x request head, keeping the header order.
func t7b16HTTPHead(seg []byte) *t7b16HTTP {
	lines := bytes.Split(seg, []byte("\r\n"))
	if len(lines) < 2 {
		return nil
	}
	parts := strings.Split(string(lines[0]), " ")
	if len(parts) != 3 || !strings.HasPrefix(parts[2], "HTTP/1.") {
		return nil
	}
	h := &t7b16HTTP{method: parts[0], target: parts[1]}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			break
		}
		k, v, ok := strings.Cut(string(line), ":")
		if !ok {
			return nil
		}
		v = strings.TrimSpace(v)
		h.order = append(h.order, k)
		switch k {
		case "Host":
			h.host = v
		case "User-Agent":
			h.agent = v
		case "Accept":
			h.accept = v
		case "Accept-Language":
			h.lang = v
		case "Accept-Encoding":
			h.enc = v
		}
	}
	return h
}

// t7b16ClientHello walks the handshake by hand: version, session id, cipher
// suites, compression methods, every extension, then the SNI name, the ALPN
// list, the supported groups and the ec point formats, and asserts the JA3
// string and MD5 the op reports can only come from those bytes.
func t7b16ClientHello(seg []byte) *t7b16TLS {
	if len(seg) < 6 || seg[0] != 0x16 || seg[1] != 0x03 || seg[5] != 0x01 {
		return nil
	}
	rec := seg[5:]
	hl := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if 4+hl > len(rec) {
		return nil
	}
	body := rec[4 : 4+hl]
	if len(body) < 35 {
		return nil
	}
	h := &t7b16TLS{version: binary.BigEndian.Uint16(body[:2])}
	p := 34
	sidLen := int(body[p])
	p += 1 + sidLen
	csLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	if p+csLen > len(body) || csLen%2 != 0 {
		return nil
	}
	var ciphers []int
	for i := p; i < p+csLen; i += 2 {
		if v := binary.BigEndian.Uint16(body[i:]); !t7b16Grease(v) {
			ciphers = append(ciphers, int(v))
		}
	}
	p += csLen
	compLen := int(body[p])
	p += 1 + compLen
	if p+2 > len(body) {
		return nil
	}
	extLen := int(binary.BigEndian.Uint16(body[p:]))
	p += 2
	end := p + extLen
	if end > len(body) {
		return nil
	}
	var exts, groups, points []int
	for p+4 <= end {
		et := binary.BigEndian.Uint16(body[p:])
		el := int(binary.BigEndian.Uint16(body[p+2:]))
		p += 4
		if p+el > end {
			return nil
		}
		ext := body[p : p+el]
		if !t7b16Grease(et) {
			exts = append(exts, int(et))
		}
		switch et {
		case 0: // server_name: list length, then type+length+host
			if len(ext) >= 5 {
				n := int(binary.BigEndian.Uint16(ext[3:]))
				if 5+n <= len(ext) {
					h.sni = string(ext[5 : 5+n])
				}
			}
		case 16: // ALPN: list length, then one length-prefixed protocol per entry
			if len(ext) >= 2 {
				al := int(binary.BigEndian.Uint16(ext[:2]))
				for q := 2; q+1 <= len(ext) && q < 2+al; {
					n := int(ext[q])
					q++
					if q+n > len(ext) {
						break
					}
					h.alpn = append(h.alpn, string(ext[q:q+n]))
					q += n
				}
			}
		case 10: // supported_groups
			if len(ext) >= 2 {
				n := int(binary.BigEndian.Uint16(ext[:2]))
				for q := 2; q+2 <= len(ext) && q < 2+n; q += 2 {
					if g := binary.BigEndian.Uint16(ext[q:]); !t7b16Grease(g) {
						groups = append(groups, int(g))
					}
				}
			}
		case 11: // ec_point_formats
			if len(ext) >= 1 {
				for _, b := range ext[1 : 1+int(ext[0])] {
					points = append(points, int(b))
				}
			}
		}
		p += el
	}
	h.ja3 = t7b16Join([]int{int(h.version)}, ",") + "," +
		t7b16Join(ciphers, "-") + "," + t7b16Join(exts, "-") + "," +
		t7b16Join(groups, "-") + "," + t7b16Join(points, "-")
	sum := md5.Sum([]byte(h.ja3))
	h.sum = hex.EncodeToString(sum[:])
	return h
}

// t7b16ParseCapture walks classic pcap records and decodes each frame's
// Ethernet/IPv4 payload. It fails on any header it cannot account for, so a
// packet the tool counts but these bytes do not hold is a test error.
func t7b16ParseCapture(raw []byte) (t7b16Capture, error) {
	var d t7b16Capture
	if len(raw) < 24 || !bytes.Equal(raw[:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) {
		return d, fmt.Errorf("capture is not a little-endian microsecond pcap")
	}
	d.format = "pcap"
	d.snaplen = binary.LittleEndian.Uint32(raw[16:20])
	d.link = binary.LittleEndian.Uint32(raw[20:24])
	off := 24
	for off < len(raw) {
		if off+16 > len(raw) {
			return d, fmt.Errorf("record header at %d is truncated", off)
		}
		incl := int(binary.LittleEndian.Uint32(raw[off+8:]))
		off += 16
		if incl > int(d.snaplen) {
			return d, fmt.Errorf("record caplen %d over snaplen %d", incl, d.snaplen)
		}
		if off+incl > len(raw) {
			return d, fmt.Errorf("record payload %d at %d is truncated", incl, off)
		}
		pkt := raw[off : off+incl]
		off += incl
		d.packets++
		if err := t7b16Frame(pkt, d.packets, &d); err != nil {
			return d, fmt.Errorf("frame %d: %w", d.packets, err)
		}
	}
	return d, nil
}

func t7b16Frame(pkt []byte, n int, d *t7b16Capture) error {
	if d.link != 1 {
		return fmt.Errorf("only Ethernet is decoded here, link type %d", d.link)
	}
	if len(pkt) < 14 {
		return fmt.Errorf("frame shorter than an Ethernet header")
	}
	if et := binary.BigEndian.Uint16(pkt[12:]); et != 0x0800 {
		return fmt.Errorf("ethertype %#04x is not IPv4", et)
	}
	ip := pkt[14:]
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return fmt.Errorf("no IPv4 header")
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ip) {
		return fmt.Errorf("IPv4 IHL %d past the packet", ihl)
	}
	l4 := ip[ihl:]
	switch ip[9] {
	case 17:
		if len(l4) < 8 || binary.BigEndian.Uint16(l4[2:]) != 53 {
			return nil
		}
		msg := l4[8:]
		if len(msg) < 12 || binary.BigEndian.Uint16(msg[4:]) == 0 {
			return fmt.Errorf("DNS message without a question")
		}
		name, _, err := t7b16DNSName(msg, 12)
		if err != nil {
			return err
		}
		d.dns = append(d.dns, strings.ToLower(name))
	case 6:
		if len(l4) < 20 {
			return fmt.Errorf("TCP header truncated")
		}
		seg := l4[int(l4[12]>>4)*4:]
		if h := t7b16HTTPHead(seg); h != nil {
			h.frame, h.src, h.dst = n, t7b16IPv4(ip[12:16]), t7b16IPv4(ip[16:20])
			h.sport, h.dport = int(binary.BigEndian.Uint16(l4[0:])), int(binary.BigEndian.Uint16(l4[2:]))
			d.http = append(d.http, *h)
			return nil
		}
		if h := t7b16ClientHello(seg); h != nil {
			h.frame, h.src, h.dst = n, t7b16IPv4(ip[12:16]), t7b16IPv4(ip[16:20])
			h.sport, h.dport = int(binary.BigEndian.Uint16(l4[0:])), int(binary.BigEndian.Uint16(l4[2:]))
			d.tls = append(d.tls, *h)
		}
	}
	return nil
}

func t7b16Eq(t *testing.T, field string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %#v, want %#v (independent byte decode)", field, got, want)
	}
}

func TestTur7Bucket16PcapClient(t *testing.T) {
	path, err := filepath.Abs(t7b16PcapRel)
	if err != nil {
		t.Fatalf("fixture path: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	want, err := t7b16ParseCapture(raw)
	if err != nil {
		t.Fatalf("independent decode: %v", err)
	}
	if want.packets != 3 || len(want.http) != 1 || len(want.tls) != 1 {
		t.Fatalf("independent decode found %d packets, %d http, %d tls", want.packets, len(want.http), len(want.tls))
	}

	res, err := runOp("inspect_pcap_client", path)
	if err != nil {
		t.Fatalf("inspect_pcap_client: %v", err)
	}
	out := res.(map[string]any)

	// Capture level: five header values, all read from the global header.
	cap := out["capture"].(netcCapInfo)
	t7b16Eq(t, "capture.format", cap.Format, want.format)
	t7b16Eq(t, "capture.link_type", cap.Link, want.link)
	t7b16Eq(t, "capture.link_layer", cap.LinkName, "ethernet")
	t7b16Eq(t, "capture.snaplen", cap.Snaplen, want.snaplen)
	t7b16Eq(t, "capture.packets", cap.Packets, want.packets)
	t7b16Eq(t, "capture.decoded", cap.Decoded, want.packets)
	t7b16Eq(t, "capture.packet_cap_hit", cap.CapHit, false)
	t7b16Eq(t, "capture.file_truncated", cap.Truncated, false)
	// The first packet is a DNS query, so the two client rows start at frames
	// 2 and 3; a row invented for frame 1 would break these two values.
	t7b16Eq(t, "dns names", want.dns, []string{"probe.example.com"})

	httpRows := out["http_clients"].([]*netcHTTPClient)
	if len(httpRows) != len(want.http) {
		t.Fatalf("http_clients rows = %d, want %d", len(httpRows), len(want.http))
	}
	wh := want.http[0]
	hr := httpRows[0]
	t7b16Eq(t, "http.first_frame", hr.Frame, wh.frame)
	t7b16Eq(t, "http.src", hr.Src, wh.src)
	t7b16Eq(t, "http.src_port", hr.SrcPort, wh.sport)
	t7b16Eq(t, "http.dst", hr.Dst, wh.dst)
	t7b16Eq(t, "http.dst_port", hr.DstPort, wh.dport)
	t7b16Eq(t, "http.host", hr.Host, wh.host)
	t7b16Eq(t, "http.method", hr.Method, wh.method)
	t7b16Eq(t, "http.target", hr.Target, wh.target)
	t7b16Eq(t, "http.user_agent", hr.UserAgent, wh.agent)
	t7b16Eq(t, "http.accept", hr.Accept, wh.accept)
	t7b16Eq(t, "http.accept_language", hr.AcceptLang, wh.lang)
	t7b16Eq(t, "http.accept_encoding", hr.AcceptEnc, wh.enc)
	t7b16Eq(t, "http.header_order", hr.HeaderOrder, wh.order)
	// probe-agent/1.0 matches no known stack prefix, so the label is "other".
	t7b16Eq(t, "http.family", hr.Family, "other")
	t7b16Eq(t, "http.requests", hr.Count, 1)

	tlsRows := out["tls_clients"].([]*netcTLSClient)
	if len(tlsRows) != len(want.tls) {
		t.Fatalf("tls_clients rows = %d, want %d", len(tlsRows), len(want.tls))
	}
	wt := want.tls[0]
	tr := tlsRows[0]
	t7b16Eq(t, "tls.first_frame", tr.Frame, wt.frame)
	t7b16Eq(t, "tls.src", tr.Src, wt.src)
	t7b16Eq(t, "tls.src_port", tr.SrcPort, wt.sport)
	t7b16Eq(t, "tls.dst", tr.Dst, wt.dst)
	t7b16Eq(t, "tls.dst_port", tr.DstPort, wt.dport)
	t7b16Eq(t, "tls.sni", tr.SNI, wt.sni)
	t7b16Eq(t, "tls.alpn", tr.ALPN, wt.alpn)
	t7b16Eq(t, "tls.version", tr.Version, wt.version)
	t7b16Eq(t, "tls.ja3", tr.JA3, wt.ja3)
	t7b16Eq(t, "tls.ja3_md5", tr.JA3MD5, wt.sum)
	// No HTTP request, and the random/ciphers/extensions do not fingerprint a
	// known stack, so the family is the empty marker, not a guess.
	t7b16Eq(t, "tls.family", tr.Family, "-")
	t7b16Eq(t, "tls.hellos", tr.Count, 1)
}
