package main

// Tests for the capture and dylib items (final.md 30, 31, 35, 43). Every
// fixture is real bytes written to t.TempDir(): a classic pcap, a pcapng, an
// Apple .ips, and thin/fat Mach-O images carrying LC_LOAD_DYLIB/LC_RPATH.

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- capture fixtures ---

func netcTestEth(proto byte, l4 []byte) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0, 0x11, 0x22, 0x33, 0x44, 0x55})
	copy(eth[6:12], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	return append(append(eth, ip...), l4...)
}

func netcTestTCP(sport, dport uint16, flags byte, payload []byte) []byte {
	h := make([]byte, 20)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint32(h[4:], 1)
	binary.BigEndian.PutUint32(h[8:], 2)
	h[12] = 5 << 4
	h[13] = flags
	binary.BigEndian.PutUint16(h[14:], 65535)
	return append(h, payload...)
}

func netcTestUDP(sport, dport uint16, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], sport)
	binary.BigEndian.PutUint16(h[2:], dport)
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

func netcTestDNSQuery(id uint16, name string, qtype uint16) []byte {
	m := make([]byte, 12)
	binary.BigEndian.PutUint16(m[0:], id)
	m[2] = 0x01 // standard query, recursion desired
	binary.BigEndian.PutUint16(m[4:], 1)
	for label := range strings.SplitSeq(name, ".") {
		m = append(m, byte(len(label)))
		m = append(m, label...)
	}
	m = append(m, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return m
}

const netcTestHTTP = "GET /api/items?x=1 HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\nAccept-Encoding: gzip\r\n\r\n"

func netcTestHello(host string, ciphers []uint16, groups []uint16, points []byte, alpn []string) []byte {
	var ext []byte
	entry := append([]byte{0}, byte(len(host)>>8), byte(len(host)))
	entry = append(entry, host...)
	sni := append([]byte{byte(len(entry) >> 8), byte(len(entry))}, entry...)
	ext = append(ext, 0, 0, byte(len(sni)>>8), byte(len(sni)))
	ext = append(ext, sni...)
	if len(alpn) > 0 {
		var list []byte
		for _, p := range alpn {
			list = append(list, byte(len(p)))
			list = append(list, p...)
		}
		al := append([]byte{byte(len(list) >> 8), byte(len(list))}, list...)
		ext = append(ext, 0, 16, byte(len(al)>>8), byte(len(al)))
		ext = append(ext, al...)
	}
	var g []byte
	for _, x := range groups {
		g = append(g, byte(x>>8), byte(x))
	}
	gd := append([]byte{byte(len(g) >> 8), byte(len(g))}, g...)
	ext = append(ext, 0, 10, byte(len(gd)>>8), byte(len(gd)))
	ext = append(ext, gd...)
	pd := append([]byte{byte(len(points))}, points...)
	ext = append(ext, 0, 11, byte(len(pd)>>8), byte(len(pd)))
	ext = append(ext, pd...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // empty session id
	cs := []byte{byte(len(ciphers) * 2 >> 8), byte(len(ciphers) * 2)}
	for _, c := range ciphers {
		cs = append(cs, byte(c>>8), byte(c))
	}
	body = append(body, cs...)
	body = append(body, 1, 0) // one compression method: null
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// netcTestClassicPcap writes microsecond little-endian pcap with four frames.
func netcTestClassicPcap(t *testing.T) string {
	t.Helper()
	hdr := make([]byte, 24)
	copy(hdr[0:4], []byte{0xd4, 0xc3, 0xb2, 0xa1}) // microsecond, little endian
	binary.LittleEndian.PutUint16(hdr[4:], 2)
	binary.LittleEndian.PutUint16(hdr[6:], 4)
	binary.LittleEndian.PutUint32(hdr[16:], 65535)
	binary.LittleEndian.PutUint32(hdr[20:], 1) // ethernet
	var b bytes.Buffer
	b.Write(hdr)
	frames := [][]byte{
		netcTestEth(6, netcTestTCP(49152, 80, 0x02, nil)),
		netcTestEth(17, netcTestUDP(5353, 53, netcTestDNSQuery(0x1234, "example.com", 1))),
		netcTestEth(6, netcTestTCP(49152, 80, 0x18, []byte(netcTestHTTP))),
		netcTestEth(6, netcTestTCP(49152, 443, 0x18, netcTestHello("api.example.com", []uint16{0x1301}, []uint16{29}, []byte{0}, []string{"h2"}))),
	}
	for i, f := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], uint32(1_700_000_000+i))
		binary.LittleEndian.PutUint32(rec[4:], 500_000)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(f)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(f)))
		b.Write(rec)
		b.Write(f)
	}
	path := filepath.Join(t.TempDir(), "classic.pcap")
	if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func netcTestPcapngBlock(btype uint32, body []byte) []byte {
	blen := 12 + len(body)
	pad := (4 - len(body)%4) % 4
	blen += pad
	out := make([]byte, 0, blen)
	out = binary.LittleEndian.AppendUint32(out, btype)
	out = binary.LittleEndian.AppendUint32(out, uint32(blen))
	out = append(out, body...)
	out = append(out, make([]byte, pad)...)
	out = binary.LittleEndian.AppendUint32(out, uint32(blen))
	return out
}

// netcTestPcapng writes SHB + IDB + two EPBs holding a DNS query and an HTTP
// request. The second block's timestamp is 1.5 s on the microsecond clock.
func netcTestPcapng(t *testing.T) string {
	t.Helper()
	shb := []byte{0x4d, 0x3c, 0x2b, 0x1a} // little-endian byte-order magic
	shb = append(shb, 1, 0, 0, 0)         // version 1.0
	shb = append(shb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff)
	idb := []byte{1, 0, 0, 0, 0xff, 0xff, 0, 0} // ethernet, snaplen 65535
	epb := func(ts uint32, f []byte) []byte {
		body := make([]byte, 0, 20+len(f))
		body = binary.LittleEndian.AppendUint32(body, 0)
		body = binary.LittleEndian.AppendUint32(body, 0)
		body = binary.LittleEndian.AppendUint32(body, ts)
		body = binary.LittleEndian.AppendUint32(body, uint32(len(f)))
		body = binary.LittleEndian.AppendUint32(body, uint32(len(f)))
		return append(body, f...)
	}
	var b []byte
	b = append(b, netcTestPcapngBlock(0x0a0d0d0a, shb)...)
	b = append(b, netcTestPcapngBlock(1, idb)...)
	b = append(b, netcTestPcapngBlock(6, epb(1_000_000, netcTestEth(17, netcTestUDP(5353, 53, netcTestDNSQuery(0xbeef, "ng.example.com", 28)))))...)
	b = append(b, netcTestPcapngBlock(6, epb(1_500_000, netcTestEth(6, netcTestTCP(50000, 8080, 0x18, []byte("POST /v1/save HTTP/1.1\r\nHost: ng.example.com\r\nUser-Agent: Go-http-client/2.0\r\n\r\n")))))...)
	path := filepath.Join(t.TempDir(), "ng.pcapng")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// --- Mach-O fixtures ---

func netcTestMachO(cpu uint32, dylibs map[uint32][]string) []byte {
	var cmds []byte
	add := func(cmd uint32, name string) {
		n := len(name) + 1
		size := 24 + n
		size = (size + 3) &^ 3
		c := make([]byte, size)
		binary.LittleEndian.PutUint32(c[0:], cmd)
		binary.LittleEndian.PutUint32(c[4:], uint32(size))
		binary.LittleEndian.PutUint32(c[8:], 24)
		copy(c[24:], name)
		cmds = append(cmds, c...)
	}
	for _, cmd := range []uint32{lcLoadDylib, lcLoadWeakDylib, lcReexportDylib, lcUpwardDylib, lcIDDylib, lcRpathCMD} {
		for _, name := range dylibs[cmd] {
			add(cmd, name)
		}
	}
	hdr := make([]byte, 32)
	binary.LittleEndian.PutUint32(hdr[0:], 0xfeedfacf) // MH_MAGIC_64
	binary.LittleEndian.PutUint32(hdr[4:], cpu)
	binary.LittleEndian.PutUint32(hdr[12:], 6) // MH_DYLIB
	binary.LittleEndian.PutUint32(hdr[16:], uint32(len(dylibsToCmds(dylibs))))
	binary.LittleEndian.PutUint32(hdr[20:], uint32(len(cmds)))
	return append(hdr, cmds...)
}

// dylibsToCmds counts only commands that made it into the image.
func dylibsToCmds(dylibs map[uint32][]string) []string {
	var out []string
	for _, names := range dylibs {
		out = append(out, names...)
	}
	return out
}

func netcTestFat(t *testing.T, slices [][]byte) []byte {
	t.Helper()
	n := len(slices)
	out := make([]byte, 8)
	binary.BigEndian.PutUint32(out[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(out[4:], uint32(n))
	offsets := make([]int, n)
	pos := 8 + n*20
	for i := range slices {
		pos = (pos + 4095) &^ 4095
		offsets[i] = pos
		pos += len(slices[i])
	}
	for i := range slices {
		e := make([]byte, 20)
		binary.BigEndian.PutUint32(e[0:], binary.LittleEndian.Uint32(slices[i][4:]))
		binary.BigEndian.PutUint32(e[8:], uint32(offsets[i]))
		binary.BigEndian.PutUint32(e[12:], uint32(len(slices[i])))
		binary.BigEndian.PutUint32(e[16:], 12)
		out = append(out, e...)
	}
	buf := make([]byte, pos)
	copy(buf, out)
	for i := range slices {
		copy(buf[offsets[i]:], slices[i])
	}
	return buf
}

func netcWrite(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// --- tests ---

func TestNetCPacketFieldsClassic(t *testing.T) {
	path := netcTestClassicPcap(t)
	res, err := runOp("inspect_packet_fields", path)
	if err != nil {
		t.Fatalf("inspect_packet_fields: %v", err)
	}
	out := res.(map[string]any)
	capture := out["capture"].(netcCapInfo)
	if capture.Format != "pcap" || capture.LinkName != "ethernet" || capture.Packets != 4 || capture.Decoded != 4 {
		t.Fatalf("capture = %+v, want pcap/ethernet 4 packets decoded", capture)
	}
	frames := out["frames"].([]netcPacket)
	if len(frames) != 4 {
		t.Fatalf("decoded %d frames, want 4", len(frames))
	}

	syn := frames[0]
	if syn.TCP == nil || syn.TCP.SrcPort != 49152 || syn.TCP.DstPort != 80 || syn.TCP.Flags != "S" {
		t.Fatalf("frame 1 tcp = %+v, want 49152->80 SYN", syn.TCP)
	}
	if syn.IP == nil || syn.IP.Src != "10.0.0.1" || syn.IP.Dst != "93.184.216.34" || syn.IP.TTL != 64 || syn.IP.Protocol != "tcp" {
		t.Fatalf("frame 1 ip = %+v", syn.IP)
	}
	if syn.Payload == nil || syn.Payload.Offset != 54 || syn.Payload.Length != 0 {
		t.Fatalf("frame 1 payload = %+v, want offset 54 length 0", syn.Payload)
	}

	dns := frames[1]
	if dns.UDP == nil || dns.UDP.SrcPort != 5353 || dns.UDP.DstPort != 53 {
		t.Fatalf("frame 2 udp = %+v", dns.UDP)
	}
	if dns.Payload == nil || dns.Payload.Offset != 42 {
		t.Fatalf("frame 2 payload offset = %+v, want 42 (14 eth + 20 ip + 8 udp)", dns.Payload)
	}
	if dns.DNS == nil || len(dns.DNS.Questions) != 1 {
		t.Fatalf("frame 2 dns = %+v", dns.DNS)
	}
	if q := dns.DNS.Questions[0]; q.Name != "example.com" || q.Type != 1 || q.Class != 1 || dns.DNS.ID != 0x1234 {
		t.Fatalf("frame 2 question = %+v id %#x", q, dns.DNS.ID)
	}

	http := frames[2]
	if http.HTTP == nil {
		t.Fatal("frame 3 carries no HTTP request head")
	}
	if http.HTTP.Method != "GET" || http.HTTP.Target != "/api/items?x=1" || http.HTTP.Version != "HTTP/1.1" {
		t.Fatalf("frame 3 request = %+v", http.HTTP)
	}
	if got := strings.Join(http.HTTP.HeaderOrder, ","); got != "Host,User-Agent,Accept,Accept-Encoding" {
		t.Fatalf("frame 3 header order = %q", got)
	}
	if http.Payload.Offset != 54 {
		t.Fatalf("frame 3 payload offset = %d, want 54", http.Payload.Offset)
	}

	tls := frames[3]
	if tls.TLS == nil || tls.TLS.SNI != "api.example.com" || len(tls.TLS.ALPN) != 1 || tls.TLS.ALPN[0] != "h2" {
		t.Fatalf("frame 4 tls = %+v", tls.TLS)
	}
	if tls.TLS.JA3 != "771,4865,0-16-10-11,29,0" {
		t.Fatalf("frame 4 ja3 = %q", tls.TLS.JA3)
	}
	sum := md5.Sum([]byte(tls.TLS.JA3))
	if tls.TLS.JA3MD5 != hex.EncodeToString(sum[:]) {
		t.Fatalf("frame 4 ja3 md5 = %q, want md5 of the ja3 string", tls.TLS.JA3MD5)
	}
	if app := out["app"].(map[string]int); app["dns"] != 1 || app["http"] != 1 || app["tls"] != 1 {
		t.Fatalf("app counts = %v", app)
	}
}

func TestNetCPcapngBlocks(t *testing.T) {
	path := netcTestPcapng(t)
	res, err := runOp("inspect_packet_fields", path)
	if err != nil {
		t.Fatalf("inspect_packet_fields(pcapng): %v", err)
	}
	out := res.(map[string]any)
	capture := out["capture"].(netcCapInfo)
	if capture.Format != "pcapng" || capture.Link != 1 || capture.LinkName != "ethernet" || capture.Packets != 2 {
		t.Fatalf("capture = %+v, want pcapng/ethernet 2 packets", capture)
	}
	frames := out["frames"].([]netcPacket)
	if frames[0].DNS == nil || frames[0].DNS.Questions[0].Name != "ng.example.com" || frames[0].DNS.Questions[0].Type != 28 {
		t.Fatalf("epb 1 dns = %+v", frames[0].DNS)
	}
	ts, err := time.Parse(time.RFC3339Nano, frames[1].Time)
	if err != nil || ts.UnixNano() != 1_500_000_000 {
		t.Fatalf("epb 2 time = %q (%v), want 1.5s", frames[1].Time, err)
	}
	if frames[1].HTTP == nil || frames[1].HTTP.Target != "/v1/save" || frames[1].TCP.DstPort != 8080 {
		t.Fatalf("epb 2 http = %+v tcp %+v", frames[1].HTTP, frames[1].TCP)
	}
}

func TestNetCPcapClient(t *testing.T) {
	path := netcTestClassicPcap(t)
	res, err := runOp("inspect_pcap_client", path)
	if err != nil {
		t.Fatalf("inspect_pcap_client: %v", err)
	}
	out := res.(map[string]any)
	httpRows := out["http_clients"].([]*netcHTTPClient)
	if len(httpRows) != 1 {
		t.Fatalf("http rows = %d, want 1", len(httpRows))
	}
	row := httpRows[0]
	if row.UserAgent != "curl/8.4.0" || row.Host != "api.example.com" || row.Target != "/api/items?x=1" ||
		row.Family != "curl" || row.Count != 1 || row.DstPort != 80 {
		t.Fatalf("http row = %+v", row)
	}
	tlsRows := out["tls_clients"].([]*netcTLSClient)
	if len(tlsRows) != 1 {
		t.Fatalf("tls rows = %d, want 1", len(tlsRows))
	}
	if tl := tlsRows[0]; tl.SNI != "api.example.com" || tl.JA3MD5 == "" || tl.DstPort != 443 || tl.Version != 771 {
		t.Fatalf("tls row = %+v", tl)
	}
}

func TestNetCCaptureErrors(t *testing.T) {
	bad := netcTestClassicPcap(t)
	b, err := os.ReadFile(bad)
	if err != nil {
		t.Fatal(err)
	}
	// caplen past snaplen: the reader must refuse, not read past the file
	over := append([]byte(nil), b[:24]...)
	over = append(over, b[24:]...)
	binary.LittleEndian.PutUint32(over[16:], 10) // snaplen 10, records claim more
	if _, err := runOp("inspect_packet_fields", netcWrite(t, "over.pcap", over)); err == nil || !strings.Contains(err.Error(), "snaplen") {
		t.Fatalf("caplen over snaplen error = %v", err)
	}
	// declared body past EOF
	short := b[:len(b)-3]
	if _, err := runOp("inspect_packet_fields", netcWrite(t, "short.pcap", short)); err == nil || !strings.Contains(err.Error(), "only") {
		t.Fatalf("truncated record error = %v", err)
	}
	if _, err := runOp("inspect_packet_fields", netcWrite(t, "not.pcap", []byte("definitely not a capture"))); err == nil || !strings.Contains(err.Error(), "neither a pcap nor a pcapng") {
		t.Fatalf("non-capture error = %v", err)
	}
	empty := netcWrite(t, "empty.pcap", b[:24])
	if _, err := runOp("inspect_packet_fields", empty); err == nil || !strings.Contains(err.Error(), "no packets") {
		t.Fatalf("empty capture error = %v", err)
	}
}

func TestNetCRecordedCrash(t *testing.T) {
	header := `{"app_name":"LreconApp","bundleID":"com.example.lrecon","app_version":"1.2.3","build_version":"45","os_version":"macOS 14.0 (23A344)","timestamp":"2024-01-02 03:04:05.00 +0300","incident_id":"ABC-123","bug_type":"309"}`
	body := `{"exception":{"type":"EXC_BAD_ACCESS","signal":"SIGSEGV","codes":"0x0000000000000001, 0x0000000000000000"},"faultingThread":0,"threads":[{"triggered":true,"id":42,"queue":"com.apple.main-thread","frames":[{"imageIndex":0,"imageOffset":4660,"symbol":"-[App crash]","symbolLocation":16,"sourceFile":"App.m","sourceLine":7},{"imageIndex":1,"imageOffset":1234,"symbol":"start"}]},{"triggered":false,"id":43,"frames":[]}],"usedImages":[{"name":"LreconApp","path":"/Applications/Lrecon.app/Contents/MacOS/LreconApp","base":4294967296,"uuid":"AAAA","arch":"arm64"},{"name":"libsystem_kernel.dylib","base":2147483648}]}`
	path := netcWrite(t, "crash.ips", []byte(header+"\n"+body+"\n"))
	res, err := runOp("inspect_recorded_crash", path)
	if err != nil {
		t.Fatalf("inspect_recorded_crash: %v", err)
	}
	out := res.(map[string]any)
	if out["app"] != "LreconApp" || out["bundle_id"] != "com.example.lrecon" || out["incident_id"] != "ABC-123" {
		t.Fatalf("header fields = app %v bundle %v incident %v", out["app"], out["bundle_id"], out["incident_id"])
	}
	exc := out["exception"].(netcCrashException)
	if exc.Type != "EXC_BAD_ACCESS" || exc.Signal != "SIGSEGV" || !strings.HasPrefix(exc.Codes, "0x0000000000000001") {
		t.Fatalf("exception = %+v", exc)
	}
	if out["faulting_thread"] != 0 || out["triggered_thread"] != 0 {
		t.Fatalf("faulting/triggered = %v/%v", out["faulting_thread"], out["triggered_thread"])
	}
	threads := out["threads"].([]netcCrashThread)
	if len(threads) != 2 || !threads[0].Triggered || threads[0].Queue != "com.apple.main-thread" || threads[0].ID != 42 {
		t.Fatalf("threads = %+v", threads)
	}
	f := threads[0].Frames[0]
	if f.ImageIndex != 0 || f.ImageOffset != 4660 || f.Offset != "0x1234" || f.Symbol != "-[App crash]" ||
		f.SymbolLoc != 16 || f.Source != "App.m" || f.SourceLine != 7 || f.Image != "LreconApp" {
		t.Fatalf("frame 0 = %+v", f)
	}
	if f.Address != "0x100001234" {
		t.Fatalf("frame 0 address = %q, want base+offset", f.Address)
	}
	if second := threads[0].Frames[1]; second.Image != "libsystem_kernel.dylib" || second.Address != "0x800004d2" {
		t.Fatalf("frame 1 = %+v", second)
	}

	for _, c := range []struct{ name, body string }{
		{"one.ips", header},
		{"bad.ips", header + "\n{\"exception\":"},
	} {
		p := netcWrite(t, c.name, []byte(c.body))
		if _, err := runOp("inspect_recorded_crash", p); err == nil {
			t.Fatalf("%s accepted, want an error", c.name)
		}
	}
}

func TestNetCDylibResolutionThin(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "LreconHost")
	img := netcTestMachO(0x0100000c, map[uint32][]string{
		lcRpathCMD:      {"@executable_path/Frameworks"},
		lcLoadDylib:     {"@rpath/libfoo.dylib", "@loader_path/libbar.dylib"},
		lcLoadWeakDylib: {"@rpath/libweak.dylib"},
		lcIDDylib:       {"@rpath/libLreconHost.dylib"},
	})
	if err := os.WriteFile(bin, img, 0o644); err != nil {
		t.Fatal(err)
	}
	fw := filepath.Join(dir, "Frameworks")
	if err := os.MkdirAll(fw, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fw, "libfoo.dylib"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	abs := filepath.Join(dir, "libabs.dylib")
	if err := os.WriteFile(abs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := runOp("trace_dylib_resolution", bin)
	if err != nil {
		t.Fatalf("trace_dylib_resolution: %v", err)
	}
	out := res.(map[string]any)
	slices := out["slices"].([]netcDylibSlice)
	if len(slices) != 1 || slices[0].Arch != "arm64" {
		t.Fatalf("slices = %+v", slices)
	}
	s := slices[0]
	if len(s.Rpaths) != 1 || s.Rpaths[0] != "@executable_path/Frameworks" {
		t.Fatalf("rpaths = %v", s.Rpaths)
	}
	byName := map[string]netcDylib{}
	for _, d := range s.Dylibs {
		byName[d.InstallName] = d
	}
	foo := byName["@rpath/libfoo.dylib"]
	if foo.Kind != "load" || len(foo.Candidates) != 1 || foo.Candidates[0] != filepath.Join(fw, "libfoo.dylib") || !foo.Exists {
		t.Fatalf("@rpath/libfoo.dylib = %+v", foo)
	}
	bar := byName["@loader_path/libbar.dylib"]
	if bar.Exists || bar.Resolved != "" || bar.Candidates[0] != filepath.Join(dir, "libbar.dylib") {
		t.Fatalf("@loader_path/libbar.dylib = %+v", bar)
	}
	if weak := byName["@rpath/libweak.dylib"]; weak.Kind != "weak" || weak.Exists {
		t.Fatalf("@rpath/libweak.dylib = %+v", weak)
	}
	if id := byName["@rpath/libLreconHost.dylib"]; id.Kind != "id" {
		t.Fatalf("LC_ID_DYLIB row = %+v", id)
	}
	// LC_ID_DYLIB is this image's own name, not a dependency to resolve.
	if s.Present != 1 || s.Missing != 2 {
		t.Fatalf("present/missing = %d/%d, want 1/2", s.Present, s.Missing)
	}

	// an absolute install name is one candidate and is never rewritten
	img2 := netcTestMachO(0x0100000c, map[uint32][]string{lcLoadDylib: {abs}})
	res2, err := runOp("trace_dylib_resolution", netcWrite(t, "abs", img2))
	if err != nil {
		t.Fatalf("absolute dylib: %v", err)
	}
	d := res2.(map[string]any)["slices"].([]netcDylibSlice)[0].Dylibs[0]
	if len(d.Candidates) != 1 || d.Candidates[0] != abs || d.Resolved != abs {
		t.Fatalf("absolute dylib = %+v", d)
	}
}

func TestNetCDylibResolutionFat(t *testing.T) {
	arm := netcTestMachO(0x0100000c, map[uint32][]string{lcLoadDylib: {"/usr/lib/libarm.dylib"}})
	x86 := netcTestMachO(0x01000007, map[uint32][]string{lcLoadDylib: {"/usr/lib/libx86.dylib"}})
	path := netcWrite(t, "fat.dylib", netcTestFat(t, [][]byte{arm, x86}))
	res, err := runOp("trace_dylib_resolution", path)
	if err != nil {
		t.Fatalf("trace_dylib_resolution(fat): %v", err)
	}
	slices := res.(map[string]any)["slices"].([]netcDylibSlice)
	if len(slices) != 2 || slices[0].Arch != "arm64" || slices[1].Arch != "x86-64" {
		t.Fatalf("fat slices = %+v", slices)
	}
	if slices[0].Dylibs[0].InstallName != "/usr/lib/libarm.dylib" || slices[1].Dylibs[0].InstallName != "/usr/lib/libx86.dylib" {
		t.Fatalf("fat dylibs = %+v / %+v", slices[0].Dylibs, slices[1].Dylibs)
	}
	if slices[0].Dylibs[0].Exists {
		t.Fatal("/usr/lib/libarm.dylib does not exist, but the op says it does")
	}
	if _, err := runOp("trace_dylib_resolution", netcWrite(t, "junk", []byte("not mach-o at all"))); err == nil || !strings.Contains(err.Error(), "not Mach-O") {
		t.Fatalf("non-Mach-O error = %v", err)
	}
}
