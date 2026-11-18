package main

import (
	"debug/pe"
	"encoding/binary"
	"testing"
)

// These tests pin the lane-09 fixes: each one fails on the version before the
// fix, so a later refactor cannot quietly bring the bug back.

// TestLane09DalvikInsnWidths covers the opcode widths metaBInvokes walks with:
// jumbo const-string, filled-new-array, fill-array-data and the switch payloads
// are 3 units, monitor-enter/exit are 1.
func TestLane09DalvikInsnWidths(t *testing.T) {
	cases := []struct {
		op   byte
		want int
	}{
		{0x1b, 3}, // const-string/jumbo
		{0x24, 3}, // filled-new-array
		{0x25, 3}, // filled-new-array/range
		{0x26, 3}, // fill-array-data
		{0x2b, 3}, // packed-switch
		{0x2c, 3}, // sparse-switch
		{0x1d, 1}, // monitor-enter
		{0x1e, 1}, // monitor-exit
		{0x1a, 2}, // const-string
		{0x22, 2}, // new-instance
		{0x29, 2}, // goto/16
	}
	for _, c := range cases {
		if got := metaBInsnLen(c.op); got != c.want {
			t.Errorf("metaBInsnLen(%#02x) = %d, want %d", c.op, got, c.want)
		}
	}
}

// lane09CLRPE is buildCLIPE with a caller-supplied metadata root, so an
// uncompressed "#-" table stream can be handed to metaCLI.
func lane09CLRPE(t *testing.T, meta []byte) string {
	t.Helper()
	img := make([]byte, 0x600)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x40)

	peOff := 0x40
	copy(img[peOff:], "PE\x00\x00")
	coff := img[peOff+4:]
	binary.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], 240)
	binary.LittleEndian.PutUint16(coff[18:], 0x0022)

	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], 0x2000)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 3)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	dd := 112 + pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR*8
	binary.LittleEndian.PutUint32(opt[dd:], 0x1000)
	binary.LittleEndian.PutUint32(opt[dd+4:], 0x48)

	sec := img[0x148:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], uint32(0x200+len(meta)))
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x400)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)

	cli := img[0x200:]
	binary.LittleEndian.PutUint32(cli[0:], 0x48)
	binary.LittleEndian.PutUint16(cli[4:], 2)
	binary.LittleEndian.PutUint16(cli[6:], 5)
	binary.LittleEndian.PutUint32(cli[8:], 0x1200)
	binary.LittleEndian.PutUint32(cli[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(cli[16:], 1)
	binary.LittleEndian.PutUint32(cli[20:], 0x06000001)
	copy(img[0x400:], meta)
	return writeTemp(t, "lane09-managed.exe", img)
}

// TestLane09MetaCLIUncompressedStream pins the "#-" fallback: on the version
// before the fix every uncompressed metadata stream was refused with
// "table stream missing".
func TestLane09MetaCLIUncompressedStream(t *testing.T) {
	heap := newTestHeap()
	heap.add("kernel32.dll")
	meta := tablesMeta(1, 1, "#-", buildTableStream(0, nil, nil), heap.b)
	facts, err := metaCLI(lane09CLRPE(t, meta))
	if err != nil {
		t.Fatalf("metaCLI with a #- stream: %v", err)
	}
	if facts.Rows != 0 || len(facts.Types) != 0 {
		t.Fatalf("facts = %+v, want an empty table set", facts)
	}
}

// TestLane09MetaSymbolAtMiss pins the "not found" delta: it used to come back
// as int64(1<<63), which JSON-encodes as -9223372036854775808.
func TestLane09MetaSymbolAtMiss(t *testing.T) {
	name, delta := metaSymbolAt("/bin/ls", 1)
	if name != "" {
		t.Fatalf("metaSymbolAt at address 1 = %q, want no symbol", name)
	}
	if delta != 0 {
		t.Fatalf("delta = %d, want 0 on a miss", delta)
	}
}

// lane09IPv4ICMPFrame wraps an ICMP body in a bare ethernet+ipv4 frame.
func lane09IPv4ICMPFrame(tail []byte) []byte {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	ip := make([]byte, 20)
	ip[0] = 0x45
	total := 20 + len(tail)
	ip[2], ip[3] = byte(total>>8), byte(total)
	ip[9] = 1
	return append(append(eth, ip...), tail...)
}

// TestLane09ShortICMPFrame pins the short-frame path: a frame that ends inside
// the 4-byte ICMP header used to report a negative payload length.
func TestLane09ShortICMPFrame(t *testing.T) {
	p := netcDecode(netcFrame{n: 1, link: 1, data: lane09IPv4ICMPFrame([]byte{8, 0})})
	if p.Payload != nil {
		t.Fatalf("short icmp frame produced payload %+v, want nil", *p.Payload)
	}
	if p.ICMP != nil || p.Note == "" {
		t.Fatalf("icmp=%+v note=%q, want nil icmp and a note", p.ICMP, p.Note)
	}
	q := netcDecode(netcFrame{n: 2, link: 1, data: lane09IPv4ICMPFrame([]byte{8, 0, 0, 0, 0, 0, 0, 0})})
	if q.ICMP == nil || q.ICMP.Type != 8 || q.Payload == nil || q.Payload.Length != 4 {
		t.Fatalf("full icmp frame = %+v payload %+v", q.ICMP, q.Payload)
	}
}

// TestLane09IPv6FragmentAtFrameEnd pins the bound check: a fragment header that
// starts exactly at the end of the frame used to panic with an index out of
// range instead of returning a note.
func TestLane09IPv6FragmentAtFrameEnd(t *testing.T) {
	eth := make([]byte, 14)
	eth[12], eth[13] = 0x86, 0xdd
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[6] = 44 // fragment header is next, but the frame ends here
	p := netcDecode(netcFrame{n: 3, link: 1, data: append(eth, ip...)})
	if p.IP == nil {
		t.Fatalf("packet = %+v, want the ipv6 header parsed", p)
	}
	if p.Note != "frame ends inside the ipv6 fragment header" {
		t.Fatalf("note = %q, want the fragment-header bound note", p.Note)
	}
}
