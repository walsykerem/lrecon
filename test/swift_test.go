package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

func le32(vals ...uint32) []byte {
	b := make([]byte, 4*len(vals))
	for i, v := range vals {
		binary.LittleEndian.PutUint32(b[4*i:], v)
	}
	return b
}

func TestSwiftTargets(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		base   uint64
		mask   uint32
		want   []uint64
		nulls  int
		wantOK bool
	}{
		{
			// type metadata: low 2 bits are TypeReferenceKind, cleared first
			name: "type tags masked", data: le32(0x51, 0x52, 0xFFFFFFF0), base: 0x1000, mask: 3,
			want: []uint64{0x1050, 0x1054, 0xFF8}, wantOK: true,
		},
		{
			// protocol descriptors: low bit is indirectness, cleared first
			name: "protocol bit masked", data: le32(0x1, 0x11), base: 0x2000, mask: 1,
			want: []uint64{0x2000, 0x2014}, wantOK: true,
		},
		{
			name: "zero is null", data: le32(0, 0x10), base: 0x3000, mask: 3,
			want: []uint64{0x3004 + 0x10}, nulls: 1, wantOK: true,
		},
		{
			name: "negative offset", data: le32(0xFFFFFFFC), base: 0x4000, mask: 0,
			want: []uint64{0x3FFC}, wantOK: true,
		},
		{
			name: "misaligned size refused", data: make([]byte, 6), base: 0x5000, mask: 3,
			wantOK: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, nulls, ok := swiftTargets(c.data, c.base, c.mask)
			if ok != c.wantOK {
				t.Fatalf("ok = %v, want %v", ok, c.wantOK)
			}
			if !c.wantOK {
				return
			}
			if nulls != c.nulls {
				t.Errorf("nulls = %d, want %d", nulls, c.nulls)
			}
			if len(got) != len(c.want) {
				t.Fatalf("targets = %#x, want %#x", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("targets[%d] = %#x, want %#x", i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestSwiftReflectionVersion(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		want   uint16
		wantOK bool
	}{
		{"layout 3", []byte{0x03, 0x00}, 3, true},
		{"truncated", []byte{0x03}, 0, false},
		{"absent", nil, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := swiftReflectionVersion(c.data)
			if ok != c.wantOK || (ok && got != c.want) {
				t.Fatalf("got (%d, %v), want (%d, %v)", got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestSwiftEntryCount(t *testing.T) {
	cases := []struct {
		name   string
		size   int
		n      int
		want   int
		wantOK bool
	}{
		{"fieldmd records", 16, 32, 2, true},
		{"relative pointer records", 4, 12, 3, true},
		{"empty", 16, 0, 0, true},
		{"cut mid record", 16, 40, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := swiftEntryCount(make([]byte, c.n), c.size)
			if ok != c.wantOK || (ok && got != c.want) {
				t.Fatalf("got (%d, %v), want (%d, %v)", got, ok, c.want, c.wantOK)
			}
		})
	}
}

func TestSwiftSectionName(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"__swift5_types", "types", true},
		{"__swift5_types2", "types2", true},
		{"__swift5_proto", "proto", true},
		{"swift5_protocol_conformances", "proto", true},
		{".swift5_type_metadata", "types", true},
		{"swift5_fieldmd", "fieldmd", true},
		{"__TEXT", "", false},
		{"__const", "", false},
	}
	for _, c := range cases {
		got, ok := swiftSectionName(c.raw)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%q = (%q, %v), want (%q, %v)", c.raw, got, ok, c.want, c.ok)
		}
	}
}

// A file with no Swift metadata must fall through untouched: a post reader may
// not change Kind and must not claim anything it did not see. The tracked fat
// fixture is universal, so this also covers the fat path.
func TestSwiftSilentOnNonSwiftBinary(t *testing.T) {
	path := fixtureFat
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("%s unreadable: %v", path, err)
	}
	head := make([]byte, 512)
	n, _ := f.Read(head)
	f.Close()
	head = head[:n]
	st, err := os.Stat(path)
	if err != nil {
		t.Skipf("%s unreadable: %v", path, err)
	}
	if !fatMachOOK(head, st.Size()) {
		t.Skipf("%s is not a fat Mach-O", path)
	}

	d := Digest{Path: path, Kind: "macho", Format: "universal"}
	dispatchPost(path, head, st.Size(), &d)
	if d.Kind != "macho" {
		t.Errorf("Kind = %q, want macho", d.Kind)
	}
	if len(d.Capabilities) != 0 {
		t.Errorf("Capabilities = %v, want none", d.Capabilities)
	}
	// Only the Swift reader's own reasons are the contract here: the fat fixture
	// is a Go binary, and some unrelated reader (producer records) may add its
	// own skip without the Swift post reader having claimed anything.
	for _, s := range d.Skipped {
		if strings.Contains(s.Reason, "swift") {
			t.Errorf("Swift reader claimed something on a non-Swift binary: %+v", s)
		}
	}
}

// tinySwiftMachO builds the smallest 64-bit Mach-O this reader understands: one
// __TEXT segment holding a 4-byte __swift5_types section.
func tinySwiftMachO() []byte {
	const hdr, segCmd, sect = 32, 72, 80
	cmdSize := segCmd + sect // a segment command owns its section headers
	dataOff := hdr + cmdSize
	b := make([]byte, dataOff+4)
	binary.LittleEndian.PutUint32(b[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c)       // cpu arm64
	binary.LittleEndian.PutUint32(b[12:], 2)               // MH_EXECUTE
	binary.LittleEndian.PutUint32(b[16:], 1)               // ncmds
	binary.LittleEndian.PutUint32(b[20:], uint32(cmdSize)) // sizeofcmds
	seg := b[hdr:]
	binary.LittleEndian.PutUint32(seg[0:], 0x19) // LC_SEGMENT_64
	binary.LittleEndian.PutUint32(seg[4:], uint32(cmdSize))
	copy(seg[8:24], "__TEXT")
	binary.LittleEndian.PutUint64(seg[24:], 0x1000) // vmaddr
	binary.LittleEndian.PutUint64(seg[32:], 0x1000) // vmsize
	binary.LittleEndian.PutUint64(seg[48:], uint64(len(b)))
	binary.LittleEndian.PutUint32(seg[56:], 7) // maxprot
	binary.LittleEndian.PutUint32(seg[60:], 5) // initprot
	binary.LittleEndian.PutUint32(seg[64:], 1) // nsects
	sc := seg[segCmd:]
	copy(sc[0:16], "__swift5_types")
	copy(sc[16:32], "__TEXT")
	binary.LittleEndian.PutUint64(sc[32:], 0x1000) // addr
	binary.LittleEndian.PutUint64(sc[40:], 4)      // size
	binary.LittleEndian.PutUint32(sc[48:], uint32(dataOff))
	copy(b[dataOff:], le32(0x51))
	return b
}

// fatWithBadSlice wraps good in a fat header whose first slice is zeroed: the
// whole-file parse refuses it, and only per-slice parsing can still see good.
func fatWithBadSlice(good []byte) []byte {
	const arch = 20
	buf := make([]byte, 0x200+len(good))
	binary.BigEndian.PutUint32(buf[0:], 0xcafebabe)
	binary.BigEndian.PutUint32(buf[4:], 2)
	putArch := func(i int, cpu, off, size uint32) {
		e := buf[8+i*arch:]
		binary.BigEndian.PutUint32(e[0:], cpu)
		binary.BigEndian.PutUint32(e[8:], off)
		binary.BigEndian.PutUint32(e[12:], size)
		binary.BigEndian.PutUint32(e[16:], 12)
	}
	putArch(0, 0x01000007, 0x100, 0x40) // x86_64 slice without a Mach-O magic
	putArch(1, 0x0100000c, 0x200, uint32(len(good)))
	copy(buf[0x200:], good)
	return buf
}

func TestSwiftFatSliceSelection(t *testing.T) {
	buf := fatWithBadSlice(tinySwiftMachO())
	if !fatMachOOK(buf[:512], int64(len(buf))) {
		t.Fatal("prefilter rejected the synthetic fat header")
	}
	imgs, bad := machoSwiftImages(bytes.NewReader(buf))
	if len(imgs) != 1 || bad != 1 {
		t.Fatalf("imgs = %d, bad = %d, want 1 readable and 1 unreadable slice", len(imgs), bad)
	}
	d := Digest{Kind: "macho", Format: "universal"}
	reportSwift(imgs, bad, &d)

	var types, sliceSkip bool
	for _, c := range d.Capabilities {
		types = types || c == "swift:types=1"
	}
	for _, s := range d.Skipped {
		sliceSkip = sliceSkip || s.Reason == swiftSliceUnreadable
	}
	if !types {
		t.Errorf("Capabilities = %v, want swift:types=1 from the readable slice", d.Capabilities)
	}
	if !sliceSkip {
		t.Errorf("Skipped = %v, want %s for the truncated slice", d.Skipped, swiftSliceUnreadable)
	}
	if d.Coverage.Unknown < 1 {
		t.Errorf("Coverage.Unknown = %d, want >= 1", d.Coverage.Unknown)
	}
}

func TestSwiftMisalignedSectionRefused(t *testing.T) {
	// a section body cut mid-record is refused by name, not counted
	d := Digest{}
	img := swiftImage{
		sections: []swiftSec{{name: "types", addr: 0x1000, data: make([]byte, 6)}},
		version:  []byte{0x03, 0x00},
	}
	reportSwift([]swiftImage{img}, 0, &d)
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != swiftSizeMisaligned {
		t.Fatalf("Skipped = %v, want one %s", d.Skipped, swiftSizeMisaligned)
	}
	for _, c := range d.Capabilities {
		if c == "swift:types=1" {
			t.Errorf("misaligned section was counted: %v", d.Capabilities)
		}
	}
}
