package main

import (
	"encoding/binary"
	"testing"
)

// bplistExtendedCountOverflowTrigger is the hostile 52-byte bplist: an array
// marker (0xDF) whose extended count is 2^61 with refSize 8. n*2*refSize wraps
// to 0 in int arithmetic, so the bounds check passes and (*bplist).ref slices
// past the buffer. The fix rejects the count in (*bplist).count.
func bplistExtendedCountOverflowTrigger() []byte {
	b := make([]byte, 52)
	copy(b, "bplist00")
	b[8] = 0xDF
	b[9] = 0x13 // int marker, 2^3 = 8 bytes follow
	binary.BigEndian.PutUint64(b[10:18], 1<<61)
	b[18] = 8
	tr := b[20:]
	tr[6] = 1 // offSize
	tr[7] = 8 // refSize
	binary.BigEndian.PutUint64(tr[8:16], 1)
	binary.BigEndian.PutUint64(tr[24:32], 18)
	return b
}

func TestKeyedArchiveExtendedCountOverflow(t *testing.T) {
	p := opStaticFile(t, "overflow.bplist", bplistExtendedCountOverflowTrigger())
	if _, err := runOp("inspect_keyed_archive", p); err == nil {
		t.Fatal("want an error, not a silent pass")
	}
	// The same file must not reach Probe's bundleExecutable either: it reads
	// the same .app/Contents/Info.plist through (*bplist).entry.
	p2, err := openBplist(bplistExtendedCountOverflowTrigger())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := p2.entry(p2.top); err == nil {
		t.Fatal("entry should reject the overflowing extended count")
	}
}
