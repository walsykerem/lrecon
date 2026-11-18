package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic .mv bytes only: the header and the two tables this reader walks are
// small enough to write by hand, so no fixture binary is carried.

type moveDirEntry struct {
	kind  byte
	off   uint32
	count uint32
}

func moveLE16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func moveLE32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

func moveULEB(s string) []byte {
	var b []byte
	n := len(s)
	for n >= 0x80 {
		b = append(b, byte(n)|0x80)
		n >>= 7
	}
	b = append(b, byte(n))
	return append(b, s...)
}

func moveAssemble(magic []byte, version uint32, dir []moveDirEntry, body []byte) []byte {
	b := append([]byte{}, magic...)
	b = append(b, moveLE32(version)...)
	b = append(b, byte(len(dir)))
	for _, e := range dir {
		b = append(b, e.kind)
		b = append(b, moveLE32(e.off)...)
		b = append(b, moveLE32(e.count)...)
	}
	return append(b, body...)
}

// moveSample lays a module-handle table followed by the identifiers table, the
// layout a real writer produces for a file with two tables.
func moveSample(version uint32, handleCount, identCount uint32, nameIdx uint16, names ...string) []byte {
	handleOff := uint32(moveHeaderSize + 2*moveTableEntrySize)
	identOff := handleOff + moveModuleHandleLen
	body := append(moveLE16(0), moveLE16(nameIdx)...)
	for _, n := range names {
		body = append(body, moveULEB(n)...)
	}
	return moveAssemble(moveMagic, version, []moveDirEntry{
		{moveTableModuleHandles, handleOff, handleCount},
		{moveTableIdentifiers, identOff, identCount},
	}, body)
}

func moveProbe(t *testing.T, b []byte) Digest {
	t.Helper()
	p := filepath.Join(t.TempDir(), "module.mv")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return d
}

func moveCap(d Digest, want string) bool {
	return strings.Contains(strings.Join(d.Capabilities, " "), want)
}

func moveSkip(d Digest) string {
	if len(d.Skipped) == 0 {
		return ""
	}
	return d.Skipped[0].Reason
}

func TestMoveVersion5Module(t *testing.T) {
	d := moveProbe(t, moveSample(5, 1, 2, 1, "ignored", "counter"))
	if d.Kind != "move" || d.Format != "move" {
		t.Fatalf("kind/format = %q/%q, want move/move", d.Kind, d.Format)
	}
	if d.Mod != "counter" {
		t.Fatalf("module = %q, want counter", d.Mod)
	}
	for _, want := range []string{"move:magic=a11ceb0b", "move:version=5", "move:module=counter"} {
		if !moveCap(d, want) {
			t.Fatalf("capabilities = %v, want %s", d.Capabilities, want)
		}
	}
	if d.Coverage == nil || d.Coverage.Parsed != 2 || d.Coverage.Skipped != 0 || d.Coverage.Unknown != 0 {
		t.Fatalf("coverage = %+v, want 2 parsed, 0 skipped, 0 unknown", d.Coverage)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %v, want none", d.Skipped)
	}
}

func TestMoveVersion6Module(t *testing.T) {
	d := moveProbe(t, moveSample(6, 1, 1, 0, "coin"))
	if d.Kind != "move" || d.Mod != "coin" {
		t.Fatalf("kind/module = %q/%q, want move/coin", d.Kind, d.Mod)
	}
	if !moveCap(d, "move:version=6") {
		t.Fatalf("capabilities = %v, want version 6", d.Capabilities)
	}
	if len(d.Skipped) != 0 || d.Coverage == nil || d.Coverage.Parsed != 2 {
		t.Fatalf("skipped/coverage = %v/%+v, want none/2 parsed", d.Skipped, d.Coverage)
	}
}

func TestMoveVersion4Refused(t *testing.T) {
	d := moveProbe(t, moveSample(4, 1, 1, 0, "counter"))
	if d.Kind != "move" {
		t.Fatalf("kind = %q, want move", d.Kind)
	}
	if !moveCap(d, "move:magic=a11ceb0b") || !moveCap(d, "move:version=4") {
		t.Fatalf("capabilities = %v, want magic and version 4 reported", d.Capabilities)
	}
	if moveSkip(d) != "move-version-unsupported" {
		t.Fatalf("skipped = %v, want move-version-unsupported", d.Skipped)
	}
	if d.Mod != "" {
		t.Fatalf("module = %q, want empty", d.Mod)
	}
	if d.Coverage == nil || d.Coverage.Skipped != 1 || d.Coverage.Parsed != 0 {
		t.Fatalf("coverage = %+v, want 0 parsed, 1 skipped", d.Coverage)
	}
}

func TestMoveTableOffsetPastEOF(t *testing.T) {
	b := moveSample(6, 1, 1, 0, "counter")
	binary.LittleEndian.PutUint32(b[moveHeaderSize+1:moveHeaderSize+5], uint32(len(b)+64))
	d := moveProbe(t, b)
	if d.Kind != "move" {
		t.Fatalf("kind = %q, want move", d.Kind)
	}
	if moveSkip(d) != "move-table-truncated" {
		t.Fatalf("skipped = %v, want move-table-truncated", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Skipped != 1 || d.Coverage.Parsed != 0 {
		t.Fatalf("coverage = %+v, want 0 parsed, 1 skipped", d.Coverage)
	}
}

func TestMoveHugeCounts(t *testing.T) {
	// A count is a u32: 0xffffffff must cost no allocation and no loop.
	d := moveProbe(t, moveSample(6, 0xffffffff, 0xffffffff, 0, "counter"))
	if d.Mod != "counter" {
		t.Fatalf("module = %q, want counter", d.Mod)
	}
	if len(d.Skipped) != 0 || d.Coverage == nil || d.Coverage.Parsed != 2 {
		t.Fatalf("skipped/coverage = %v/%+v, want none/2 parsed", d.Skipped, d.Coverage)
	}
}

func TestMoveMagicReversed(t *testing.T) {
	b := moveSample(6, 1, 1, 0, "counter")
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0] // 0b eb 1c a1
	d := moveProbe(t, b)
	if d.Kind == "move" || d.Format == "move" {
		t.Fatalf("kind/format = %q/%q, want the byte-swapped magic refused", d.Kind, d.Format)
	}
	if d.Mod != "" {
		t.Fatalf("module = %q, want empty", d.Mod)
	}
}

func TestMoveNoHandleTable(t *testing.T) {
	b := moveSample(6, 1, 1, 0, "counter")
	b[moveHeaderSize] = 0x2 // struct handles, no module-handle table
	d := moveProbe(t, b)
	if moveSkip(d) != "move-table-unverified" {
		t.Fatalf("skipped = %v, want move-table-unverified", d.Skipped)
	}
	if d.Mod != "" {
		t.Fatalf("module = %q, want empty", d.Mod)
	}
}

func TestMoveHeaderTruncated(t *testing.T) {
	d := moveProbe(t, moveSample(6, 1, 1, 0, "counter")[:6])
	if moveSkip(d) != "move-header-truncated" {
		t.Fatalf("skipped = %v, want move-header-truncated", d.Skipped)
	}
	if !moveCap(d, "move:magic=a11ceb0b") {
		t.Fatalf("capabilities = %v, want the magic reported", d.Capabilities)
	}
}
