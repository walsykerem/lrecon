package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tur7Bucket14Image is four 4 KiB blocks whose per-block Shannon entropy is
// known exactly: two uniform blocks, one block that is 4095/4096 of a single
// symbol (h = 0.004 after the 3-decimal block rounding), and a block that is a
// third distinct uniform symbol.
func tur7Bucket14Image(rare, far byte) []byte {
	b := make([]byte, 4*4096)
	for i := 4096; i < 2*4096; i++ {
		b[i] = 0xAA
	}
	b[4096+2048] = rare
	for i := 3 * 4096; i < 4*4096; i++ {
		b[i] = far
	}
	return b
}

// TestTur7Bucket14EntropyTracksBytes: inspect_byte_entropy must derive its
// numbers from the symbol distribution of the bytes it read. A byte-identical
// copy answers identically; pushing the single rare symbol back onto the
// majority symbol drops max entropy to zero; and a change that keeps the
// distribution (a different uniform symbol, or a different identity for the
// rare byte) changes nothing at all.
func TestTur7Bucket14EntropyTracksBytes(t *testing.T) {
	dir := t.TempDir()
	base := tur7Bucket14Image(0x55, 0x11)
	path := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	orig := opStatic(t, "inspect_byte_entropy", path("orig.bin", base))
	if got := opStaticNum(t, orig, "blocks"); got != 4 {
		t.Fatalf("blocks = %d, want 4: %v", got, orig)
	}
	if got := opStaticNum(t, orig, "block_bytes"); got != 4096 {
		t.Fatalf("block_bytes = %d, want 4096", got)
	}
	if got := opStaticNum(t, orig, "plain_blocks"); got != 4 {
		t.Fatalf("plain_blocks = %d, want 4 (every block is under 5 bits)", got)
	}
	if got := opStaticNum(t, orig, "packed_blocks"); got != 0 {
		t.Fatalf("packed_blocks = %d, want 0", got)
	}
	if got := orig["min"].(float64); got != 0 {
		t.Fatalf("min = %v, want 0", got)
	}
	max := orig["max"].(float64)
	// The 4095/4096 block holds 0.003282 bits/byte, rounded to 3 decimals.
	if max != 0.003 {
		t.Fatalf("max = %v, want 0.003 (one symbol in 4096)", max)
	}
	if got := orig["mean"].(float64); got != 0 {
		t.Fatalf("mean = %v, want 0 (0.004/4 rounds to 0.00)", got)
	}

	// A byte-identical copy must answer identically: the numbers are computed
	// from the bytes, not from the path, size or an earlier run.
	copyOut := opStatic(t, "inspect_byte_entropy", path("copy.bin", append([]byte(nil), base...)))
	if !reflect.DeepEqual(orig, copyOut) {
		t.Fatalf("copy = %v, want %v", copyOut, orig)
	}

	// Sensitivity: one byte in the mixed block, moved from the rare symbol to
	// the majority symbol. Entropy must go down, and only that block's value.
	sensitive := append([]byte(nil), base...)
	sensitive[4096+2048] = 0xAA
	down := opStatic(t, "inspect_byte_entropy", path("down.bin", sensitive))
	if got := down["max"].(float64); got >= max {
		t.Fatalf("max after single-byte flip = %v, want under %v (entropy must drop)", got, max)
	}
	if got := down["max"].(float64); got != 0 {
		t.Fatalf("max after single-byte flip = %v, want 0 (the mixed block is now uniform)", got)
	}
	for _, k := range []string{"blocks", "block_bytes", "min", "mean", "packed_blocks", "plain_blocks"} {
		if !reflect.DeepEqual(down[k], orig[k]) {
			t.Fatalf("%s changed on the entropy-changing flip: %v -> %v", k, orig[k], down[k])
		}
	}

	// An unrelated region: the far block keeps its 4 KiB of one symbol but the
	// symbol itself differs. Every reported field must stay identical, or the
	// answer is a hash of the content rather than an entropy measurement.
	far := tur7Bucket14Image(0x55, 0x22)
	if bytes.Equal(far, base) {
		t.Fatal("fixture bug: the unrelated-region variant is byte-identical to the original")
	}
	farOut := opStatic(t, "inspect_byte_entropy", path("far.bin", far))
	if !reflect.DeepEqual(farOut, orig) {
		t.Fatalf("unrelated-region change = %v, want %v (distribution unchanged)", farOut, orig)
	}

	// Same single byte as the sensitive flip, changed to a different symbol of
	// equal count: the distribution is untouched, so the answer must be too.
	sameCount := tur7Bucket14Image(0x77, 0x11)
	sameOut := opStatic(t, "inspect_byte_entropy", path("samecount.bin", sameCount))
	if !reflect.DeepEqual(sameOut, orig) {
		t.Fatalf("rare-symbol identity change = %v, want %v", sameOut, orig)
	}
}

// TestTur7Bucket14FirmwareRegionOffsetsFollowBytes: the carved region list must
// be the byte offsets of the container magics in the image. A flipped magic
// byte removes the region; four bytes prepended ahead of it moves the reported
// offset by exactly four, and a byte-identical copy keeps it.
func TestTur7Bucket14FirmwareRegionOffsetsFollowBytes(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	image := func(pad int) []byte {
		b := make([]byte, pad)
		b = append(b, "hsqs"...)
		return append(b, make([]byte, 4096)...)
	}

	orig := opStatic(t, "inspect_firmware_regions", write("orig.img", image(64)))
	if got := opStaticNum(t, orig, "regions"); got != 1 {
		t.Fatalf("regions = %d, want 1: %v", got, orig)
	}
	detail := orig["region_detail"].([]any)
	if len(detail) != 1 || detail[0] != "0x00000040 squashfs" {
		t.Fatalf("region_detail = %v, want [0x00000040 squashfs]", detail)
	}

	copyOut := opStatic(t, "inspect_firmware_regions", write("copy.img", image(64)))
	if !reflect.DeepEqual(orig, copyOut) {
		t.Fatalf("copy = %v, want %v", copyOut, orig)
	}

	// One flipped magic byte: no container is carved any more, so the op
	// refuses instead of reporting the region it used to find.
	broken := image(64)
	broken[64] = 'x'
	gone := opStatic(t, "inspect_firmware_regions", write("broken.img", broken))
	skip, _ := gone["skipped"].(string)
	if !strings.Contains(skip, "holds no known container magic") {
		t.Fatalf("magic flip = %v, want a refusal naming the lost container magic", gone)
	}
	if _, ok := gone["regions"]; ok {
		t.Fatalf("a carved region survived the magic flip: %v", gone)
	}

	// Four bytes prepended: the same container now starts four bytes later.
	moved := opStatic(t, "inspect_firmware_regions", write("moved.img", image(68)))
	if got := opStaticNum(t, moved, "regions"); got != 1 {
		t.Fatalf("regions after prepend = %d, want 1: %v", got, moved)
	}
	md := moved["region_detail"].([]any)
	if len(md) != 1 || md[0] != "0x00000044 squashfs" {
		t.Fatalf("region_detail after prepend = %v, want [0x00000044 squashfs]", md)
	}
}
