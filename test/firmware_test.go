package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFirmwareKind(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{"nil", "", ""},
		{"short", "hsq", ""},
		{"squashfs", "hsqs\x00\x00\x00\x00", "squashfs"},
		{"squashfs-be", "sqsh\x00\x00\x00\x00", "squashfs-be"},
		{"ubi", "UBI#\x01\x00\x00\x00", "ubi"},
		{"cramfs", "\x45\x3d\xcd\x28\x00\x00\x00\x00", "cramfs"},
		{"trx", "HDR0\x00\x00\x00\x00", "trx"},
		{"uimage", "\x27\x05\x19\x56\x00\x00\x00\x00", "uimage"},
		{"dtb", "\xd0\x0d\xfe\xed\x00\x00\x00\x00", "dtb"},
		{"jffs2", "\x19\x85\x00\x00\x00\x00\x00\x00", "jffs2"},
		{"jffs2-swapped", "\x85\x19\x00\x00\x00\x00\x00\x00", "jffs2"},
		{"gzip", "\x1f\x8b\x08\x00\x00\x00\x00\x00", "gzip"},
		{"xz", "\xfd\x37\x7a\x58\x5a\x00\x00\x00", "xz"},
		{"jffs2-midfile", "abc\x19\x85", ""}, // short magics are offset-0 only
		{"text", "hello firmware", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := firmwareKind([]byte(c.head)); got != c.want {
				t.Fatalf("firmwareKind = %q, want %q", got, c.want)
			}
		})
	}
}

// gzip/xz wrap the real image: Probe names the outer container and tells the
// agent to decompress before trusting anything inside.
func TestFirmwareWrapped(t *testing.T) {
	cases := []struct{ name, head, kind, note string }{
		{"gzip", "\x1f\x8b\x08\x00", "gzip", "gzip: outer compression, decompress the wrapper first"},
		{"xz", "\xfd\x37\x7a\x58\x5a\x00", "xz", "xz: outer compression, decompress the wrapper first"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), c.name+".bin")
			img := append([]byte(c.head), make([]byte, 256)...)
			if err := os.WriteFile(p, img, 0o644); err != nil {
				t.Fatal(err)
			}
			d, err := Probe(p)
			if err != nil {
				t.Fatal(err)
			}
			if d.Kind != "firmware" || d.Format != c.kind || d.FirmwareKind != c.kind {
				t.Fatalf("kind/format/firmware_kind = %q/%q/%q, want firmware/%q/%q",
					d.Kind, d.Format, d.FirmwareKind, c.kind, c.kind)
			}
			if !notesContain(d, c.note) {
				t.Fatalf("notes = %v, want %q", d.Notes, c.note)
			}
		})
	}
}

// A squashfs image with an embedded TRX plus a DTB must report every container
// at its real offset, not just the header of the file.
func TestFirmwareCarve(t *testing.T) {
	img := make([]byte, 512)
	copy(img[0:], "hsqs")
	copy(img[128:], "HDR0")
	copy(img[400:], "\xd0\x0d\xfe\xed")
	p := filepath.Join(t.TempDir(), "fw.bin")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "firmware" || d.Format != "squashfs" {
		t.Fatalf("kind/format = %q/%q, want firmware/squashfs", d.Kind, d.Format)
	}
	if d.FirmwareEnd != 3 {
		t.Fatalf("firmware_parts = %d, want 3 (%v)", d.FirmwareEnd, d.FirmwareParts)
	}
	want := []string{"0x00000000 squashfs", "0x00000080 trx", "0x00000190 dtb"}
	if strings.Join(d.FirmwareParts, "|") != strings.Join(want, "|") {
		t.Fatalf("parts = %v, want %v", d.FirmwareParts, want)
	}
	out := d.Text()
	for _, line := range append([]string{"kind: firmware", "format: squashfs", "firmware_parts: 3"}, want...) {
		if !strings.Contains(out, line) {
			t.Fatalf("Text() missing %q:\n%s", line, out)
		}
	}
}

// TestFirmwareHitCapKeepsEarliest: when one magic overflows the cap, the list
// still keeps the earliest offsets overall rather than the first type scanned.
func TestFirmwareHitCapKeepsEarliest(t *testing.T) {
	img := make([]byte, 2048)
	copy(img, "HDR0") // trx at offset 0, scanned after squashfs
	for i := 0; i <= maxFirmwareParts; i++ {
		copy(img[1024+8*i:], "hsqs")
	}
	p := filepath.Join(t.TempDir(), "cap.bin")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.FirmwareParts) != maxFirmwareParts || d.FirmwareParts[0] != "0x00000000 trx" {
		t.Fatalf("parts = %d first %q, want %d starting at the offset-0 trx",
			len(d.FirmwareParts), d.FirmwareParts[0], maxFirmwareParts)
	}
	if !notesContain(d, "firmware: parts capped at 40") {
		t.Fatalf("notes = %v, want cap note", d.Notes)
	}
}

// TestFirmwareDeepNoteHandoff checks the image handoff note names the next
// capability (decompress entries, find boot/config partitions) and no tool.
func TestFirmwareDeepNoteHandoff(t *testing.T) {
	cases := []struct{ name, head string }{
		{"gzip", "\x1f\x8b\x08\x00"},
		{"squashfs", "hsqs\x00\x00\x00\x00"},
		{"trx", "HDR0\x00\x00\x00\x00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			img := append([]byte(c.head), make([]byte, 256)...)
			p := filepath.Join(t.TempDir(), c.name+".bin")
			if err := os.WriteFile(p, img, 0o644); err != nil {
				t.Fatal(err)
			}
			d, err := Probe(p)
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if d.Kind != "firmware" {
				t.Fatalf("kind = %q, want firmware", d.Kind)
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
			for _, want := range []string{"decompress", "boot and config partitions"} {
				if !strings.Contains(deep, want) {
					t.Fatalf("deep note = %q, want it to mention %q", deep, want)
				}
			}
			pcapFwAssertNoToolNames(t, d)
		})
	}
}

// TestFirmwareDTBDeepNote checks a flattened device tree gets node-tree
// guidance instead of rootfs advice: an FDT is a property table, so nothing
// inside it is compressed or carved.
func TestFirmwareDTBDeepNote(t *testing.T) {
	img := append([]byte("\xd0\x0d\xfe\xed"), make([]byte, 256)...)
	p := filepath.Join(t.TempDir(), "board.dtb")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "firmware" {
		t.Fatalf("kind = %q, want firmware", d.Kind)
	}
	var deep string
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "deep: ") {
			deep = n
		}
	}
	if !strings.Contains(deep, "device tree") {
		t.Fatalf("deep note = %q, want it to name the device tree", deep)
	}
	for _, unwanted := range []string{"rootfs container entries", "decompress each entry"} {
		if strings.Contains(deep, unwanted) {
			t.Fatalf("deep note = %q, must not claim %q", deep, unwanted)
		}
	}
	pcapFwAssertNoToolNames(t, d)
}
