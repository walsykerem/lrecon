package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"sort"
)

// shortMagics: wrappers shorter than 4 bytes, matched at offset 0 only. Kept
// out of fwMagics because a raw byte scan would match them thousands of times.
// ponytail: jffs2 is recognised as an outer image only; its nodes inside a dump
// are not carved. Add a node walker when a real jffs2 dump shows up.
// ponytail: gzip/xz are general wrappers, so a .tar.gz is named firmware here;
// reclassifying them touches op_inspect_firmware_regions.go and 6+ test sites.
var shortMagics = []struct {
	magic []byte
	name  string
}{
	{[]byte("\x19\x85"), "jffs2"},              // 16-bit big-endian superblock magic
	{[]byte("\x85\x19"), "jffs2"},              // byte-swapped
	{[]byte("\x1f\x8b\x08"), "gzip"},           // deflate member
	{[]byte("\xfd\x37\x7a\x58\x5a\x00"), "xz"}, // xz stream
}

// fwMagics: strong container signatures carved anywhere in the image.
var fwMagics = []struct {
	magic []byte
	name  string
}{
	{[]byte("hsqs"), "squashfs"},    // little-endian superblock
	{[]byte("sqsh"), "squashfs-be"}, // big-endian superblock
	{[]byte("UBI#"), "ubi"},
	{[]byte("\x45\x3d\xcd\x28"), "cramfs"},
	{[]byte("\x28\xcd\x3d\x45"), "cramfs-be"},
	{[]byte("HDR0"), "trx"},
	{[]byte("\x27\x05\x19\x56"), "uimage"},
	{[]byte("\xd0\x0d\xfe\xed"), "dtb"},
}

const (
	maxFirmwareScan  = 64 << 20
	maxFirmwareParts = 40
)

// firmwareKind names a firmware/rootfs container from its magic, "" otherwise.
// Signature scan only: never extract or execute anything here.
func firmwareKind(head []byte) string {
	if len(head) < 2 {
		return ""
	}
	for _, m := range shortMagics {
		if bytes.HasPrefix(head, m.magic) {
			return m.name
		}
	}
	for _, m := range fwMagics {
		if bytes.HasPrefix(head, m.magic) {
			return m.name
		}
	}
	return ""
}

// fwHit is one carved container: byte offset and type.
type fwHit struct {
	off  int
	name string
}

// firmwareHits carves known container magics out of an in-memory image, sorted
// by offset. The bool reports a cap hit, so the caller can say the list is cut.
func firmwareHits(buf []byte) ([]fwHit, bool) {
	var hits []fwHit
	capped := false
	for _, m := range fwMagics {
		n := 0
		for off := 0; off < len(buf); {
			i := bytes.Index(buf[off:], m.magic)
			if i < 0 {
				break
			}
			at := off + i
			off = at + 1
			// The earliest N hits of one magic are enough to decide the
			// earliest N overall, so per-magic memory stays bounded.
			if n >= maxFirmwareParts {
				capped = true
				break
			}
			hits = append(hits, fwHit{at, m.name})
			n++
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].off < hits[j].off })
	if len(hits) > maxFirmwareParts {
		hits = hits[:maxFirmwareParts]
		capped = true
	}
	return hits, capped
}

// firmwarePartLines renders carved hits in the digest's detail format.
func firmwarePartLines(buf []byte) []string {
	hits, _ := firmwareHits(buf)
	parts := make([]string, 0, len(hits))
	for _, h := range hits {
		parts = append(parts, fmt.Sprintf("0x%08x %s", h.off, h.name))
	}
	return parts
}

// inspectFirmware carves known container magics out of the image and reports
// offset + type per hit, sorted by offset.
func inspectFirmware(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		d.Notes = append(d.Notes, "firmware: "+err.Error())
		return
	}
	defer f.Close()
	// Size the scan buffer from the file, not from the 64 MiB ceiling: a small
	// image must not cost 64 MiB of heap just to be carved.
	size := int64(maxFirmwareScan)
	if fi, err := f.Stat(); err == nil && fi.Size() < size {
		size = fi.Size()
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF {
		d.Truncated = true
	}
	buf = buf[:n]

	d.FirmwareKind = firmwareKind(buf)
	switch d.FirmwareKind {
	case "gzip":
		d.Notes = append(d.Notes, "gzip: outer compression, decompress the wrapper first")
	case "xz":
		d.Notes = append(d.Notes, "xz: outer compression, decompress the wrapper first")
	}
	if d.FirmwareKind == "dtb" {
		// A flattened device tree is a node/property table, not a compressed
		// container: telling the caller to decompress entries sends it hunting
		// for payloads that do not exist.
		deepNote(d, "device tree blob: walk the FDT node tree to recover the machine model, the memory map and the peripheral addresses the bootloader hands the kernel; no payload is compressed inside it")
	} else {
		deepNote(d, "image holds rootfs container entries with compressed or obfuscated payloads; decompress each entry in-process to recover the original content, and locate boot and config partitions")
	}

	hits, capped := firmwareHits(buf)
	for _, h := range hits {
		d.FirmwareParts = append(d.FirmwareParts, fmt.Sprintf("0x%08x %s", h.off, h.name))
	}
	d.FirmwareEnd = len(d.FirmwareParts)
	if capped {
		d.Notes = append(d.Notes, fmt.Sprintf("firmware: parts capped at %d", maxFirmwareParts))
	}
	if n == maxFirmwareScan {
		d.Notes = append(d.Notes, "firmware: scanned first 64 MiB only")
	}
	if len(hits) == 0 {
		d.Notes = append(d.Notes, "firmware: no known container magic in scanned range")
	}
}
