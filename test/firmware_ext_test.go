package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha512"
	"encoding/binary"
	"encoding/json"
	"hash/crc32"
	"strings"
	"testing"
)

// crafted headers: each builder carries the field a byte-perfect copy would
// get wrong, so the refusal cases only have to break one value.

func fxBE16(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }
func fxBE32(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
func fxLE16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func fxLE32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

func fxProbe(t *testing.T, name string, img []byte) Digest {
	t.Helper()
	d, err := Probe(writeTemp(t, name, img))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return d
}

func fxRefused(t *testing.T, name string, img []byte, reason string) Digest {
	t.Helper()
	d := fxProbe(t, name, img)
	for _, s := range d.Skipped {
		if s.Reason == reason {
			if d.Kind != "firmware" || d.Format == "firmware-ext" {
				t.Fatalf("refusal left kind/format = %q/%q", d.Kind, d.Format)
			}
			return d
		}
	}
	t.Fatalf("skipped = %v, want %s", d.Skipped, reason)
	return d
}

func fxVerified(t *testing.T, name string, img []byte, format, note string) Digest {
	t.Helper()
	d := fxProbe(t, name, img)
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %v, want none", d.Skipped)
	}
	if d.Kind != "firmware" || d.Format != format || d.FirmwareKind != format {
		t.Fatalf("kind/format/firmware_kind = %q/%q/%q, want firmware/%q/%q",
			d.Kind, d.Format, d.FirmwareKind, format, format)
	}
	if !notesContain(d, note) {
		t.Fatalf("notes = %v, want %q", d.Notes, note)
	}
	return d
}

func fxUBI() []byte {
	b := make([]byte, 4096)
	copy(b, "UBI#")
	b[4] = 1
	fxBE32(b, 16, 64) // vid header
	fxBE32(b, 20, 128)
	fxBE32(b, 24, 0x465be12b)
	fxBE32(b, 60, fwExtRawCRC(b[:60]))
	return b
}

func fxUBIFS() []byte {
	b := make([]byte, fwExtUBIFSNode)
	copy(b, fwExtUBIFSMagic)
	fxLE32(b, 16, fwExtUBIFSNode)
	b[20] = 6
	fxLE32(b, 36, 126976)
	fxLE32(b, 40, 14)
	fxLE32(b, 4, fwExtRawCRC(b[8:]))
	return b
}

func fxJFFS2() []byte {
	b := make([]byte, 64)
	fxLE16(b, 0, 0x1985)
	fxLE16(b, 2, 0xe001)
	fxLE32(b, 4, 64)
	fxLE32(b, 8, fwExtJFFSCRC(b[:8]))
	return b
}

func fxTRX() []byte {
	b := make([]byte, 64)
	copy(b, "HDR0")
	fxLE32(b, 4, 64)
	fxLE16(b, 14, 1)
	fxLE32(b, 8, fwExtRawCRC(b[12:]))
	return b
}

func fxUIMAGE() []byte {
	b := make([]byte, 96)
	copy(b, "\x27\x05\x19\x56")
	fxBE32(b, 12, 32)
	for i := 64; i < 96; i++ {
		b[i] = byte(i)
	}
	fxBE32(b, 24, crc32.ChecksumIEEE(b[64:]))
	fxUIMAGEHeaderCRC(b)
	return b
}

func fxUIMAGEHeaderCRC(b []byte) {
	h := append([]byte(nil), b[:64]...)
	copy(h[4:8], []byte{0, 0, 0, 0})
	fxBE32(b, 4, crc32.ChecksumIEEE(h))
}

func fxSEAMA() []byte {
	payload := []byte("12345678")
	b := make([]byte, 28+4+len(payload))
	copy(b, "\x5e\xa3\xa4\x17")
	fxBE16(b, 6, 4)
	fxBE32(b, 8, uint32(len(payload)))
	copy(b[28:], "abcd")
	copy(b[32:], payload)
	sum := md5.Sum(payload)
	copy(b[12:28], sum[:])
	return b
}

func fxSHRS() []byte {
	payload := bytes.Repeat([]byte{0xa5}, 128)
	b := make([]byte, fwExtSHRSHeader+len(payload))
	copy(b, "SHRS")
	fxBE32(b, 4, uint32(len(payload)))
	fxBE32(b, 8, uint32(len(payload)))
	sum := sha512.Sum512(payload)
	copy(b[156:220], sum[:])
	copy(b[fwExtSHRSHeader:], payload)
	return b
}

func fxDTB() []byte {
	b := make([]byte, 80)
	copy(b, "\xd0\x0d\xfe\xed")
	fxBE32(b, 4, 80)
	fxBE32(b, 8, 40)  // off_dt_struct
	fxBE32(b, 12, 48) // off_dt_strings
	fxBE32(b, 16, 56) // off_mem_rsvmap
	fxBE32(b, 20, 17)
	fxBE32(b, 24, 16)
	fxBE32(b, 32, 4) // size_dt_strings
	fxBE32(b, 36, 8) // size_dt_struct
	fxBE32(b, 40, 1) // FDT_BEGIN_NODE
	fxBE32(b, 44, 2) // FDT_END_NODE
	return b
}

func fxSparse() []byte {
	raw := make([]byte, 20)
	fxLE16(raw, 0, 0xcac1)
	fxLE32(raw, 4, 2)
	fxLE32(raw, 8, 20)
	fill := make([]byte, 16)
	fxLE16(fill, 0, 0xcac2)
	fxLE32(fill, 4, 1)
	fxLE32(fill, 8, 16)
	dont := make([]byte, 12)
	fxLE16(dont, 0, 0xcac3)
	fxLE32(dont, 4, 1)
	fxLE32(dont, 8, 12)
	b := make([]byte, 28)
	fxLE32(b, 0, 0xed26ff3a)
	fxLE16(b, 4, 1)
	fxLE16(b, 8, 28)
	fxLE16(b, 10, 12)
	fxLE32(b, 12, 4) // blk_sz
	fxLE32(b, 16, 4) // total_blks
	fxLE32(b, 20, 3) // total_chunks
	return append(append(append(b, raw...), fill...), dont...)
}

func fxBootimg() []byte {
	b := make([]byte, 6144)
	copy(b, "ANDROID!")
	fxLE32(b, 8, 100) // kernel
	fxLE32(b, 16, 50) // ramdisk
	fxLE32(b, 36, 2048)
	fxLE32(b, 40, 0) // v0
	return b
}

func TestFirmwareExtVerified(t *testing.T) {
	cases := []struct {
		name, format, note string
		img                func() []byte
	}{
		{"ubi", "ubi", "ubi ec version=1 hdr_crc ok", fxUBI},
		{"ubifs", "ubifs", "ubifs superblock crc ok leb_size=126976", fxUBIFS},
		{"jffs2", "jffs2", "jffs2 le nodetype=0xe001", fxJFFS2},
		{"trx", "trx", "trx v1 len=64 crc ok", fxTRX},
		{"uimage", "uimage", "uimage hdr_crc ok size=32", fxUIMAGE},
		{"seama", "seama", "seama meta=4 size=8 md5 ok", fxSEAMA},
		{"shrs", "shrs", "shrs sha512 ok file_size=128", fxSHRS},
		{"dtb", "dtb", "dtb totalsize=80 version=17", fxDTB},
		{"sparse", "sparse", "sparse chunks=3 blk=4 total_blks=4", fxSparse},
		{"bootimg", "bootimg", "bootimg v0 page=2048 kernel=100 ramdisk=50", fxBootimg},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fxVerified(t, c.name+".bin", c.img(), c.format, c.note)
		})
	}
}

// A UBI eraseblock holding a UBIFS superblock at its data offset names both.
func TestFirmwareExtUBICarriesUBIFS(t *testing.T) {
	b := append(fxUBI(), make([]byte, 4096)...)
	copy(b[128:], fxUBIFS())
	d := fxVerified(t, "ubi-ubifs.bin", b, "ubi", "ubi ec version=1 hdr_crc ok")
	if !notesContain(d, "ubifs superblock at 0x00000080") {
		t.Fatalf("notes = %v, want the inner superblock", d.Notes)
	}
	found := false
	for _, part := range d.FirmwareParts {
		if part == "0x00000080 ubifs" {
			found = true
		}
	}
	if !found {
		t.Fatalf("firmware_detail = %v, want 0x00000080 ubifs", d.FirmwareParts)
	}
}

func TestFirmwareExtRefusals(t *testing.T) {
	cases := []struct {
		name, reason string
		img          func() []byte
	}{
		{"ubi-crc", fwExtCRC, func() []byte { b := fxUBI(); b[24] ^= 1; return b }},
		{"ubi-version", fwExtInvalid, func() []byte {
			b := fxUBI()
			b[4] = 2
			fxBE32(b, 60, fwExtRawCRC(b[:60]))
			return b
		}},
		{"ubi-offsets", fwExtInvalid, func() []byte {
			b := fxUBI()
			fxBE32(b, 20, 32) // data before the vid header
			fxBE32(b, 60, fwExtRawCRC(b[:60]))
			return b
		}},
		{"ubifs-crc", fwExtCRC, func() []byte { b := fxUBIFS(); b[4] ^= 1; return b }},
		{"ubifs-type", fwExtInvalid, func() []byte {
			b := fxUBIFS()
			b[20] = 7
			fxLE32(b, 4, fwExtRawCRC(b[8:]))
			return b
		}},
		{"jffs2-crc", fwExtCRC, func() []byte { b := fxJFFS2(); fxLE32(b, 8, 0); return b }},
		{"jffs2-length", fwExtLength, func() []byte { b := fxJFFS2(); fxLE32(b, 4, 1<<20); return b }},
		{"trx-length", fwExtLength, func() []byte { b := fxTRX(); fxLE32(b, 4, 4096); return b }},
		{"trx-digest", fwExtDigest, func() []byte { b := fxTRX(); b[40] ^= 1; return b }},
		{"uimage-header-crc", fwExtCRC, func() []byte { b := fxUIMAGE(); b[4] ^= 1; return b }},
		{"uimage-length", fwExtLength, func() []byte {
			b := fxUIMAGE()
			fxBE32(b, 12, 1000)
			fxUIMAGEHeaderCRC(b)
			return b
		}},
		{"uimage-digest", fwExtDigest, func() []byte { b := fxUIMAGE(); b[64] ^= 1; return b }},
		{"seama-md5", fwExtDigest, func() []byte { b := fxSEAMA(); b[12] ^= 1; return b }},
		{"seama-length", fwExtLength, func() []byte { b := fxSEAMA(); fxBE32(b, 8, 1000); return b }},
		{"seama-label", fwExtUnverified, func() []byte { return []byte("SEAMA....header-only-payload") }},
		{"shrs-digest", fwExtDigest, func() []byte { b := fxSHRS(); b[fwExtSHRSHeader] ^= 1; return b }},
		{"shrs-length", fwExtLength, func() []byte { b := fxSHRS(); fxBE32(b, 8, 200); return b }},
		{"dtb-token", fwExtInvalid, func() []byte { b := fxDTB(); fxBE32(b, 40, 2); return b }},
		{"dtb-length", fwExtLength, func() []byte { b := fxDTB(); fxBE32(b, 4, 1000); return b }},
		{"sparse-raw-size", fwExtInvalid, func() []byte { b := fxSparse(); fxLE32(b, 28+4, 3); return b }},
		{"sparse-block-sum", fwExtLength, func() []byte { b := fxSparse(); fxLE32(b, 16, 5); return b }},
		{"sparse-chunk-cap", fwExtTooBig, func() []byte {
			b := fxSparse()[:28]
			fxLE32(b, 20, 5000)
			return b
		}},
		{"bootimg-page", fwExtInvalid, func() []byte { b := fxBootimg(); fxLE32(b, 36, 1000); return b }},
		{"bootimg-length", fwExtLength, func() []byte { b := fxBootimg(); fxLE32(b, 8, 100000); return b }},
		{"bootimg-v3", fwExtUnverified, func() []byte { b := fxBootimg(); fxLE32(b, 40, 3); return b }},
		{"ubifs-truncated", fwExtTruncated, func() []byte { return fxUBIFS()[:16] }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fxRefused(t, c.name+".bin", c.img(), c.reason)
		})
	}
}

// The refusal carries the honest numbers, not just the label.
func TestFirmwareExtRefusalDetail(t *testing.T) {
	b := fxTRX()
	fxLE32(b, 4, 4096)
	d := fxRefused(t, "trx-lie.bin", b, fwExtLength)
	if !strings.Contains(d.Skipped[0].Detail, "4096") {
		t.Fatalf("detail = %q, want the declared length", d.Skipped[0].Detail)
	}
	b = fxSparse()
	fxLE32(b, 20, 5000)
	d = fxRefused(t, "sparse-cap.bin", b[:28], fwExtTooBig)
	if !strings.Contains(d.Skipped[0].Detail, "cap") {
		t.Fatalf("detail = %q, want the cap", d.Skipped[0].Detail)
	}
}

// Black box: a lying length is a finding (exit 0) with a switchable reason.
func TestFirmwareExtCLILyingLength(t *testing.T) {
	p := writeTemp(t, "trx-lying.bin", fxTRX()[:28])
	out, code := runCLI(t, "--json", p)
	if code != 0 {
		t.Fatalf("exit %d, want 0: %s", code, out)
	}
	var got struct {
		Kind    string `json:"kind"`
		Format  string `json:"format"`
		Skipped []struct {
			Reason string `json:"reason"`
		} `json:"skipped"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json: %v\n%s", err, out)
	}
	if got.Kind != "firmware" || got.Format != "trx" {
		t.Fatalf("kind/format = %q/%q, want firmware/trx", got.Kind, got.Format)
	}
	if len(got.Skipped) == 0 || got.Skipped[0].Reason != fwExtLength {
		t.Fatalf("skipped = %v, want %s", got.Skipped, fwExtLength)
	}
}
