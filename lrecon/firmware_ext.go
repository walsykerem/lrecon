package main

import (
	"bytes"
	"crypto/md5"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
)

// firmware_ext owns the handler formats firmware.go only names by magic: it
// re-reads the header, checks the field a byte-perfect copy would get wrong
// (CRC, declared length, magic2, block coverage), and refuses with a reason
// when the declaration and the bytes disagree.
//
// It is a post reader with claimsKind so UBIFS/JFFS2/SHRS/SEAMA/sparse/bootimg
// get a format even though firmware.go does not list their magic; formats it
// already names (UBI, TRX, UIMAGE, DTB) keep their kind and gain the check.

const (
	fwExtHead         = 8 << 10  // header window: SHRS 1756 B, bootimg v2 1660 B, UBIFS SB 4096 B
	fwExtDigestCap    = 16 << 20 // payload bytes hashed/checked in one pass
	fwExtSparseChunks = 4096     // sparse chunk headers walked
	fwExtSHRSHeader   = 1756     // D-Link SHRS header size
	fwExtUBIFSNode    = 4096     // UBIFS superblock node length
)

const (
	fwExtCRC        = "firmware-ext-header-crc"
	fwExtInvalid    = "firmware-ext-header-invalid"
	fwExtUnverified = "firmware-ext-header-unverified"
	fwExtLength     = "firmware-ext-length-disagree"
	fwExtDigest     = "firmware-ext-digest-mismatch"
	fwExtTooBig     = "firmware-ext-too-big"
	fwExtTruncated  = "firmware-ext-truncated"
)

var fwExtUBIFSMagic = []byte("\x31\x18\x10\x06")

func init() {
	reasonRegistry["firmware-ext"] = reasonSet(
		fwExtCRC, fwExtInvalid, fwExtUnverified, fwExtLength,
		fwExtDigest, fwExtTooBig, fwExtTruncated,
	)
	register(reader{
		format: "firmware-ext",
		reasons: []string{
			fwExtCRC, fwExtInvalid, fwExtUnverified, fwExtLength,
			fwExtDigest, fwExtTooBig, fwExtTruncated,
		},
		post:       true,
		claimsKind: true,
		match:      fwExtMatch,
		inspect:    inspectFirmwareExt,
	})
}

func fwExtMatch(head []byte, _ int64) bool { return fwExtName(head) != "" }

func fwExtName(h []byte) string {
	switch {
	case bytes.HasPrefix(h, []byte("UBI#")):
		return "ubi"
	case bytes.HasPrefix(h, fwExtUBIFSMagic):
		return "ubifs"
	case bytes.HasPrefix(h, []byte("\x19\x85")), bytes.HasPrefix(h, []byte("\x85\x19")):
		return "jffs2"
	case bytes.HasPrefix(h, []byte("HDR0")):
		return "trx"
	case bytes.HasPrefix(h, []byte("\x27\x05\x19\x56")):
		return "uimage"
	case bytes.HasPrefix(h, []byte("SEAMA")), bytes.HasPrefix(h, []byte("\x5e\xa3\xa4\x17")):
		return "seama"
	case bytes.HasPrefix(h, []byte("SHRS")):
		return "shrs"
	case bytes.HasPrefix(h, []byte("\xd0\x0d\xfe\xed")):
		return "dtb"
	case bytes.HasPrefix(h, []byte("\x3a\xff\x26\xed")):
		return "sparse"
	case bytes.HasPrefix(h, []byte("ANDROID!")):
		return "bootimg"
	}
	return ""
}

func inspectFirmwareExt(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		d.skip(fwExtTruncated, "open: "+err.Error())
		return
	}
	defer f.Close()

	var buf [fwExtHead]byte
	n, err := io.ReadFull(f, buf[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		d.skip(fwExtTruncated, "read: "+err.Error())
		return
	}
	hdr := buf[:n]
	fwExtWitness(d, 0, int64(n))

	kind := fwExtName(hdr)
	if kind == "" {
		return
	}
	d.Kind = "firmware"
	d.Format = kind
	d.FirmwareKind = kind

	switch kind {
	case "ubi":
		fwExtUBI(f, hdr, d)
	case "ubifs":
		fwExtUBIFS(f, hdr, d)
	case "jffs2":
		fwExtJFFS2(hdr, d)
	case "trx":
		fwExtTRX(f, hdr, d)
	case "uimage":
		fwExtUIMAGE(f, hdr, d)
	case "seama":
		fwExtSEAMA(f, hdr, d)
	case "shrs":
		fwExtSHRS(f, hdr, d)
	case "dtb":
		fwExtDTB(f, hdr, d)
	case "sparse":
		fwExtSparse(f, hdr, d)
	case "bootimg":
		fwExtBootimg(hdr, d)
	}
}

// fwExtWitness records one real read span; the class is fixed at this call site.
func fwExtWitness(d *Digest, start, n int64) {
	if n <= 0 {
		return
	}
	d.witness(Witness{Axis: "read", Class: "read", Value: "read", Start: start, End: start + n})
}

// fwExtReadAt reads inside the file silently: scans use it for candidates that
// may simply not hold a node.
func fwExtReadAt(f *os.File, d *Digest, start, n int64) ([]byte, bool) {
	if n <= 0 {
		return nil, true
	}
	if start < 0 || start+n > d.FileSize {
		return nil, false
	}
	var b [fwExtUBIFSNode]byte
	if n > int64(len(b)) {
		return nil, false
	}
	if _, err := f.ReadAt(b[:n], start); err != nil {
		return nil, false
	}
	fwExtWitness(d, start, n)
	return b[:n], true
}

func fwExtRead(f *os.File, d *Digest, start, n int64) ([]byte, bool) {
	b, ok := fwExtReadAt(f, d, start, n)
	if !ok {
		d.skip(fwExtTruncated, fmt.Sprintf("wanted %d B at offset %d, file is %d B", n, start, d.FileSize))
	}
	return b, ok
}

// fwExtSum hashes a declared payload in place: no buffer, and past the cap it
// refuses instead of hashing a prefix and calling it verified.
func fwExtSum(f *os.File, d *Digest, start, n int64, what string, h hash.Hash) ([]byte, bool) {
	if n > fwExtDigestCap {
		d.skip(fwExtTooBig, fmt.Sprintf("%s is %d B, digest cap %d B", what, n, fwExtDigestCap))
		return nil, false
	}
	if start < 0 || n < 0 || start+n > d.FileSize {
		d.skip(fwExtTruncated, fmt.Sprintf("%s wants %d B at offset %d, file is %d B", what, n, start, d.FileSize))
		return nil, false
	}
	if _, err := io.CopyN(h, io.NewSectionReader(f, start, n), n); err != nil {
		d.skip(fwExtTruncated, fmt.Sprintf("%s read: %v", what, err))
		return nil, false
	}
	fwExtWitness(d, start, n)
	return h.Sum(nil), true
}

// fwExtRawCRC is the kernel's raw CRC32: init 0xFFFFFFFF, no final xor. UBI,
// UBIFS and TRX store it; JFFS2 uses the pre/post-inverted form below.
func fwExtRawCRC(b []byte) uint32 { return ^crc32.ChecksumIEEE(b) }

var fwExtIEEETable = crc32.MakeTable(crc32.IEEE)

// fwExtJFFSCRC is JFFS2's header CRC, which is neither ChecksumIEEE nor the raw
// kernel form: seed 0xFFFFFFFF through the standard table, then invert.
func fwExtJFFSCRC(b []byte) uint32 { return ^crc32.Update(0xFFFFFFFF, fwExtIEEETable, b) }

func fwExtNote(d *Digest, format string, args ...any) {
	d.Notes = append(d.Notes, "firmware-ext: "+fmt.Sprintf(format, args...))
}

func fwExtNeed(hdr []byte, n int, d *Digest, what string) bool {
	if len(hdr) < n {
		d.skip(fwExtTruncated, fmt.Sprintf("%s header needs %d B, file is %d B", what, n, len(hdr)))
		return false
	}
	return true
}

// UBI eraseblock header: 64 B, version, two offsets and a raw CRC32 over the
// first 60 bytes. A copy with one field changed fails the CRC.
func fwExtUBI(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 64, d, "ubi ec") {
		return
	}
	if v := hdr[4]; v != 1 {
		d.skip(fwExtInvalid, fmt.Sprintf("ubi version %d, want 1", v))
		return
	}
	if got, want := binary.BigEndian.Uint32(hdr[60:64]), fwExtRawCRC(hdr[:60]); got != want {
		d.skip(fwExtCRC, fmt.Sprintf("ubi hdr_crc 0x%08x, computed 0x%08x", got, want))
		return
	}
	vid := int64(binary.BigEndian.Uint32(hdr[16:20]))
	data := int64(binary.BigEndian.Uint32(hdr[20:24]))
	seq := binary.BigEndian.Uint32(hdr[24:28])
	if vid < 64 || vid+64 > data {
		d.skip(fwExtInvalid, fmt.Sprintf("ubi vid_hdr_offset %d does not leave room for the 64 B vid header before data_offset %d", vid, data))
		return
	}
	if data > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("ubi data_offset %d is past the %d B file", data, d.FileSize))
		return
	}
	d.parsed()
	fwExtNote(d, "ubi ec version=1 hdr_crc ok image_seq=0x%08x vid_hdr=%d data=%d", seq, vid, data)

	// A UBI image often carries UBIFS: the first superblock sits at the first
	// eraseblock's data offset. Name it only after its own CRC and node type pass.
	for off := 0; off < len(hdr); {
		i := bytes.Index(hdr[off:], fwExtUBIFSMagic)
		if i < 0 {
			break
		}
		at := int64(off + i)
		if node, ok := fwExtReadAt(f, d, at, fwExtUBIFSNode); ok {
			if info, ok := fwExtUBIFSSuper(node); ok {
				d.FirmwareParts = append(d.FirmwareParts, fmt.Sprintf("0x%08x ubifs", at))
				d.FirmwareEnd = len(d.FirmwareParts)
				fwExtNote(d, "ubifs superblock at 0x%08x leb_size=%d leb_cnt=%d", at, info.lebSize, info.lebCnt)
				break
			}
		}
		off += i + 1
	}
}

type fwExtUBIFSInfo struct{ lebSize, lebCnt uint32 }

// fwExtUBIFSSuper checks a UBIFS superblock node: LE length at 16, node type 6
// at 20, and a raw CRC32 over [8:len) at 4.
func fwExtUBIFSSuper(b []byte) (fwExtUBIFSInfo, bool) {
	var info fwExtUBIFSInfo
	if len(b) < 24 || !bytes.HasPrefix(b, fwExtUBIFSMagic) {
		return info, false
	}
	n := int(binary.LittleEndian.Uint32(b[16:20]))
	if n < 32 || n > fwExtUBIFSNode || len(b) < n {
		return info, false
	}
	if got, want := binary.LittleEndian.Uint32(b[4:8]), fwExtRawCRC(b[8:n]); got != want {
		return info, false
	}
	if b[20] != 6 {
		return info, false
	}
	if n >= 44 {
		info.lebSize = binary.LittleEndian.Uint32(b[36:40])
		info.lebCnt = binary.LittleEndian.Uint32(b[40:44])
	}
	return info, true
}

// Naked UBIFS: the file starts at the superblock, so a bad field is a refusal
// rather than a scan miss.
func fwExtUBIFS(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 24, d, "ubifs superblock") {
		return
	}
	n := int(binary.LittleEndian.Uint32(hdr[16:20]))
	if n < 32 || n > fwExtUBIFSNode {
		d.skip(fwExtInvalid, fmt.Sprintf("ubifs node length %d outside [32,%d]", n, fwExtUBIFSNode))
		return
	}
	node, ok := fwExtRead(f, d, 0, int64(n))
	if !ok {
		return
	}
	if got, want := binary.LittleEndian.Uint32(node[4:8]), fwExtRawCRC(node[8:n]); got != want {
		d.skip(fwExtCRC, fmt.Sprintf("ubifs crc 0x%08x, computed 0x%08x", got, want))
		return
	}
	if node[20] != 6 {
		d.skip(fwExtInvalid, fmt.Sprintf("ubifs node type %d, want superblock 6", node[20]))
		return
	}
	info, _ := fwExtUBIFSSuper(node)
	d.parsed()
	fwExtNote(d, "ubifs superblock crc ok leb_size=%d leb_cnt=%d", info.lebSize, info.lebCnt)
}

// JFFS2 node header: magic 0x1985 in either byte order, nodetype, totlen and a
// raw CRC32 over the first 8 bytes.
func fwExtJFFS2(hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 12, d, "jffs2 node") {
		return
	}
	be := hdr[0] == 0x19
	var u16 = binary.LittleEndian.Uint16
	var u32 = binary.LittleEndian.Uint32
	order := "le"
	if be {
		u16, u32 = binary.BigEndian.Uint16, binary.BigEndian.Uint32
		order = "be"
	}
	if u16(hdr[0:2]) != 0x1985 {
		d.skip(fwExtInvalid, fmt.Sprintf("jffs2 magic 0x%04x, want 0x1985", u16(hdr[0:2])))
		return
	}
	nodetype := u16(hdr[2:4])
	totlen := int64(u32(hdr[4:8]))
	crc := u32(hdr[8:12])
	known := map[uint16]bool{
		0x2003: true, 0x2004: true, 0x2006: true,
		0xe001: true, 0xe002: true, 0xe008: true, 0xe009: true,
	}
	exact := known[nodetype]
	if !exact && !known[nodetype|0x2000] {
		d.skip(fwExtInvalid, fmt.Sprintf("jffs2 nodetype 0x%04x is not a node this parser knows", nodetype))
		return
	}
	if totlen < 12 {
		d.skip(fwExtInvalid, fmt.Sprintf("jffs2 totlen %d is smaller than the 12 B header", totlen))
		return
	}
	if totlen > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("jffs2 node declares %d B, file is %d B", totlen, d.FileSize))
		return
	}
	if exact {
		if got, want := crc, fwExtJFFSCRC(hdr[:8]); got != want {
			d.skip(fwExtCRC, fmt.Sprintf("jffs2 hdr_crc 0x%08x, computed 0x%08x", got, want))
			return
		}
	}
	d.parsed()
	if exact {
		fwExtNote(d, "jffs2 %s nodetype=0x%04x totlen=%d hdr_crc ok", order, nodetype, totlen)
	} else {
		fwExtNote(d, "jffs2 %s nodetype=0x%04x totlen=%d hdr_crc not checked (nodetype bit 0x2000 unset)", order, nodetype, totlen)
	}
}

// TRX: little-endian length at 4, raw CRC32 over [12:len) at 8, version 1
// (three partition offsets) or 2 (four).
func fwExtTRX(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 28, d, "trx") {
		return
	}
	ver := binary.LittleEndian.Uint16(hdr[14:16])
	hdrLen := 28
	switch ver {
	case 1:
	case 2:
		hdrLen = 32
	default:
		d.skip(fwExtInvalid, fmt.Sprintf("trx version %d, want 1 or 2", ver))
		return
	}
	if !fwExtNeed(hdr, hdrLen, d, "trx v"+fmt.Sprint(ver)) {
		return
	}
	total := int64(binary.LittleEndian.Uint32(hdr[4:8]))
	if total < int64(hdrLen) {
		d.skip(fwExtInvalid, fmt.Sprintf("trx length %d is smaller than the %d B header", total, hdrLen))
		return
	}
	if total > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("trx declares %d B, file is %d B", total, d.FileSize))
		return
	}
	for off := 16; off < hdrLen; off += 4 {
		v := int64(binary.LittleEndian.Uint32(hdr[off : off+4]))
		if v != 0 && (v < int64(hdrLen) || v > total) {
			d.skip(fwExtInvalid, fmt.Sprintf("trx offset @%d = %d outside [%d,%d]", off, v, hdrLen, total))
			return
		}
	}
	h := crc32.New(fwExtIEEETable)
	if _, ok := fwExtSum(f, d, 12, total-12, "trx image", h); !ok {
		return
	}
	if got, want := binary.LittleEndian.Uint32(hdr[8:12]), ^h.Sum32(); got != want {
		d.skip(fwExtDigest, fmt.Sprintf("trx crc 0x%08x, computed 0x%08x over [12:%d)", got, want, total))
		return
	}
	d.parsed()
	fwExtNote(d, "trx v%d len=%d crc ok", ver, total)
}

// UIMAGE: 64 B big-endian header, CRC32 over the header with its own CRC field
// zeroed, then the payload CRC at 24 and the declared size at 12.
func fwExtUIMAGE(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 64, d, "uimage") {
		return
	}
	var hcrc [64]byte
	copy(hcrc[:], hdr[:64])
	copy(hcrc[4:8], []byte{0, 0, 0, 0})
	if got, want := binary.BigEndian.Uint32(hdr[4:8]), crc32.ChecksumIEEE(hcrc[:]); got != want {
		d.skip(fwExtCRC, fmt.Sprintf("uimage hdr_crc 0x%08x, computed 0x%08x", got, want))
		return
	}
	size := int64(binary.BigEndian.Uint32(hdr[12:16]))
	if size > d.FileSize-64 {
		d.skip(fwExtLength, fmt.Sprintf("uimage payload declares %d B, only %d B follow the header", size, d.FileSize-64))
		return
	}
	dcrc := binary.BigEndian.Uint32(hdr[24:28])
	h := crc32.NewIEEE()
	if _, ok := fwExtSum(f, d, 64, size, "uimage payload", h); !ok {
		return
	}
	if dcrc != 0 {
		if got, want := dcrc, h.Sum32(); got != want {
			d.skip(fwExtDigest, fmt.Sprintf("uimage data_crc 0x%08x, computed 0x%08x", got, want))
			return
		}
	}
	d.parsed()
	fwExtNote(d, "uimage hdr_crc ok size=%d os=%d arch=%d type=%d comp=%d",
		size, hdr[28], hdr[29], hdr[30], hdr[31])
}

// SEAMA: big-endian magic, metasize at 6, image size at 8, MD5 of the image at
// 12. The ASCII "SEAMA" label variant has no verified layout, so it refuses.
func fwExtSEAMA(f *os.File, hdr []byte, d *Digest) {
	if bytes.HasPrefix(hdr, []byte("SEAMA")) {
		d.skip(fwExtUnverified, "seama label without the binary header: layout not verified")
		return
	}
	if !fwExtNeed(hdr, 28, d, "seama") {
		return
	}
	meta := int64(binary.BigEndian.Uint16(hdr[6:8]))
	size := int64(binary.BigEndian.Uint32(hdr[8:12]))
	if size == 0 {
		d.skip(fwExtInvalid, "seama image size 0")
		return
	}
	total := 28 + meta + size
	if total > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("seama meta %d + image %d + 28 B header exceeds the %d B file", meta, size, d.FileSize))
		return
	}
	h := md5.New()
	if _, ok := fwExtSum(f, d, 28+meta, size, "seama image", h); !ok {
		return
	}
	sum := h.Sum(nil)
	if !bytes.Equal(sum, hdr[12:28]) {
		d.skip(fwExtDigest, fmt.Sprintf("seama md5 %x, computed %x", hdr[12:28], sum))
		return
	}
	d.parsed()
	fwExtNote(d, "seama meta=%d size=%d md5 ok", meta, size)
}

// SHRS: 1756 B header, file size at 4, unpadded size at 8, SHA-512 of the
// unpadded payload at 156.
func fwExtSHRS(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, fwExtSHRSHeader, d, "shrs") {
		return
	}
	size := int64(binary.BigEndian.Uint32(hdr[4:8]))
	nopad := int64(binary.BigEndian.Uint32(hdr[8:12]))
	if size == 0 {
		d.skip(fwExtInvalid, "shrs file_size 0")
		return
	}
	if nopad == 0 || nopad > size {
		d.skip(fwExtLength, fmt.Sprintf("shrs no_padding %d outside [1,%d]", nopad, size))
		return
	}
	if fwExtSHRSHeader+size > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("shrs declares %d B payload, only %d B follow the header", size, d.FileSize-fwExtSHRSHeader))
		return
	}
	h := sha512.New()
	if _, ok := fwExtSum(f, d, fwExtSHRSHeader, nopad, "shrs payload", h); !ok {
		return
	}
	sum := h.Sum(nil)
	if !bytes.Equal(sum, hdr[156:220]) {
		d.skip(fwExtDigest, fmt.Sprintf("shrs sha512 %x, computed %x", hdr[156:220], sum))
		return
	}
	d.parsed()
	fwExtNote(d, "shrs sha512 ok file_size=%d no_padding=%d", size, nopad)
}

// DTB/FDT: big-endian totalsize and block offsets, with the first struct token
// required to be FDT_BEGIN_NODE — the magic2 a copied header gets wrong.
func fwExtDTB(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 40, d, "dtb") {
		return
	}
	total := int64(binary.BigEndian.Uint32(hdr[4:8]))
	structOff := int64(binary.BigEndian.Uint32(hdr[8:12]))
	stringsOff := int64(binary.BigEndian.Uint32(hdr[12:16]))
	rsvOff := int64(binary.BigEndian.Uint32(hdr[16:20]))
	ver := binary.BigEndian.Uint32(hdr[20:24])
	stringsSize := int64(binary.BigEndian.Uint32(hdr[32:36]))
	structSize := int64(binary.BigEndian.Uint32(hdr[36:40]))
	if ver != 16 && ver != 17 {
		d.skip(fwExtInvalid, fmt.Sprintf("dtb version %d, want 16 or 17", ver))
		return
	}
	if total < 40 {
		d.skip(fwExtInvalid, fmt.Sprintf("dtb totalsize %d is smaller than the 40 B header", total))
		return
	}
	if total > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("dtb declares %d B, file is %d B", total, d.FileSize))
		return
	}
	if structOff < 40 || stringsOff < 40 || rsvOff < 40 {
		d.skip(fwExtInvalid, fmt.Sprintf("dtb block offsets struct=%d strings=%d rsvmap=%d must follow the header", structOff, stringsOff, rsvOff))
		return
	}
	if ver >= 17 {
		if structOff+structSize > total || stringsOff+stringsSize > total {
			d.skip(fwExtLength, fmt.Sprintf("dtb struct[%d:+%d] or strings[%d:+%d] exceeds totalsize %d",
				structOff, structSize, stringsOff, stringsSize, total))
			return
		}
		tok, ok := fwExtRead(f, d, structOff, 4)
		if !ok {
			return
		}
		if v := binary.BigEndian.Uint32(tok); v != 1 {
			d.skip(fwExtInvalid, fmt.Sprintf("dtb first struct token 0x%08x, want FDT_BEGIN_NODE (1)", v))
			return
		}
	} else if structOff >= total || stringsOff >= total || rsvOff >= total {
		d.skip(fwExtInvalid, "dtb block offset past totalsize")
		return
	}
	d.parsed()
	fwExtNote(d, "dtb totalsize=%d version=%d struct=%d+%d strings=%d+%d", total, ver, structOff, structSize, stringsOff, stringsSize)
}

// Android sparse: chunk headers must tile the declared block count; a raw chunk
// payload must cost exactly chunk_sz*blk_sz bytes.
func fwExtSparse(f *os.File, hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 28, d, "sparse") {
		return
	}
	major := binary.LittleEndian.Uint16(hdr[4:6])
	fileHdr := int64(binary.LittleEndian.Uint16(hdr[8:10]))
	chunkHdr := int64(binary.LittleEndian.Uint16(hdr[10:12]))
	if major != 1 {
		d.skip(fwExtInvalid, fmt.Sprintf("sparse major %d, want 1", major))
		return
	}
	if fileHdr != 28 || chunkHdr != 12 {
		d.skip(fwExtInvalid, fmt.Sprintf("sparse header sizes %d/%d, want 28/12", fileHdr, chunkHdr))
		return
	}
	blk := int64(binary.LittleEndian.Uint32(hdr[12:16]))
	totalBlks := int64(binary.LittleEndian.Uint32(hdr[16:20]))
	totalChunks := int64(binary.LittleEndian.Uint32(hdr[20:24]))
	checksum := binary.LittleEndian.Uint32(hdr[24:28])
	if blk == 0 {
		d.skip(fwExtInvalid, "sparse block size 0")
		return
	}
	if totalChunks > fwExtSparseChunks {
		d.skip(fwExtTooBig, fmt.Sprintf("sparse %d chunks, cap %d", totalChunks, fwExtSparseChunks))
		return
	}
	off := fileHdr
	var blocks int64
	for i := range totalChunks {
		ch, ok := fwExtRead(f, d, off, chunkHdr)
		if !ok {
			return
		}
		types := binary.LittleEndian.Uint16(ch[0:2])
		csz := int64(binary.LittleEndian.Uint32(ch[4:8]))
		tsz := int64(binary.LittleEndian.Uint32(ch[8:12]))
		switch types {
		case 0xcac1:
			if csz*blk != tsz-chunkHdr {
				d.skip(fwExtInvalid, fmt.Sprintf("sparse chunk %d raw %d blocks is %d B, header says %d B", i, csz, csz*blk+chunkHdr, tsz))
				return
			}
		case 0xcac2, 0xcac3, 0xcac4:
		default:
			d.skip(fwExtInvalid, fmt.Sprintf("sparse chunk %d type 0x%04x is not raw/fill/dontcare/crc32", i, types))
			return
		}
		if csz > totalBlks {
			d.skip(fwExtInvalid, fmt.Sprintf("sparse chunk %d covers %d blocks, header declares %d", i, csz, totalBlks))
			return
		}
		if tsz < chunkHdr || off+tsz > d.FileSize {
			d.skip(fwExtLength, fmt.Sprintf("sparse chunk %d ends at %d, file is %d B", i, off+tsz, d.FileSize))
			return
		}
		blocks += csz
		off += tsz
	}
	if blocks != totalBlks {
		d.skip(fwExtLength, fmt.Sprintf("sparse chunks cover %d blocks, header declares %d", blocks, totalBlks))
		return
	}
	d.parsed()
	fwExtNote(d, "sparse chunks=%d blk=%d total_blks=%d checksum=0x%08x", totalChunks, blk, totalBlks, checksum)
}

// Android boot image: page size at 36 must be a real page, and the page-aligned
// layout (kernel, ramdisk, second, v1 recovery dtbo, v2 dtb) must fit the file.
func fwExtBootimg(hdr []byte, d *Digest) {
	if !fwExtNeed(hdr, 44, d, "bootimg") {
		return
	}
	page := int64(binary.LittleEndian.Uint32(hdr[36:40]))
	switch page {
	case 2048, 4096, 8192, 16384:
	default:
		d.skip(fwExtInvalid, fmt.Sprintf("bootimg page_size %d, want 2048/4096/8192/16384", page))
		return
	}
	ver := binary.LittleEndian.Uint32(hdr[40:44])
	if ver > 2 {
		d.skip(fwExtUnverified, fmt.Sprintf("bootimg v%d layout not verified (only v0-v2)", ver))
		return
	}
	need := int64(1632) // v0; v1 adds 16 B (recovery dtbo), v2 adds 28 B (dtb)
	if ver == 1 {
		need = 1648
	}
	if ver == 2 {
		need = 1660
	}
	if need > page {
		d.skip(fwExtInvalid, fmt.Sprintf("bootimg v%d header %d B does not fit a %d B page", ver, need, page))
		return
	}
	if int64(len(hdr)) < need {
		d.skip(fwExtTruncated, fmt.Sprintf("bootimg v%d header needs %d B, file is %d B", ver, need, d.FileSize))
		return
	}
	round := func(n int64) int64 {
		if n <= 0 {
			return 0
		}
		return (n + page - 1) / page * page
	}
	kernel := int64(binary.LittleEndian.Uint32(hdr[8:12]))
	ramdisk := int64(binary.LittleEndian.Uint32(hdr[16:20]))
	second := int64(binary.LittleEndian.Uint32(hdr[24:28]))
	total := page + round(kernel) + round(ramdisk) + round(second)
	if ver >= 1 {
		total += round(int64(binary.LittleEndian.Uint32(hdr[1632:1636])))
	}
	if ver >= 2 {
		total += round(int64(binary.LittleEndian.Uint32(hdr[1648:1652])))
	}
	if total > d.FileSize {
		d.skip(fwExtLength, fmt.Sprintf("bootimg v%d layout needs %d B, file is %d B", ver, total, d.FileSize))
		return
	}
	d.parsed()
	fwExtNote(d, "bootimg v%d page=%d kernel=%d ramdisk=%d second=%d", ver, page, kernel, ramdisk, second)
}
