package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"debug/macho"
	"encoding/hex"
	"fmt"
)

// Mach-O code signature: an LC_CODE_SIGNATURE load command points at a
// SuperBlob (big-endian magic 0xFADE0CC0) of typed blobs. The CodeDirectory
// says how many pages of the image were sealed and with which hash; those
// page hashes are recomputed from the file here, not taken on faith.

const (
	csSuperBlobMagic = 0xfade0cc0
	csCodeDirMagic   = 0xfade0c02
	csMaxBlobs       = 256
)

var csBlobTypes = map[uint32]string{
	0: "CodeDirectory", 1: "InfoSlot", 2: "Requirements", 3: "ResourceDir",
	4: "Application", 5: "Entitlements", 6: "RepSpecific", 7: "DmgInfo",
	8: "DEREntitlements", 0x10000: "AltCodeDirectory",
}

var csHashNames = map[uint8]string{1: "sha1", 2: "sha256", 3: "sha256-truncated", 4: "sha384"}

type csBlob struct {
	Type     uint32 `json:"type"`
	TypeName string `json:"type_name"`
	Magic    string `json:"magic"`
	Offset   uint32 `json:"offset"`
	Length   uint32 `json:"length"`
}

type csCodeDirectory struct {
	Version      uint32 `json:"version"`
	Flags        uint32 `json:"flags"`
	Identifier   string `json:"identifier"`
	TeamID       string `json:"team_id,omitempty"`
	HashType     string `json:"hash_type"`
	HashTypeID   uint8  `json:"hash_type_id"`
	HashSize     uint8  `json:"hash_size"`
	HashOffset   uint32 `json:"hash_offset"`
	PageSize     uint32 `json:"page_size"`
	CodeLimit    uint64 `json:"code_limit"`
	CodeSlots    uint32 `json:"code_slots"`
	SpecialSlots uint32 `json:"special_slots"`
	CDHash       string `json:"cdhash,omitempty"`

	slots []byte // hash slots, relative to this CodeDirectory
}

type csVerify struct {
	PagesChecked uint32   `json:"pages_checked"`
	HashesOK     bool     `json:"hashes_ok"`
	Mismatched   []uint32 `json:"mismatched_pages,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

type csResult struct {
	Source        string           `json:"source"`
	Magic         string           `json:"magic"`
	Length        uint32           `json:"length"`
	Blobs         []csBlob         `json:"blobs"`
	CodeDirectory *csCodeDirectory `json:"code_directory,omitempty"`
	Verification  csVerify         `json:"verification"`
}

func init() {
	registerOp(op{
		name:  "inspect_signature",
		route: "L",
		needs: true,
		desc:  "Mach-O code signature SuperBlob: every blob, CodeDirectory fields, and each page hash recomputed against the signed bytes",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			blob, code, source, err := csLocate(path, b)
			if err != nil {
				return nil, err
			}
			res := csResult{Source: source}
			cd, err := csParseSuperBlob(blob, &res)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			if cd == nil {
				return nil, fmt.Errorf("%s code signature carries no CodeDirectory", path)
			}
			res.CodeDirectory = cd
			if code == nil {
				res.Verification.Reason = "bare signature blob: the signed image bytes are not in this file"
				return res, nil
			}
			res.Verification = csVerifyPages(cd, code)
			return res, nil
		},
	})
}

// csLocate returns the SuperBlob and, when the target is a Mach-O, the image
// bytes the code pages were sealed over. A bare 0xFADE0CC0 blob has neither.
func csLocate(path string, b []byte) (blob, code []byte, source string, err error) {
	if len(b) >= 4 && u32be(b, 0) == csSuperBlobMagic {
		return b, nil, "superblob", nil
	}
	var m *macho.File
	var base int64
	if ff, ferr := macho.OpenFat(path); ferr == nil {
		defer ff.Close()
		if len(ff.Arches) == 0 {
			return nil, nil, "", fmt.Errorf("%s is an empty fat Mach-O", path)
		}
		m, base = ff.Arches[0].File, int64(ff.Arches[0].Offset)
	} else if tf, terr := macho.Open(path); terr == nil {
		defer tf.Close()
		m = tf
	} else {
		return nil, nil, "", fmt.Errorf("%s is neither a code-signature blob nor Mach-O (%v)", path, terr)
	}
	for _, l := range m.Loads {
		raw := l.Raw()
		if len(raw) < 16 || macho.LoadCmd(m.ByteOrder.Uint32(raw[0:4])) != lcCodeSignature {
			continue
		}
		dataoff := int64(m.ByteOrder.Uint32(raw[8:12]))
		datasize := int64(m.ByteOrder.Uint32(raw[12:16]))
		start := base + dataoff
		if start < 0 || datasize <= 0 || start+datasize > int64(len(b)) {
			return nil, nil, "", fmt.Errorf("%s code signature at %#x+%d runs past the file", path, start, datasize)
		}
		return b[start : start+datasize], b[base:start], "macho", nil
	}
	return nil, nil, "", fmt.Errorf("%s has no LC_CODE_SIGNATURE load command", path)
}

// csParseSuperBlob fills the blob table and returns the first CodeDirectory.
func csParseSuperBlob(blob []byte, res *csResult) (*csCodeDirectory, error) {
	if len(blob) < 12 {
		return nil, fmt.Errorf("signature blob is %d bytes, shorter than the SuperBlob header", len(blob))
	}
	if u32be(blob, 0) != csSuperBlobMagic {
		return nil, fmt.Errorf("signature magic is %#08x, not a SuperBlob", u32be(blob, 0))
	}
	length, count := u32be(blob, 4), u32be(blob, 8)
	if length < 12 || uint64(length) > uint64(len(blob)) {
		return nil, fmt.Errorf("SuperBlob declares %d bytes, file holds %d", length, len(blob))
	}
	if count > csMaxBlobs {
		return nil, fmt.Errorf("SuperBlob declares %d blobs", count)
	}
	if 12+int(count)*8 > int(length) {
		return nil, fmt.Errorf("SuperBlob index of %d entries runs past %d bytes", count, length)
	}
	res.Magic, res.Length = "0xfade0cc0", length
	var cd *csCodeDirectory
	for i := range count {
		typ, off := u32be(blob, 12+int(i)*8), u32be(blob, 16+int(i)*8)
		if uint64(off)+8 > uint64(length) {
			return nil, fmt.Errorf("blob %d at %#x runs past the SuperBlob", i, off)
		}
		magic, blen := u32be(blob, int(off)), u32be(blob, int(off)+4)
		if blen < 8 || uint64(off)+uint64(blen) > uint64(length) {
			return nil, fmt.Errorf("blob %d at %#x declares %d bytes past the SuperBlob", i, off, blen)
		}
		name, known := csBlobTypes[typ]
		if !known {
			name = fmt.Sprintf("type-%#x", typ)
		}
		res.Blobs = append(res.Blobs, csBlob{Type: typ, TypeName: name,
			Magic: fmt.Sprintf("%#08x", magic), Offset: off, Length: blen})
		if magic == csCodeDirMagic && cd == nil {
			var err error
			if cd, err = csParseCodeDirectory(blob[off : off+blen]); err != nil {
				return nil, fmt.Errorf("CodeDirectory at %#x: %v", off, err)
			}
		}
	}
	return cd, nil
}

func csParseCodeDirectory(b []byte) (*csCodeDirectory, error) {
	if len(b) < 44 {
		return nil, fmt.Errorf("%d bytes, shorter than the fixed header", len(b))
	}
	cd := &csCodeDirectory{
		Version: u32be(b, 8), Flags: u32be(b, 12), HashOffset: u32be(b, 16),
		SpecialSlots: u32be(b, 24), CodeSlots: u32be(b, 28), CodeLimit: uint64(u32be(b, 32)),
		HashSize: b[36], HashTypeID: b[37],
	}
	identOff := u32be(b, 20)
	name, ok := csString(b, identOff)
	if !ok {
		return nil, fmt.Errorf("identifier at %#x is outside the %d-byte blob", identOff, len(b))
	}
	cd.Identifier = name
	cd.HashType = csHashNames[cd.HashTypeID]
	if cd.HashType == "" {
		cd.HashType = fmt.Sprintf("type-%d", cd.HashTypeID)
	}
	if cd.HashSize == 0 {
		return nil, fmt.Errorf("CodeDirectory has hash size 0")
	}
	pageSize := uint32(1) << b[39]
	if b[39] > 20 || pageSize < 512 {
		return nil, fmt.Errorf("CodeDirectory page size is 2^%d", b[39])
	}
	cd.PageSize = pageSize
	if cd.Version >= 0x20200 {
		if len(b) < 52 {
			return nil, fmt.Errorf("version %#x is shorter than its team id field", cd.Version)
		}
		if teamOff := u32be(b, 48); teamOff != 0 {
			team, ok := csString(b, teamOff)
			if !ok {
				return nil, fmt.Errorf("team id at %#x is outside the blob", teamOff)
			}
			cd.TeamID = team
		}
	}
	if cd.Version >= 0x20300 {
		if len(b) < 64 {
			return nil, fmt.Errorf("version %#x is shorter than its codeLimit64 field", cd.Version)
		}
		// codeLimit64 only carries the limit once the 32-bit field overflows.
		if cd.CodeLimit == 0xFFFFFFFF {
			cd.CodeLimit = u64be(b, 56)
		}
	}
	if uint64(cd.HashOffset)+uint64(cd.CodeSlots)*uint64(cd.HashSize) > uint64(len(b)) {
		return nil, fmt.Errorf("%d code slots at %#x run past the %d-byte blob", cd.CodeSlots, cd.HashOffset, len(b))
	}
	if uint64(cd.SpecialSlots)*uint64(cd.HashSize) > uint64(cd.HashOffset) {
		return nil, fmt.Errorf("%d special slots at %#x precede the blob", cd.SpecialSlots, cd.HashOffset)
	}
	if id := cd.HashTypeID; id >= 1 && id <= 4 {
		cd.CDHash = hex.EncodeToString(csHashFor(id)(b))
	}
	cd.slots = b[cd.HashOffset:][:uint32(cd.CodeSlots)*uint32(cd.HashSize)]
	return cd, nil
}

func csString(b []byte, off uint32) (string, bool) {
	if uint64(off) >= uint64(len(b)) {
		return "", false
	}
	end := bytes.IndexByte(b[off:], 0)
	if end < 0 || end > 512 {
		return "", false
	}
	return string(b[off : int(off)+end]), true
}

func csHashFor(typ uint8) func([]byte) []byte {
	switch typ {
	case 1:
		return func(b []byte) []byte { s := sha1.Sum(b); return s[:] } // NOSONAR Apple CodeDirectory hash type 1 mandates SHA-1; recomputation must match the signed on-disk digest.
	case 2:
		return func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
	case 3:
		return func(b []byte) []byte { s := sha256.Sum256(b); return s[:20] }
	case 4:
		return func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
	}
	return nil
}

// csVerifyPages recomputes every sealed page hash. A mismatch is evidence, so
// it is reported in the result rather than turned into a parse error.
func csVerifyPages(cd *csCodeDirectory, code []byte) csVerify {
	h := csHashFor(cd.HashTypeID)
	if h == nil {
		return csVerify{Reason: "unsupported hash type " + cd.HashType}
	}
	pages := uint32((cd.CodeLimit + uint64(cd.PageSize) - 1) / uint64(cd.PageSize))
	if pages == 0 {
		return csVerify{Reason: "CodeDirectory seals no pages; no page hashes were recomputed"}
	}
	if pages != cd.CodeSlots {
		return csVerify{Reason: fmt.Sprintf("CodeDirectory declares %d slots but the limit covers %d pages", cd.CodeSlots, pages)}
	}
	if cd.CodeLimit > uint64(len(code)) {
		return csVerify{Reason: fmt.Sprintf("code limit %d is past the %d signed bytes", cd.CodeLimit, len(code))}
	}
	v := csVerify{PagesChecked: pages, HashesOK: true}
	for i := range pages {
		start := uint64(i) * uint64(cd.PageSize)
		end := min(start+uint64(cd.PageSize), cd.CodeLimit)
		got := h(code[start:end])
		want := cd.slots[i*uint32(cd.HashSize):][:cd.HashSize]
		if !bytes.Equal(got, want) {
			v.HashesOK = false
			if len(v.Mismatched) < 16 {
				v.Mismatched = append(v.Mismatched, i)
			}
		}
	}
	return v
}
