package main

// The CodeDirectory below version 0x20300 keeps codeLimit in one 32-bit field.
// From 0x20300 on, that field may be 0xFFFFFFFF and the real limit moves to
// codeLimit64, so a reader that ignores the shift reports a 4 GiB image. This
// test builds a SuperBlob by hand: an 8-byte Entitlements blob first in the
// index (the CodeDirectory is second), sha384 hashes, and a codeLimit32 that is
// all ones. Every asserted value is written here, never read back from the
// parser. The two mutations are container metadata: a slot count that claims
// more hashes than the blob holds, and a file cut below the declared SuperBlob
// length. Both must be refusals, not a half-filled result.

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// tur7CodeDirectory writes a version 0x20300 CodeDirectory with two special
// slots, sha384 hashes over 512-byte pages, and codeLimit32 = 0xFFFFFFFF while
// codeLimit64 carries 3000.
func tur7CodeDirectory(ident, team string, codeSlots uint32) []byte {
	const hashSize, special, idOff = 48, 2, 96
	teamOff := idOff + len(ident) + 1
	hashOff := teamOff + len(team) + 1
	b := make([]byte, hashOff+int(codeSlots)*hashSize)
	binary.BigEndian.PutUint32(b[0:], csCodeDirMagic)
	binary.BigEndian.PutUint32(b[4:], uint32(len(b)))
	binary.BigEndian.PutUint32(b[8:], 0x20300)
	binary.BigEndian.PutUint32(b[12:], 0x2)
	binary.BigEndian.PutUint32(b[16:], uint32(hashOff))
	binary.BigEndian.PutUint32(b[20:], idOff)
	binary.BigEndian.PutUint32(b[24:], special)
	binary.BigEndian.PutUint32(b[28:], codeSlots)
	binary.BigEndian.PutUint32(b[32:], 0xFFFFFFFF)
	b[36], b[37], b[39] = hashSize, 4, 9 // sha384 over 2^9-byte pages
	binary.BigEndian.PutUint32(b[48:], uint32(teamOff))
	binary.BigEndian.PutUint64(b[56:], 3000)
	copy(b[idOff:], ident+"\x00")
	copy(b[teamOff:], team+"\x00")
	return b
}

// tur7SuperBlob wraps the CodeDirectory behind a 8-byte Entitlements blob.
func tur7SuperBlob(cd []byte) []byte {
	const entLen, index = 8, 12 + 2*8
	sig := make([]byte, index+entLen+len(cd))
	binary.BigEndian.PutUint32(sig[0:], csSuperBlobMagic)
	binary.BigEndian.PutUint32(sig[4:], uint32(len(sig)))
	binary.BigEndian.PutUint32(sig[8:], 2)
	binary.BigEndian.PutUint32(sig[12:], 5) // Entitlements
	binary.BigEndian.PutUint32(sig[16:], index)
	binary.BigEndian.PutUint32(sig[20:], 0) // CodeDirectory, second slot
	binary.BigEndian.PutUint32(sig[24:], index+entLen)
	binary.BigEndian.PutUint32(sig[index:], 0xfade7171)
	binary.BigEndian.PutUint32(sig[index+4:], entLen)
	copy(sig[index+entLen:], cd)
	return sig
}

func TestTur7Bucket17SignatureCodeLimit(t *testing.T) {
	const ident, team = "com.tur7.container", "TUR7TEAM01"
	cd := tur7CodeDirectory(ident, team, 2)
	sig := tur7SuperBlob(cd)

	m := reaDataJSON(t, "inspect_signature", a10Write(t, "tur7.sig", sig))
	if m["source"] != "superblob" || m["magic"] != "0xfade0cc0" || m["length"] != float64(len(sig)) {
		t.Fatalf("header = %v, want the superblob fields written at bytes 0-7", m)
	}
	if n := a10Num(t, m, "blobs", 1, "offset"); n != float64(12+2*8+8) {
		t.Fatalf("CodeDirectory blob offset = %v, want %d", n, 12+2*8+8)
	}
	if name := a10Get(t, m, "blobs", 0, "type_name"); name != "Entitlements" {
		t.Fatalf("blobs[0].type_name = %v, want Entitlements", name)
	}
	if name := a10Get(t, m, "blobs", 1, "type_name"); name != "CodeDirectory" {
		t.Fatalf("blobs[1].type_name = %v, want CodeDirectory", name)
	}
	if n := a10Num(t, m, "code_directory", "code_limit"); n != 3000 {
		t.Fatalf("code_limit = %v, want 3000 from codeLimit64 (codeLimit32 is all ones)", n)
	}
	if n := a10Num(t, m, "code_directory", "version"); n != 0x20300 {
		t.Fatalf("version = %v, want 0x20300", n)
	}
	if s := a10Get(t, m, "code_directory", "identifier"); s != ident {
		t.Fatalf("identifier = %v, want %q", s, ident)
	}
	if s := a10Get(t, m, "code_directory", "team_id"); s != team {
		t.Fatalf("team_id = %v, want %q", s, team)
	}
	if s := a10Get(t, m, "code_directory", "hash_type"); s != "sha384" {
		t.Fatalf("hash_type = %v, want sha384", s)
	}
	if n := a10Num(t, m, "code_directory", "page_size"); n != 512 {
		t.Fatalf("page_size = %v, want 512 (2^9)", n)
	}
	if n := a10Num(t, m, "code_directory", "special_slots"); n != 2 {
		t.Fatalf("special_slots = %v, want 2", n)
	}
	// The cdhash is the sha384 of the directory blob itself; recompute it here
	// so a canned 64/96-char string cannot pass.
	sum := sha512.Sum384(cd)
	if got := a10Get(t, m, "code_directory", "cdhash"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("cdhash = %v, want sha384 of the written directory %x", got, sum)
	}
	if v := a10Get(t, m, "verification", "reason"); !strings.Contains(v.(string), "bare signature blob") {
		t.Fatalf("verification reason = %v, want the bare-blob refusal", v)
	}

	// Mutation 1: the slot count is container metadata. Two real slots become
	// forty, so the hash array no longer fits in the blob the header declared.
	bad := tur7CodeDirectory(ident, team, 2)
	binary.BigEndian.PutUint32(bad[28:], 40)
	sig = tur7SuperBlob(bad)
	_, err := runOp("inspect_signature", a10Write(t, "slots.sig", sig))
	if err == nil || !strings.Contains(err.Error(), "code slots at") || !strings.Contains(err.Error(), "run past the") {
		t.Fatalf("slot overflow error = %v, want a past-the-blob refusal", err)
	}

	// Mutation 2: cut the file one byte below the SuperBlob length the header
	// declares; the tail of the directory is gone, so the parse must fail.
	cd = tur7CodeDirectory(ident, team, 2)
	sig = tur7SuperBlob(cd)
	_, err = runOp("inspect_signature", a10Write(t, "cut.sig", sig[:len(sig)-1]))
	if err == nil || !strings.Contains(err.Error(), "SuperBlob declares") || !strings.Contains(err.Error(), "file holds") {
		t.Fatalf("truncation error = %v, want a declared-length refusal", err)
	}
}
