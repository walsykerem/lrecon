package main

// Dart snapshot reader: the header Dart's own loader checks. The magic is the
// only way in; nothing else in a file is allowed to claim this format.
//
// Layout (runtime/vm/snapshot.h): magic int32 at 0, length int64 at 4 (stored
// without the magic, so the real length is stored+4), kind int64 at 12, header
// 20 bytes. The version hash that follows the header is not mapped to a Dart
// release here, so the digest says so instead of inventing a version.

import (
	"encoding/binary"
	"fmt"
	"os"
)

const (
	dartMagic      = 0xdcdcf5f5
	dartHeaderSize = 20
)

func init() {
	reasonRegistry["dart"] = reasonSet("version-hash-unmapped")
	register(reader{
		format:  "dart",
		reasons: []string{"version-hash-unmapped"},
		post:    true,
		match: func(head []byte, size int64) bool {
			return len(head) >= 4 && binary.LittleEndian.Uint32(head) == dartMagic
		},
		inspect: inspectDartSnapshot,
	})
}

// dartVersionHash is the snapshot's own version string: the MD5 hexdigest of the
// VM sources, 32 ASCII characters written right after the 20-byte header
// (runtime/vm/app_snapshot.cc, tools/make_version.py). Anything else is not a
// version, so a cut or binary tail is refused instead of hex-encoded.
func dartVersionHash(b []byte) string {
	if len(b) < 32 {
		return ""
	}
	for _, c := range b[:32] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return string(b[:32])
}

var dartKinds = map[uint64]string{
	0: "full",
	1: "full-jit",
	2: "full-aot",
	3: "module",
}

func inspectDartSnapshot(path string, d *Digest) {
	// detect.go owns the flutter label; a post reader never renames a file.
	if d.Kind != "flutter" {
		return
	}
	head := head(path, dartHeaderSize)
	if len(head) < dartHeaderSize || binary.LittleEndian.Uint32(head) != dartMagic {
		d.skip("version-hash-unmapped", "snapshot header truncated before length/kind")
		return
	}
	d.scanned(dartHeaderSize)
	rawLen := binary.LittleEndian.Uint64(head[4:12])
	kind := binary.LittleEndian.Uint64(head[12:20])
	kindName, kindOK := dartKinds[kind]

	st, err := os.Stat(path)
	if err != nil {
		d.skip("version-hash-unmapped", "snapshot size unavailable")
		return
	}
	total := rawLen + 4 // the stored length excludes the magic
	if rawLen > uint64(st.Size()) || total < dartHeaderSize || total > uint64(st.Size()) {
		d.skip("version-hash-unmapped", fmt.Sprintf("snapshot length %d outside file size %d", total, st.Size()))
		return
	}
	if !kindOK {
		d.skip("version-hash-unmapped", fmt.Sprintf("snapshot kind %d outside kFull..kModule", kind))
		return
	}
	d.parsed()
	deepNote(d, fmt.Sprintf("dart snapshot: kind=%s, length=%d; version hash not mapped to a release", kindName, total))
}
