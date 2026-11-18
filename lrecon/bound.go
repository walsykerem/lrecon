package main

import "fmt"

// allocCeilCeiling is the spec max per digest field. A declared length above it
// is refused: the reader never allocates a buffer the format forbids.
var allocCeilCeiling = map[string]int64{
	"asar":      maxAsarHeader,
	"asar-body": maxExtract, // a member body is an extraction payload, not header JSON
	"beam":      beamMaxRead,
	"ocaml":     1 << 20, // TOC is num*8, so this is 131072 sections
	"pcap":      4 << 20, // one pcapng block; a real snaplen stops at 256 KiB
	"pe":        maxPEHeader,
	"rlib":      rlibNameTable,
	"v8cache":   v8cacheMaxHeader,
}

// allocCeil is the only place a declared length becomes an allocation. limit is
// the declared length; a field with no spec max is refused too.
func allocCeil(d *Digest, field string, limit int64, reason string) ([]byte, bool) {
	ceil, known := allocCeilCeiling[field]
	if !known || limit < 0 || limit > ceil {
		d.skip(reason, fmt.Sprintf("%s: declared %d > %d", field, limit, ceil))
		return nil, false
	}
	return make([]byte, limit), true
}
