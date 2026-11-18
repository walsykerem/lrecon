package main

import (
	"bytes"
	"os"
)

// A Go build carries one build-info blob and a build-id note in the image, and
// native.go already read them during Probe. This op reports that answer; it does
// not open a second parser, so "not a Go build" can never come from a different
// set of bytes than the digest's own producer string.
func init() {
	registerOp(op{
		name:  "inspect_go_binary",
		route: "L",
		needs: true,
		desc:  "Go build-info: toolchain, main module, module deps and pclntab name count",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			switch d.Kind {
			case "elf", "macho", "pe":
			default:
				return skipf("%s: %s is not a native image; a Go build-info blob lives in ELF, Mach-O or PE", path, d.Kind), nil
			}
			if !isGoBinary(path) && !hasMarker(path, goBuildIDMarker, maxGoInfoScan) {
				return skipf("%s: %s carries no Go build-info blob or build id; not a Go build", path, d.Kind), nil
			}
			return struct {
				Kind      string `json:"kind"`
				Toolchain string `json:"toolchain"`
				Module    string `json:"module,omitempty"`
				Deps      []Dep  `json:"deps"`
				Names     string `json:"names"`
			}{d.Kind, d.Toolchain, d.Mod, d.Deps, d.Names}, nil
		},
	})
}

// hasMarker answers bytes.Contains(head(path, max), marker) with a fixed 64 KiB
// window, so a refusal on a large non-Go image costs 64 KiB of memory instead
// of a copy of the whole scanned prefix. A read error means "no marker", the
// same answer head() gives when it cannot open the file.
func hasMarker(path string, marker []byte, max int64) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	const win = 64 << 10
	// A marker longer than 64 bytes would need a declared allocation; the only
	// caller passes goBuildIDMarker, so refuse rather than grow the pin.
	if len(marker) == 0 || len(marker) > 64 {
		return false
	}
	var buf [win + 63]byte
	keep := 0
	var read int64
	for read < max {
		want := win
		if rem := max - read; rem < int64(want) {
			want = int(rem)
		}
		n, err := f.Read(buf[keep : keep+want])
		if n > 0 {
			read += int64(n)
			if bytes.Contains(buf[:keep+n], marker) {
				return true
			}
			keep = copy(buf[:], buf[keep+n-min(keep+n, len(marker)-1):keep+n])
		}
		if err != nil {
			return false
		}
	}
	return false
}
