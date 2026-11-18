package main

import (
	"fmt"
	"os"
)

// final.md 82: read_bytes.
func init() {
	registerOp(op{
		name:  "read_bytes",
		route: "L",
		desc:  "hex+ASCII dump of LRECON_LEN bytes (default 256) at LRECON_AT, addressed as a virtual address",
		needs: true,
		run: func(path string) (any, error) {
			at, err := nativeAddrArg()
			if err != nil {
				return nil, err
			}
			n, err := nativeEnvUint("LRECON_LEN", 256, 1<<16)
			if err != nil {
				return nil, err
			}
			abs, err := absTarget(path)
			if err != nil {
				return nil, err
			}
			_, secs, err := nativeSections(abs)
			if err != nil {
				return nil, err
			}
			off, sec := fileOffsetFor(secs, at)
			mapping, section, basis := "section", "", "virtual_address"
			if sec == nil {
				if segs, serr := nativeSegments(abs); serr == nil {
					if sg := sectionFor(segs, at); sg != nil {
						sec, mapping = sg, "segment"
						off = sg.Off + (at - sg.Addr)
					}
				}
			}
			if sec == nil {
				// No section and no segment names this address. A raw file
				// offset is still readable, but only when the file is that
				// long: an answer saying length=0, truncated=true for an
				// address past EOF hides the mistake behind a success exit.
				st, serr := os.Stat(abs)
				if serr == nil && at >= uint64(st.Size()) {
					return nil, fmt.Errorf("address %s is not inside any file-backed section or segment, and %s is only %d bytes", nativeHexAddr(at), abs, st.Size())
				}
				off, mapping, basis = at, "file_offset", "file_offset"
			} else {
				section = sec.Name
			}
			b, err := nativeReadAt(abs, off, n)
			if err != nil {
				return nil, err
			}
			return map[string]any{
				"address":     nativeHexAddr(at),
				"file_offset": off,
				"section":     section,
				"mapping":     mapping,
				"basis":       basis,
				"length":      len(b),
				"truncated":   uint64(len(b)) < n,
				"hex":         nativeHexDump(b),
				"ascii":       nativeASCII(b),
			}, nil
		},
	})
}
