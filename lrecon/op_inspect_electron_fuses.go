package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

const fuseSentinel = "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX"

var fuseNames = []string{
	"RunAsNode",
	"EnableCookieEncryption",
	"EnableNodeOptionsEnvironmentVariable",
	"EnableNodeCliInspectArguments",
	"EnableEmbeddedAsarIntegrityValidation",
	"OnlyLoadAppFromAsar",
	"LoadBrowserProcessSpecificV8Snapshot",
	"GrantFileProtocolExtraPrivileges",
}

func init() {
	registerOp(op{
		name:  "inspect_electron_fuses",
		route: "L",
		needs: true,
		desc:  "locate the Electron fuse wire (sentinel + version + count + per-fuse wire byte) and name every fuse",
		run: func(path string) (any, error) {
			off, w, err := fuseWire(path)
			if err != nil {
				return nil, err
			}
			if w == nil {
				return skipf("%s carries no Electron fuse wire (not an Electron binary)", path), nil
			}
			if len(w) < 2 {
				return nil, fmt.Errorf("%s carries no fuse version byte after the sentinel (truncated wire)", path)
			}
			version, count := w[0], int(w[1])
			if count == 0 || count > 32 {
				return nil, fmt.Errorf("%s fuse wire count must be 1..32, wire declares %d", path, count)
			}
			if len(w) < 2+count {
				return nil, fmt.Errorf("%s fuse wire is not as long as its count declares: %d fuses, %d bytes present", path, count, len(w)-2)
			}
			type fuse struct {
				Index int    `json:"index"`
				Name  string `json:"name"`
				State string `json:"state"`
			}
			res := struct {
				WireOffset int64  `json:"wire_offset"`
				Version    int    `json:"wire_version"`
				Count      int    `json:"fuse_count"`
				Fuses      []fuse `json:"fuses"`
			}{WireOffset: off, Version: int(version), Count: count}
			for k := range count {
				name := fmt.Sprintf("fuse_%d", k+1)
				if k < len(fuseNames) {
					name = fuseNames[k]
				}
				state := "invalid"
				switch w[2+k] {
				case '0':
					state = "disabled"
				case '1':
					state = "enabled"
				case 'r':
					state = "removed"
				}
				res.Fuses = append(res.Fuses, fuse{k + 1, name, state})
			}
			return res, nil
		},
	})
}

// fuseWire streams the file for the fuse sentinel (Electron Framework binaries
// run past the whole-file cap) and returns its offset plus the bytes after it.
func fuseWire(path string) (int64, []byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()
	sent := []byte(fuseSentinel)
	const block = 8 << 20
	buf := make([]byte, block)
	var base int64
	for {
		n, rerr := io.ReadFull(f, buf)
		if n > 0 {
			if i := bytes.Index(buf[:n], sent); i >= 0 {
				at := base + int64(i)
				rest := make([]byte, 40)
				if m, _ := f.ReadAt(rest, at+int64(len(sent))); m > 0 {
					return at, rest[:m], nil
				}
				// The sentinel ends the file: an empty non-nil wire is a
				// truncation the caller must name, not a missing fuse wire.
				return at, rest[:0], nil
			}
		}
		if rerr != nil {
			// A short read is the last chunk and was just scanned, so seeking
			// back by the sentinel length would re-read it forever.
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				return 0, nil, nil
			}
			return 0, nil, rerr
		}
		// Keep the tail so a sentinel split across blocks is still found.
		base += int64(n) - int64(len(sent)-1)
		if _, serr := f.Seek(base, io.SeekStart); serr != nil {
			return 0, nil, serr
		}
	}
}
