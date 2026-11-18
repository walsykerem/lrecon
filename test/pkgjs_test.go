package main

import (
	"encoding/binary"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// runPkgjsReader calls one registered reader directly, which is what claim does
// after the magic switch.
func runPkgjsReader(t *testing.T, format, path string, d *Digest) {
	t.Helper()
	for _, r := range readers {
		if r.format == format {
			claim(r, path, d)
			return
		}
	}
	t.Fatalf("reader %q is not registered", format)
}

func depPairs(d *Digest) []string {
	out := make([]string, len(d.Deps))
	for i, dep := range d.Deps {
		out[i] = dep.Path + "=" + dep.Version
	}
	return out
}

func hasCap(d *Digest, want string) bool {
	return slices.Contains(d.Capabilities, want)
}

func skipReasons(d *Digest) []string {
	out := make([]string, len(d.Skipped))
	for i, s := range d.Skipped {
		out[i] = s.Reason
	}
	return out
}

func hasNote(d *Digest, want string) bool {
	for _, n := range d.Notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

// pkgBuffer builds a host with the four pkg slots patched in place, then a
// payload and the JS prelude, so the position invariant closes at EOF.
func pkgBuffer(payload []byte, prelude string) []byte {
	host := make([]byte, 200)
	slots := []struct {
		key   string
		at    int
		width int
	}{
		{"var PAYLOAD_POSITION = '", 4, 22},
		{"var PAYLOAD_SIZE = '", 50, 18},
		{"var PRELUDE_POSITION = '", 90, 22},
		{"var PRELUDE_SIZE = '", 140, 18},
	}
	for _, s := range slots {
		copy(host[s.at:], s.key)
	}
	payloadPos := int64(len(host))
	preludePos := payloadPos + int64(len(payload))
	vals := []int64{payloadPos, int64(len(payload)), preludePos, int64(len(prelude))}
	for i, s := range slots {
		v := strconv.FormatInt(vals[i], 10)
		copy(host[s.at+len(s.key):], v+strings.Repeat(" ", s.width-len(v)))
	}
	out := append(host, payload...)
	return append(out, prelude...)
}

const pkgPrelude = `const VIRTUAL_FILESYSTEM = {"/app.js":{"0":[0,42]},"/lib/x.js":{"0":[42,100]},"/dir":{}};
const DICT = {};
const SYMLINKS = {};
const DEFAULT_ENTRYPOINT = "/app.js";
const DOCOMPRESS = 0;
`

func TestPkgPayload(t *testing.T) {
	t.Run("vfs yields the file list", func(t *testing.T) {
		p := writeTemp(t, "host.bin", pkgBuffer([]byte{0, 1, 2, 3}, pkgPrelude))
		d := &Digest{Path: p, Kind: "macho"}
		runPkgjsReader(t, "pkg", p, d)
		if d.Kind != "macho" || d.Format != "" {
			t.Fatalf("post reader changed kind/format: %q %q", d.Kind, d.Format)
		}
		if got, want := strings.Join(depPairs(d), "|"), "/app.js=42|/lib/x.js=100"; got != want {
			t.Errorf("deps = %q, want %q", got, want)
		}
		for _, c := range []string{"pkg:files=2", "pkg:payload_offset=200"} {
			if !hasCap(d, c) {
				t.Errorf("missing capability %q in %v", c, d.Capabilities)
			}
		}
		if !hasNote(d, "space-padded overlay") {
			t.Errorf("notes do not describe the patched overlay: %v", d.Notes)
		}
		if !hasNote(d, "default entrypoint: /app.js") {
			t.Errorf("notes do not name the entrypoint: %v", d.Notes)
		}
		if d.Coverage == nil || d.Coverage.Parsed != 1 || d.Coverage.Skipped != 0 {
			t.Errorf("coverage = %+v", d.Coverage)
		}
		if d.BytesScanned != int64(len(pkgPrelude)) {
			t.Errorf("bytes scanned = %d, want %d", d.BytesScanned, len(pkgPrelude))
		}
	})
	t.Run("corrupt vfs is a skip", func(t *testing.T) {
		p := writeTemp(t, "host.bin", pkgBuffer(nil, `const VIRTUAL_FILESYSTEM = {"/app.js":`))
		d := &Digest{Path: p, Kind: "macho"}
		runPkgjsReader(t, "pkg", p, d)
		if got := skipReasons(d); len(got) != 1 || got[0] != "pkg-vfs-invalid" {
			t.Fatalf("skips = %v, want [pkg-vfs-invalid]", got)
		}
		if len(d.Deps) != 0 || len(d.Capabilities) != 0 || d.Coverage == nil || d.Coverage.Parsed != 0 {
			t.Errorf("corrupt vfs still produced output: %+v", d)
		}
	})
	t.Run("broken position invariant is a skip", func(t *testing.T) {
		b := pkgBuffer(nil, pkgPrelude)
		p := writeTemp(t, "host.bin", b[:len(b)-1])
		d := &Digest{Path: p, Kind: "macho"}
		runPkgjsReader(t, "pkg", p, d)
		if got := skipReasons(d); len(got) != 1 || got[0] != "pkg-layout-invalid" {
			t.Fatalf("skips = %v, want [pkg-layout-invalid]", got)
		}
	})
	t.Run("no slot leaves the digest alone", func(t *testing.T) {
		p := writeTemp(t, "host.bin", []byte("\xcf\xfa\xed\xfe"+strings.Repeat("\x00", 60)))
		d := &Digest{Path: p, Kind: "macho"}
		runPkgjsReader(t, "pkg", p, d)
		if d.Coverage != nil || len(d.Skipped) != 0 || d.BytesScanned != 0 {
			t.Errorf("plain host touched: %+v", d)
		}
	})
}

// bunBuffer builds the verified module graph: payload bytes, one 52-byte module
// record, the 32-byte offsets table, then the trailer.
func bunBuffer(entry, contents string) []byte {
	raw := append([]byte(entry), []byte(contents)...)
	modOff := len(raw)
	rec := make([]byte, bunModuleSize)
	binary.LittleEndian.PutUint32(rec[4:], uint32(len(entry)))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(entry)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(contents)))
	rec[48], rec[49], rec[50], rec[51] = 1, 1, 1, 0
	raw = append(raw, rec...)
	tab := make([]byte, 32)
	binary.LittleEndian.PutUint64(tab[0:], uint64(len(raw)))
	binary.LittleEndian.PutUint32(tab[8:], uint32(modOff))
	binary.LittleEndian.PutUint32(tab[12:], bunModuleSize)
	out := append(raw, tab...)
	return append(out, bunTrailer...)
}

func TestBunTrailer(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		entry := "/$bunfs/root/app"
		body := "// @bun\nconsole.log(1);\n"
		d := &Digest{Path: writeTemp(t, "host.bin", bunBuffer(entry, body)), Kind: "macho"}
		runPkgjsReader(t, "bun", d.Path, d)
		if got, want := strings.Join(depPairs(d), "|"), entry+"="+strconv.Itoa(len(body)); got != want {
			t.Errorf("deps = %q, want %q", got, want)
		}
		for _, c := range []string{"bun:modules=1", "bun:bytecode=0", "bun:entry_id=0"} {
			if !hasCap(d, c) {
				t.Errorf("missing capability %q in %v", c, d.Capabilities)
			}
		}
		if d.Coverage == nil || d.Coverage.Parsed != 1 {
			t.Errorf("coverage = %+v", d.Coverage)
		}
	})
	cases := []struct {
		name string
		data []byte
		want string // "" means the digest must stay untouched
	}{
		{"partial trailer, 15 bytes", []byte("\n---- Bun! ----"), "bun-trailer-missing"},
		{"trailer alone, 16 bytes", append([]byte(nil), bunTrailer...), "bun-trailer-unverified"},
		{"trailer plus u64, 24 bytes", append(append([]byte(nil), bunTrailer...), make([]byte, 8)...), "bun-trailer-unverified"},
		{"table window, 32 bytes", append(make([]byte, 16), bunTrailer...), "bun-trailer-unverified"},
		{"full window, 48 bytes", append(make([]byte, 32), bunTrailer...), "bun-trailer-unverified"},
		{"empty window, 48 bytes", make([]byte, 48), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Digest{Path: writeTemp(t, "host.bin", tc.data), Kind: "macho"}
			runPkgjsReader(t, "bun", d.Path, d)
			got := skipReasons(d)
			if tc.want == "" {
				if len(got) != 0 || len(d.Deps) != 0 || d.Coverage != nil {
					t.Fatalf("digest touched: %+v", d)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("skips = %v, want [%s]", got, tc.want)
			}
		})
	}
}

func denoPayloadBytes(body []byte) []byte {
	out := append([]byte(nil), denoMagic...)
	out = append(out, body...)
	return append(out, denoMagic...)
}

func denoEOFBuffer(host, payload []byte) []byte {
	out := append(append([]byte(nil), host...), payload...)
	tail := append([]byte(nil), denoSentinel...)
	tail = append(tail, 0xef, 0xbe, 0xad, 0xde)
	tail = binary.LittleEndian.AppendUint64(tail, uint64(len(payload)))
	return append(out, tail...)
}

func machoHost(cpu uint32) []byte {
	h := make([]byte, 32)
	binary.LittleEndian.PutUint32(h[0:], 0xfeedfacf)
	binary.LittleEndian.PutUint32(h[4:], cpu)
	return h
}

func TestDenoCompileTrailer(t *testing.T) {
	t.Run("amd64 eof sentinel", func(t *testing.T) {
		payload := denoPayloadBytes(make([]byte, 64))
		d := &Digest{Path: writeTemp(t, "host.bin", denoEOFBuffer(machoHost(0x01000007), payload)), Kind: "macho"}
		runPkgjsReader(t, "deno-compile", d.Path, d)
		if !hasCap(d, "deno:carrier=macho-eof-sentinel") {
			t.Errorf("missing carrier in %v", d.Capabilities)
		}
		if !hasCap(d, "deno:payload_bytes="+strconv.Itoa(len(payload))) {
			t.Errorf("missing size in %v", d.Capabilities)
		}
		if d.Coverage == nil || d.Coverage.Parsed != 1 {
			t.Errorf("coverage = %+v", d.Coverage)
		}
	})
	t.Run("payload without the closing magic is a skip", func(t *testing.T) {
		payload := append(append([]byte(nil), denoMagic...), make([]byte, 64)...)
		d := &Digest{Path: writeTemp(t, "host.bin", denoEOFBuffer(machoHost(0x01000007), payload)), Kind: "macho"}
		runPkgjsReader(t, "deno-compile", d.Path, d)
		if got := skipReasons(d); len(got) != 1 || got[0] != "deno-trailer-unverified" {
			t.Fatalf("skips = %v, want [deno-trailer-unverified]", got)
		}
	})
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"header only, 16 bytes", machoHost(0x01000007)[:16], ""},
		{"sentinel without length, 15 bytes", append([]byte(nil), denoSentinel...), ""},
		{"sentinel and marker only, 20 bytes", append(append([]byte(nil), denoSentinel...), 0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0), ""},
		{"length past EOF", func() []byte {
			b := append(append([]byte(nil), machoHost(0x01000007)...), denoSentinel...)
			b = append(b, 0xef, 0xbe, 0xad, 0xde)
			return binary.LittleEndian.AppendUint64(b, 1<<20)
		}(), "deno-trailer-unverified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &Digest{Path: writeTemp(t, "host.bin", tc.data), Kind: "macho"}
			runPkgjsReader(t, "deno-compile", d.Path, d)
			got := skipReasons(d)
			if tc.want == "" {
				if len(got) != 0 || len(d.Capabilities) != 0 || d.Coverage != nil {
					t.Fatalf("digest touched: %+v", d)
				}
				return
			}
			if len(got) != 1 || got[0] != tc.want {
				t.Fatalf("skips = %v, want [%s]", got, tc.want)
			}
		})
	}
	t.Run("arm64 without the __SUI segment leaves no trace", func(t *testing.T) {
		d := &Digest{Path: writeTemp(t, "host.bin", machoHost(0x0100000c)), Kind: "macho"}
		runPkgjsReader(t, "deno-compile", d.Path, d)
		if len(d.Skipped) != 0 || d.Coverage != nil {
			t.Fatalf("plain arm64 host touched: %+v", d)
		}
	})
}

func seaBlob(width int, codePath string, main []byte) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], seaMagic)
	switch width {
	case 9:
		b = append(b, 1) // execArgvExtension
	case 10:
		b = append(b, 1, 1) // execArgvExtension, mainCodeFormat=ESM
	}
	b = binary.LittleEndian.AppendUint64(b, uint64(len(codePath)))
	b = append(b, codePath...)
	b = binary.LittleEndian.AppendUint64(b, uint64(len(main)))
	return append(b, main...)
}

func TestNodeSEAHeader(t *testing.T) {
	for _, width := range []int{8, 9, 10} {
		b := seaBlob(width, "/app/sea.js", []byte("console.log(1)\n"))
		flags, gotWidth, codePath, mainLen, ok := seaHeader(b)
		if !ok || gotWidth != width || codePath != "/app/sea.js" || mainLen != 15 || flags != 0 {
			t.Errorf("width %d: header = %#x %d %q %d %v", width, flags, gotWidth, codePath, mainLen, ok)
		}
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"8 bytes", make([]byte, 8)},
		{"9 bytes", make([]byte, 9)},
		{"10 bytes", make([]byte, 10)},
		{"16 bytes", make([]byte, 16)},
		{"truncated main", seaBlob(8, "/a.js", []byte("0123456789"))[:28]},
		{"flags out of range", append([]byte{0x20, 0xda, 0x43, 0x01, 0x80, 0, 0, 0}, make([]byte, 24)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, ok := seaHeader(tc.data); ok {
				t.Fatalf("header accepted: %x", tc.data)
			}
		})
	}
	t.Run("fuse without a blob is a skip", func(t *testing.T) {
		b := append(machoHost(0x0100000c), []byte(seaFuseStart+"1")...)
		b = append(b, make([]byte, 32)...)
		d := &Digest{Path: writeTemp(t, "host.bin", b), Kind: "macho"}
		runPkgjsReader(t, "node-sea", d.Path, d)
		if got := skipReasons(d); len(got) != 1 || got[0] != "sea-blob-missing" {
			t.Fatalf("skips = %v, want [sea-blob-missing]", got)
		}
	})
}

func TestPkgjsPlainBinaryUntouched(t *testing.T) {
	paths := []string{"/bin/ls", "/usr/bin/env"}
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		for _, format := range []string{"pkg", "bun", "deno-compile", "node-sea"} {
			d := &Digest{Path: p, Kind: "macho", FileSize: st.Size()}
			runPkgjsReader(t, format, p, d)
			if d.Kind != "macho" || d.Format != "" || len(d.Deps) != 0 || len(d.Capabilities) != 0 ||
				len(d.Skipped) != 0 || d.Coverage != nil || d.BytesScanned != 0 {
				t.Errorf("%s on %s touched the digest: %+v", format, p, d)
			}
		}
	}
}
