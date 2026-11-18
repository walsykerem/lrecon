package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

const opcacheSystemID = "0123456789abcdef0123456789abcdef"

// opcacheFile builds a file-cache file: header padded to hdrSize, then body.
func opcacheFile(hdrSize int, mem, str, timestamp uint64, body []byte) []byte {
	h := make([]byte, hdrSize)
	copy(h, opcacheMagic)
	copy(h[8:40], opcacheSystemID)
	if hdrSize == 60 {
		binary.LittleEndian.PutUint32(h[40:44], uint32(mem))
		binary.LittleEndian.PutUint32(h[44:48], uint32(str))
		binary.LittleEndian.PutUint32(h[52:56], uint32(timestamp))
	} else {
		binary.LittleEndian.PutUint64(h[40:48], mem)
		binary.LittleEndian.PutUint64(h[48:56], str)
		binary.LittleEndian.PutUint64(h[56:64], uint64(hdrSize))
		binary.LittleEndian.PutUint64(h[64:72], timestamp)
	}
	return append(h, body...)
}

func TestOpcacheDigest(t *testing.T) {
	body := bytes.Repeat([]byte{0xAA}, 150)
	cases := []struct {
		name string
		buf  []byte
		skip string
		caps []string
	}{
		{
			name: "lp64 header",
			buf:  opcacheFile(80, 100, 50, 1700000000, body),
			caps: []string{"opcache:system_id=" + opcacheSystemID, "opcache:mem_size=100", "opcache:str_size=50", "opcache:script_timestamp=1700000000"},
		},
		{
			name: "ilp32 header",
			buf:  opcacheFile(60, 10, 5, 1700000123, body[:15]),
			caps: []string{"opcache:mem_size=10", "opcache:str_size=5", "opcache:script_timestamp=1700000123"},
		},
		{
			name: "trailing bytes make the header implausible",
			buf:  append(opcacheFile(80, 100, 50, 1700000000, body), 1, 2, 3),
			skip: "opcache-header-unverified",
		},
		{
			name: "declared body is truncated",
			buf:  opcacheFile(80, 1000, 1000, 1700000000, body),
			skip: "opcache-truncated",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, "script.bin", c.buf))
			if err != nil {
				t.Fatal(err)
			}
			if d.Kind != "php-opcache" {
				t.Fatalf("kind = %q, want php-opcache", d.Kind)
			}
			caps := strings.Join(d.Capabilities, "\n")
			if c.skip != "" {
				if !hasPhpSkip(d, c.skip) {
					t.Fatalf("skipped = %v, want %s", d.Skipped, c.skip)
				}
				if d.Coverage == nil || d.Coverage.Parsed != 0 {
					t.Fatalf("coverage = %+v, want no parsed record", d.Coverage)
				}
				return
			}
			if len(d.Skipped) != 0 {
				t.Fatalf("skipped = %v, want none", d.Skipped)
			}
			for _, want := range c.caps {
				if !strings.Contains(caps, want) {
					t.Fatalf("capabilities %q missing %q", caps, want)
				}
			}
			if d.Coverage == nil || d.Coverage.Parsed != 1 {
				t.Fatalf("coverage = %+v, want one parsed script", d.Coverage)
			}
		})
	}
}

func hasPhpSkip(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

type pharTestEntry struct {
	name string
	data []byte
	// flags are the entry flag bits; 0x1000 marks zlib, 0x2000 bzip2.
	flags uint32
}

// pharArchive builds stub + manifest + contents, with an optional GBMB trailer.
func pharArchive(api uint16, gflags uint32, sig []byte, sigFlag uint32, entries ...pharTestEntry) []byte {
	var content []byte
	content = binary.LittleEndian.AppendUint32(content, uint32(len(entries)))
	content = binary.BigEndian.AppendUint16(content, api)
	content = binary.LittleEndian.AppendUint32(content, gflags)
	content = binary.LittleEndian.AppendUint32(content, 0) // alias length
	content = binary.LittleEndian.AppendUint32(content, 0) // manifest metadata length
	var blob []byte
	for _, e := range entries {
		content = binary.LittleEndian.AppendUint32(content, uint32(len(e.name)))
		content = append(content, e.name...)
		content = binary.LittleEndian.AppendUint32(content, uint32(len(e.data))) // uncompressed
		content = binary.LittleEndian.AppendUint32(content, 1700000000)          // timestamp
		content = binary.LittleEndian.AppendUint32(content, uint32(len(e.data))) // compressed
		content = binary.LittleEndian.AppendUint32(content, 0)                   // crc32
		content = binary.LittleEndian.AppendUint32(content, e.flags)
		content = binary.LittleEndian.AppendUint32(content, 0) // entry metadata length
		blob = append(blob, e.data...)
	}
	out := append([]byte("<?php echo 'x';\n__HALT_COMPILER(); ?>\r\n"), binary.LittleEndian.AppendUint32(nil, uint32(len(content)))...)
	out = append(out, content...)
	out = append(out, blob...)
	if sig != nil {
		out = append(out, sig...)
		out = binary.LittleEndian.AppendUint32(out, sigFlag)
		out = append(out, "GBMB"...)
	}
	return out
}

func TestPharDigest(t *testing.T) {
	cases := []struct {
		name      string
		file      string
		buf       []byte
		skip      string
		deps      []string // path=size
		caps      []string
		noteIn    string
		unclaimed bool
	}{
		{
			name: "stub and manifest list entries",
			file: "plugin.phar",
			buf: pharArchive(0x1000, 0, nil, 0,
				pharTestEntry{name: "a.txt", data: []byte("abc")},
				pharTestEntry{name: "lib/b.bin", data: []byte("defgh"), flags: 0x1000}),
			deps:   []string{"a.txt=3", "lib/b.bin=5"},
			caps:   []string{"phar:api_version=0x1000", "phar:entries=2"},
			noteIn: "zlib=1",
		},
		{
			name: "md5 signature trailer",
			file: "signed.phar",
			buf:  pharArchive(0x1110, 0, make([]byte, 16), 1, pharTestEntry{name: "a.txt", data: []byte("abc")}),
			deps: []string{"a.txt=3"},
			caps: []string{"phar:signature=md5"},
		},
		{
			name: "wrong api version",
			file: "old.phar",
			buf:  pharArchive(0x0F00, 0, nil, 0, pharTestEntry{name: "a.txt", data: []byte("abc")}),
			skip: "phar-api-version-unverified",
		},
		{
			name: "whole-file compression flag",
			file: "whole.phar",
			buf:  pharArchive(0x1000, 0x00100000, nil, 0, pharTestEntry{name: "a.txt", data: []byte("abc")}),
			skip: "phar-whole-file-compressed",
		},
		{
			name: "signature length disagrees with contents",
			file: "short-sig.phar",
			buf:  pharArchive(0x1000, 0, []byte{1, 2}, 1, pharTestEntry{name: "a.txt", data: []byte("abc")}),
			skip: "phar-signature-length-mismatch",
		},
		{
			name:      "missing terminator is not claimed",
			file:      "plain.phar",
			buf:       []byte("<?php echo 1; ?>"),
			unclaimed: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, err := Probe(writeTemp(t, c.file, c.buf))
			if err != nil {
				t.Fatal(err)
			}
			if c.unclaimed {
				if d.Format == "phar" || len(d.Deps) != 0 || len(d.Skipped) != 0 {
					t.Fatalf("claimed a stubless file: format=%q deps=%v skipped=%v", d.Format, d.Deps, d.Skipped)
				}
				return
			}
			if d.Format != "phar" {
				t.Fatalf("format = %q, want phar", d.Format)
			}
			if c.skip != "" {
				if !hasPhpSkip(d, c.skip) {
					t.Fatalf("skipped = %v, want %s", d.Skipped, c.skip)
				}
				return
			}
			if len(d.Skipped) != 0 {
				t.Fatalf("skipped = %v, want none", d.Skipped)
			}
			var got []string
			for _, dep := range d.Deps {
				got = append(got, dep.Path+"="+dep.Version)
			}
			if strings.Join(got, ",") != strings.Join(c.deps, ",") {
				t.Fatalf("deps = %v, want %v", got, c.deps)
			}
			caps := strings.Join(d.Capabilities, "\n")
			for _, want := range c.caps {
				if !strings.Contains(caps, want) {
					t.Fatalf("capabilities %q missing %q", caps, want)
				}
			}
			if c.noteIn != "" && !strings.Contains(strings.Join(d.Notes, "\n"), c.noteIn) {
				t.Fatalf("notes %v missing %q", d.Notes, c.noteIn)
			}
			if d.Coverage == nil || d.Coverage.Parsed != 1 {
				t.Fatalf("coverage = %+v, want one parsed archive", d.Coverage)
			}
		})
	}
}
