package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// maxFuzzInput bounds one sample, so a corpus entry can never ask two readers to
// walk a huge buffer; it also keeps the temp write cheap.
const maxFuzzInput = 64 << 10

// fuzzSeeds are real-format headers: every one takes a different branch of Probe
// (ELF, PE, Mach-O, wasm, sqlite, zip, pcap, asar, lua, text) and reaches at
// least one reader before it has enough bytes.
var fuzzSeeds = [][]byte{
	[]byte("\x7fELF\x02\x01\x01\x00" + "\x00\x00\x00\x00\x00\x00\x00\x00"),
	[]byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00"),
	{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01, 0x03, 0x00, 0x00, 0x00},
	[]byte("\x00asm\x01\x00\x00\x00"),
	[]byte("SQLite format 3\x00" + "\x10\x00\x01\x01\x00@  "),
	[]byte("PK\x03\x04\x14\x00\x00\x00\x00\x00"),
	[]byte("\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
	lua51(),
	[]byte("hello lrecon\n"),
	{},
}

// fuzzOp returns the single op named by LRECON_FUZZ_OP, or nil for the default
// Probe contract. One fuzz session then hammers one reader path instead of the
// whole 64 KiB probe surface.
func fuzzOp(t *testing.F) func(string) (any, error) {
	name := os.Getenv("LRECON_FUZZ_OP")
	if name == "" {
		return nil
	}
	o, ok := ops[name]
	if !ok {
		t.Fatalf("LRECON_FUZZ_OP=%q is not a registered op", name)
	}
	if !o.needs {
		t.Fatalf("LRECON_FUZZ_OP=%q takes no target; fuzzing needs one", name)
	}
	return o.run
}

// FuzzDigest is the permanent contract net: whatever the bytes, Probe must not
// panic, must return no error (every reason is registered), must write exactly
// one JSON document whose size stays bounded, and must keep Text() inside its
// 4096-byte budget with bytes_scanned never above file_size. With
// LRECON_FUZZ_OP set, the same bytes go through that op instead, whose only
// contract is no panic (a refusal is an answer).
func FuzzDigest(f *testing.F) {
	for _, seed := range fuzzSeeds {
		f.Add(seed)
	}
	run := fuzzOp(f)
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > maxFuzzInput {
			t.Skipf("%d bytes over the %d-byte guard", len(b), maxFuzzInput)
		}
		path := filepath.Join(t.TempDir(), "sample.bin")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatalf("write sample: %v", err)
		}
		if run != nil {
			_, _ = run(path)
			return
		}
		d, err := Probe(path)
		if err != nil {
			// A zero-byte target is refused with a typed error: no bytes, no
			// identity. Every other input must digest.
			if len(b) == 0 {
				return
			}
			t.Fatalf("Probe refused a completed digest: %v", err)
		}
		if d.Kind == "" {
			t.Fatal("Kind empty")
		}
		if d.BytesScanned > d.FileSize {
			t.Fatalf("bytes_scanned %d > file_size %d", d.BytesScanned, d.FileSize)
		}
		if text := digestText(d, 4096); len(text) > 4096 {
			t.Fatalf("Text() is %d bytes, budget is 4096", len(text))
		}

		raw, err := json.Marshal(d)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if len(raw) > 1<<20 {
			t.Fatalf("one-sample JSON is %d bytes, unbounded", len(raw))
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		var doc any
		if err := dec.Decode(&doc); err != nil {
			t.Fatalf("stdout is not JSON: %v", err)
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			t.Fatalf("stdout carries more than one JSON document: %v", err)
		}
		for _, s := range d.Skipped {
			if !registeredReason(s.Reason) {
				t.Fatalf("skipped.reason %q is not registered", s.Reason)
			}
		}
	})
}
