package main

import (
	"strings"
	"testing"
)

// Crafted bytes only: the fixtures are the wasm grammar, not a compiler's
// output, so each test proves the exact field the reader is allowed to claim.

func wasmLeb(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			b |= 0x80
		}
		out = append(out, b)
		if v == 0 {
			return out
		}
	}
}

func wasmName(s string) []byte {
	return append(wasmLeb(uint32(len(s))), s...)
}

func wasmSection(id byte, parts ...[]byte) []byte {
	var payload []byte
	for _, p := range parts {
		payload = append(payload, p...)
	}
	out := []byte{id}
	out = append(out, wasmLeb(uint32(len(payload)))...)
	return append(out, payload...)
}

func wasmSub(id byte, payload []byte) []byte {
	out := []byte{id}
	out = append(out, wasmLeb(uint32(len(payload)))...)
	return append(out, payload...)
}

func wasmHead() []byte { return []byte("\x00asm\x01\x00\x00\x00") }

func wasmProducersSection(field, tool, version string) []byte {
	return wasmSection(0,
		wasmName("producers"),
		wasmLeb(1), wasmName(field),
		wasmLeb(1), wasmName(tool), wasmName(version),
	)
}

func wasmCapVersion(d Digest, tool string) string {
	for _, c := range d.Capabilities {
		if after, ok := strings.CutPrefix(c, "wasm:"+tool+"="); ok {
			return after
		}
	}
	return ""
}

func wasmHasSkip(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func TestWasmProducersMinimal(t *testing.T) {
	mod := append(wasmHead(), wasmProducersSection("processed-by", "clang", "17.0.0")...)
	d, err := Probe(writeTemp(t, "mod.wasm", mod))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "wasm" || d.Format != "v1" {
		t.Fatalf("kind/format = %q/%q, want wasm/v1", d.Kind, d.Format)
	}
	if got := wasmCapVersion(d, "clang"); got != "17.0.0" {
		t.Fatalf("clang version = %q, want exactly 17.0.0 (capabilities %+v)", got, d.Capabilities)
	}
	if wasmHasSkip(d, "wasm-producer-absent") {
		t.Fatalf("producer section present but reported absent: %+v", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("coverage = %+v, want one parsed section", d.Coverage)
	}
}

func TestWasmNameSection(t *testing.T) {
	module := wasmName("demo")
	funcs := append(wasmLeb(2), append(append(wasmLeb(0), wasmName("add")...), append(wasmLeb(1), wasmName("mul")...)...)...)
	sec := wasmSection(0,
		wasmName("name"),
		wasmSub(0, module),
		wasmSub(1, funcs),
	)
	d, err := Probe(writeTemp(t, "named.wasm", append(wasmHead(), sec...)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Mod != "demo" {
		t.Fatalf("module name = %q, want demo", d.Mod)
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "wasm function: add") || !strings.Contains(notes, "wasm function: mul") {
		t.Fatalf("function names missing: %q", notes)
	}
}

func TestWasmNameCap(t *testing.T) {
	funcs := wasmLeb(wasmMaxNames + 5)
	for i := range wasmMaxNames + 5 {
		funcs = append(funcs, wasmLeb(uint32(i))...)
		funcs = append(funcs, wasmName("fn")...)
	}
	sec := wasmSection(0, wasmName("name"), wasmSub(1, funcs))
	d, err := Probe(writeTemp(t, "many.wasm", append(wasmHead(), sec...)))
	if err != nil {
		t.Fatal(err)
	}
	if !wasmHasSkip(d, "wasm-too-many-names") {
		t.Fatalf("cap not reported: %+v", d.Skipped)
	}
	if n := strings.Count(strings.Join(d.Notes, "\n"), "wasm function:"); n != wasmMaxNames {
		t.Fatalf("kept %d function names, want cap %d", n, wasmMaxNames)
	}
}

func TestWasmTruncatedSection(t *testing.T) {
	mod := append(wasmHead(), wasmSection(2, wasmLeb(32), []byte{1, 2})...)
	d, err := Probe(writeTemp(t, "short.wasm", mod))
	if err != nil {
		t.Fatal(err)
	}
	if !wasmHasSkip(d, "wasm-truncated") {
		t.Fatalf("truncated section not reported: %+v", d.Skipped)
	}
}

func TestWasmLEB128(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want uint32
		ok   bool
	}{
		{"zero", []byte{0x00}, 0, true},
		{"max", []byte{0xff, 0xff, 0xff, 0xff, 0x0f}, 0xffffffff, true},
		{"overlong six bytes", []byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x00}, 0, false},
		{"five-byte overflow", []byte{0xff, 0xff, 0xff, 0xff, 0x7f}, 0, false},
		{"no terminator", []byte{0x80, 0x80, 0x80, 0x80, 0x80}, 0, false},
		{"empty", nil, 0, false},
	}
	for _, tc := range cases {
		c := &wasmCursor{b: tc.b}
		got, ok := c.u32()
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s: u32 = (%#x,%v), want (%#x,%v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
}

func TestWasmUnverifiedVersion(t *testing.T) {
	mod := append([]byte("\x00asm\x02\x00\x00\x00"), wasmProducersSection("processed-by", "clang", "17.0.0")...)
	d, err := Probe(writeTemp(t, "v2.wasm", mod))
	if err != nil {
		t.Fatal(err)
	}
	if !wasmHasSkip(d, "wasm-version-unverified") {
		t.Fatalf("version 2 not refused: %+v", d.Skipped)
	}
	if len(d.Deps) != 0 {
		t.Fatalf("guessed a producer from an unverified grammar: %+v", d.Deps)
	}
}

func TestWasmNonMagic(t *testing.T) {
	d, err := Probe(writeTemp(t, "not.wasm", []byte("hello, not wasm\n")))
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind == "wasm" {
		t.Fatalf("non-wasm head claimed as wasm")
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "wasm-") {
			t.Fatalf("wasm reader ran on non-wasm: %+v", s)
		}
	}
}
