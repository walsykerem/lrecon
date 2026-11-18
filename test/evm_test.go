package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Synthetic EVM bytecode only: a short dispatcher-shaped prologue plus a CBOR
// metadata trailer written by hand, so the test carries no fixture binary.

var evmTestCode = []byte{
	0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15,
	0x61, 0x00, 0x0a, 0x57, 0x00,
}

// evmTestMeta builds the trailer map Solidity emits: ipfs (34-byte multihash)
// and solc (3 bytes when the input is compact, text otherwise).
func evmTestMeta(solc []byte) []byte {
	b := []byte{0xa2, 0x64, 'i', 'p', 'f', 's', 0x58, 0x22, 0x12, 0x20}
	b = append(b, make([]byte, 32)...)
	b = append(b, 0x64, 's', 'o', 'l', 'c')
	if len(solc) == 3 {
		b = append(b, 0x43)
	} else {
		b = append(b, byte(0x60+len(solc)))
	}
	return append(b, solc...)
}

// evmTestBin appends meta and its big-endian length.
func evmTestBin(code, meta []byte) []byte {
	out := append([]byte{}, code...)
	out = append(out, meta...)
	return append(out, byte(len(meta)>>8), byte(len(meta)))
}

func evmTestProbe(t *testing.T, name string, body []byte) Digest {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return d
}

func evmTestSkipped(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func TestEvmSolcTrailer(t *testing.T) {
	d := evmTestProbe(t, "contract.bin", evmTestBin(evmTestCode, evmTestMeta([]byte{0, 8, 21})))
	if d.Kind != "unknown" || d.Format != "evm" {
		t.Fatalf("kind/format = %q/%q, want unknown/evm (no kind claim)", d.Kind, d.Format)
	}
	if d.Toolchain != "solc 0.8.21" {
		t.Fatalf("toolchain = %q, want solc 0.8.21", d.Toolchain)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 || d.Coverage.Skipped != 0 {
		t.Fatalf("coverage = %+v, want one parsed unit", d.Coverage)
	}
	found := false
	for _, c := range d.Claims {
		if c.Source == "cbor-trailer" && c.Value == evmClaim {
			found = true
		}
	}
	if !found {
		t.Fatalf("claims = %+v, want a cbor-trailer witness", d.Claims)
	}
}

func TestEvmTextSemver(t *testing.T) {
	d := evmTestProbe(t, "contract.bin", evmTestBin(evmTestCode, evmTestMeta([]byte("0.7.6"))))
	if d.Format != "evm" || d.Toolchain != "solc 0.7.6" {
		t.Fatalf("format/toolchain = %q/%q, want evm/solc 0.7.6", d.Format, d.Toolchain)
	}
}

func TestEvmAbsentTrailer(t *testing.T) {
	body := append(append([]byte{}, evmTestCode...), 0xff, 0xff)
	d := evmTestProbe(t, "vyper.bin", body)
	if !evmTestSkipped(d, "no-cbor-metadata") {
		t.Fatalf("skipped = %+v, want no-cbor-metadata", d.Skipped)
	}
	if d.Format == "evm" || d.Toolchain != "" {
		t.Fatalf("format/toolchain = %q/%q, want no version guessed", d.Format, d.Toolchain)
	}
	if d.Coverage == nil || d.Coverage.Skipped == 0 {
		t.Fatalf("coverage = %+v, want a recorded refusal", d.Coverage)
	}
}

func TestEvmLargerThanFile(t *testing.T) {
	meta := evmTestMeta([]byte{0, 8, 21})
	body := append(append([]byte{}, evmTestCode...), meta...)
	declared := len(body) + 8 // fits the spec cap, not the file
	body = append(body, byte(declared>>8), byte(declared))
	d := evmTestProbe(t, "cut.bin", body)
	if !evmTestSkipped(d, "evm-trailer-oob") {
		t.Fatalf("skipped = %+v, want evm-trailer-oob", d.Skipped)
	}
	if d.Format == "evm" || d.Toolchain != "" {
		t.Fatalf("format/toolchain = %q/%q, want no version guessed", d.Format, d.Toolchain)
	}
}

func TestEvmZeroTrailer(t *testing.T) {
	body := append(append([]byte{}, evmTestCode...), evmTestMeta([]byte{0, 8, 21})...)
	body = append(body, 0x00, 0x00)
	d := evmTestProbe(t, "no-metadata.bin", body)
	if !evmTestSkipped(d, "no-cbor-metadata") {
		t.Fatalf("skipped = %+v, want no-cbor-metadata", d.Skipped)
	}
	if d.Format == "evm" || d.Toolchain != "" {
		t.Fatalf("format/toolchain = %q/%q, want no version guessed", d.Format, d.Toolchain)
	}
}

func TestEvmNonCBORFirstByte(t *testing.T) {
	body := append(append([]byte{}, evmTestCode...), 0x01, 0x02, 0x03)
	body = append(body, 0x00, 0x03) // length 3 lands on 0x01, not a map header
	d := evmTestProbe(t, "plain.bin", body)
	if !evmTestSkipped(d, "no-cbor-metadata") {
		t.Fatalf("skipped = %+v, want no-cbor-metadata", d.Skipped)
	}
	if d.Format == "evm" || d.Toolchain != "" {
		t.Fatalf("format/toolchain = %q/%q, want no version guessed", d.Format, d.Toolchain)
	}
}

func TestEvmNegativeStart(t *testing.T) {
	meta := evmTestMeta([]byte{0, 8, 21})
	body := append(append([]byte{}, evmTestCode...), meta...)
	declared := len(body) + 2 // start = -2: the trailer overlaps itself
	body = append(body, byte(declared>>8), byte(declared))
	d := evmTestProbe(t, "overlap.bin", body)
	if !evmTestSkipped(d, "evm-trailer-oob") {
		t.Fatalf("skipped = %+v, want evm-trailer-oob", d.Skipped)
	}
	if d.Format == "evm" || d.Toolchain != "" {
		t.Fatalf("format/toolchain = %q/%q, want no version guessed", d.Format, d.Toolchain)
	}
}

func TestEvmVersionUnverified(t *testing.T) {
	d := evmTestProbe(t, "rc.bin", evmTestBin(evmTestCode, evmTestMeta([]byte("0.8.21-rc1"))))
	if d.Format != "evm" {
		t.Fatalf("format = %q, want evm (map still recognized)", d.Format)
	}
	if d.Toolchain != "" {
		t.Fatalf("toolchain = %q, want no guessed version", d.Toolchain)
	}
	if !evmTestSkipped(d, "evm-version-unverified") {
		t.Fatalf("skipped = %+v, want evm-version-unverified", d.Skipped)
	}
}

// TestEvmTrailerLengthBound pins the bounded-read rule: the declared length is
// checked against the cap and the file before any buffer exists.
func TestEvmTrailerLengthBound(t *testing.T) {
	body := append(append([]byte{}, evmTestCode...), make([]byte, 32)...)
	declared := int(evmMaxMeta + 1)
	body = append(body, byte(declared>>8), byte(declared))
	d := evmTestProbe(t, "huge.bin", body)
	if !evmTestSkipped(d, "no-cbor-metadata") {
		t.Fatalf("skipped = %+v, want no-cbor-metadata above the cap", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Skipped != 1 {
		t.Fatalf("coverage = %+v, want exactly one refusal", d.Coverage)
	}
}
