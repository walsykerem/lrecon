package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// tur7b23HexDumpBytes decodes a nativeHexDump back to bytes, and checks the
// layout while it does: an 8-digit offset per line that really counts from 0.
// A dump whose text looks plausible but is not the file gets caught here.
func tur7b23HexDumpBytes(t *testing.T, dump string) []byte {
	t.Helper()
	var out []byte
	for line := range strings.SplitSeq(strings.TrimSuffix(dump, "\n"), "\n") {
		if line == "" {
			continue
		}
		if len(line) < 11 || line[8:10] != "  " {
			t.Fatalf("hex dump line %q does not start with an 8-digit offset", line)
		}
		if want := fmt.Sprintf("%08x", len(out)); line[:8] != want {
			t.Fatalf("hex dump line %q carries offset %q, want %q for byte %d", line, line[:8], want, len(out))
		}
		body := line[10:]
		if i := strings.Index(body, " |"); i >= 0 {
			body = body[:i]
		}
		for j := 0; j+2 <= len(body); j += 3 {
			cell := body[j : j+2]
			if strings.TrimSpace(cell) == "" {
				continue // padding for a short final row, not a byte
			}
			v, err := strconv.ParseUint(cell, 16, 8)
			if err != nil {
				t.Fatalf("hex dump cell %q in %q: %v", cell, line, err)
			}
			out = append(out, byte(v))
		}
	}
	return out
}

func tur7b23WantASCII(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

// TestTur7Bucket23ReadBytesIsTheFile is the byte-identity test: read_bytes must
// hand back the bytes that are actually at the file offset it names, checked
// against an independent os.ReadFile slice of the same range — never a re-read
// through the tool's own reader, never zero padding.
func TestTur7Bucket23ReadBytesIsTheFile(t *testing.T) {
	elf := buildTarget(t, "linux", "amd64", "bytes23")
	raw, err := os.ReadFile(elf)
	if err != nil {
		t.Fatalf("independent read of %s: %v", elf, err)
	}
	if len(raw) < 1024 {
		t.Fatalf("fixture %s is %d bytes, too small to address", elf, len(raw))
	}
	_, secs, err := nativeSections(elf)
	if err != nil || len(secs) == 0 {
		t.Fatalf("nativeSections(%s) = %d sections, err %v", elf, len(secs), err)
	}
	// A section that starts in the middle of the file: the address mapping has
	// a real section to answer with, so the bytes owe both a section name and
	// the file window behind it.
	var last fileSection
	for _, s := range secs {
		if s.Size > 32 && s.Off > 0 && s.Addr != 0 && s.Off+s.Size <= uint64(len(raw)) {
			last = s
			break
		}
	}
	if last.Size <= 32 {
		t.Fatalf("no file-backed section of usable size in %d sections of %s", len(secs), elf)
	}

	t.Run("wide read at EOF is short, never padded", func(t *testing.T) {
		const n = 64
		at := uint64(len(raw)) - 8
		t.Setenv("LRECON_AT", fmt.Sprintf("%#x", at))
		t.Setenv("LRECON_LEN", strconv.Itoa(n))
		res, err := ops["read_bytes"].run(elf)
		if err != nil {
			t.Fatalf("read_bytes at %#x: %v", at, err)
		}
		m, ok := res.(map[string]any)
		if !ok {
			t.Fatalf("read_bytes returned %T, want the bytes map", res)
		}
		off, ok := m["file_offset"].(uint64)
		if !ok || off != at {
			t.Fatalf("file_offset = %v, want %#x (the address is the file offset)", m["file_offset"], at)
		}
		want := raw[off:]
		if len(want) != 8 {
			t.Fatalf("independent slice at %#x is %d bytes, want 8", off, len(want))
		}
		if got := m["length"]; got != len(want) {
			t.Fatalf("length = %v at %#x with LRECON_LEN=%d; the file tail is %d bytes there, want %d (never zero-filled to %d)",
				got, at, n, len(want), len(want), n)
		}
		if tr, _ := m["truncated"].(bool); !tr {
			t.Fatalf("truncated = %v for a %d-byte read with %d bytes left, want true", m["truncated"], n, len(want))
		}
		dump, _ := m["hex"].(string)
		if got := tur7b23HexDumpBytes(t, dump); !bytes.Equal(got, want) {
			t.Fatalf("hex dump at %#x is not the file: got % x, want % x", off, got, want)
		}
		if got, _ := m["ascii"].(string); got != tur7b23WantASCII(want) {
			t.Fatalf("ascii at %#x = %q, want %q", off, got, tur7b23WantASCII(want))
		}
	})

	t.Run("window inside the section is exactly the file window", func(t *testing.T) {
		at := last.Addr + 8
		t.Setenv("LRECON_AT", fmt.Sprintf("%#x", at))
		t.Setenv("LRECON_LEN", "24")
		res, err := ops["read_bytes"].run(elf)
		if err != nil {
			t.Fatalf("read_bytes at %#x: %v", at, err)
		}
		m := res.(map[string]any)
		off := m["file_offset"].(uint64)
		if want := last.Off + 8; off != want {
			t.Fatalf("file_offset = %#x, want %#x for %s+8", off, want, last.Name)
		}
		want := raw[off : off+24]
		if m["length"] != 24 || m["truncated"] != false {
			t.Fatalf("length/truncated = %v/%v, want 24/false", m["length"], m["truncated"])
		}
		if got := tur7b23HexDumpBytes(t, m["hex"].(string)); !bytes.Equal(got, want) {
			t.Fatalf("hex dump at %#x is not the file: got % x, want % x", off, got, want)
		}
	})

	t.Run("last byte is readable, one past it is refused with the size", func(t *testing.T) {
		size := len(raw)
		t.Setenv("LRECON_AT", fmt.Sprintf("%#x", size-1))
		t.Setenv("LRECON_LEN", "8")
		res, err := ops["read_bytes"].run(elf)
		if err != nil {
			t.Fatalf("read_bytes at the last byte %#x: %v", size-1, err)
		}
		m := res.(map[string]any)
		if m["length"] != 1 || m["truncated"] != true {
			t.Fatalf("length/truncated at the last byte = %v/%v, want 1/true", m["length"], m["truncated"])
		}
		if got := tur7b23HexDumpBytes(t, m["hex"].(string)); !bytes.Equal(got, raw[size-1:]) {
			t.Fatalf("last byte = % x, want % x", got, raw[size-1:])
		}

		// One past EOF names the size: the caller learns how long the file is,
		// so the address can be fixed instead of guessed at.
		t.Setenv("LRECON_AT", fmt.Sprintf("%#x", size))
		res, err = ops["read_bytes"].run(elf)
		if err == nil {
			t.Fatalf("read_bytes at EOF %#x answered %v, want a refusal", size, res)
		}
		if res != nil {
			t.Fatalf("refused read at EOF still returned %v", res)
		}
		msg := err.Error()
		if !strings.Contains(msg, "is not inside any file-backed section or segment") {
			t.Fatalf("EOF refusal %q does not name the mapping gap", msg)
		}
		if !strings.Contains(msg, strconv.Itoa(size)) {
			t.Fatalf("EOF refusal %q does not carry the file size %d", msg, size)
		}
		if want, _ := filepath.Abs(elf); !strings.Contains(msg, want) {
			t.Fatalf("EOF refusal %q does not name %s", msg, want)
		}
	})
}

// TestTur7Bucket23ReadFunctionInstructionsNeverFabricates pins the other half:
// instructions must come from a decompiler that ran, never from the target
// bytes. A text file has no instructions to read, so the answer may only be the
// refusal that names the kind — no envelope, no hex, no byte of the payload
// dressed up as code.
func TestTur7Bucket23ReadFunctionInstructionsNeverFabricates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notes23.txt")
	payload := []byte("not machine code: this file has no instructions to disassemble\n")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	t.Setenv("LRECON_AT", "0x0")
	res, err := ops["read_function_instructions"].run(path)
	if err != nil {
		t.Fatalf("read_function_instructions on a text file returned error %v, want the kind refusal", err)
	}
	s, ok := res.(*skip)
	if !ok {
		t.Fatalf("read_function_instructions on a text file returned %T (%v), want a skip refusal", res, res)
	}
	for _, want := range []string{"text", "no decompiler kind here", "decompiles native code only"} {
		if !strings.Contains(s.Reason, want) {
			t.Fatalf("refusal %q does not name %q", s.Reason, want)
		}
	}
	if strings.Contains(s.Reason, hex.EncodeToString(payload[:16])) {
		t.Fatalf("refusal %q carries target bytes as if they were instructions", s.Reason)
	}
}
