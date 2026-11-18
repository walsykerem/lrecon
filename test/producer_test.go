package main

import (
	"encoding/binary"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// elfWithComment builds a minimal ELF64 object whose only content section is
// .comment, so producer tests never depend on a toolchain being installed.
func elfWithComment(t *testing.T, comment string) []byte {
	t.Helper()
	strtab := []byte("\x00.comment\x00.shstrtab\x00")
	const ehdr = 64
	dataOff := ehdr
	strOff := dataOff + len(comment)
	shoff := (strOff + len(strtab) + 7) &^ 7
	b := make([]byte, shoff+3*64)
	le := binary.LittleEndian
	copy(b, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	le.PutUint16(b[16:], 1)  // ET_REL
	le.PutUint16(b[18:], 62) // x86-64
	le.PutUint32(b[20:], 1)
	le.PutUint64(b[40:], uint64(shoff))
	le.PutUint16(b[52:], ehdr)
	le.PutUint16(b[58:], 64)
	le.PutUint16(b[60:], 3)
	le.PutUint16(b[62:], 2)
	copy(b[dataOff:], comment)
	copy(b[strOff:], strtab)
	section := func(i int, name, typ uint32, off, size, align uint64) {
		p := b[shoff+i*64:]
		le.PutUint32(p[0:], name)
		le.PutUint32(p[4:], typ)
		le.PutUint64(p[24:], off)
		le.PutUint64(p[32:], size)
		le.PutUint64(p[48:], align)
	}
	section(1, 1, 1, uint64(dataOff), uint64(len(comment)), 1) // .comment
	section(2, 10, 3, uint64(strOff), uint64(len(strtab)), 1)
	return b
}

func hasReason(d Digest, want string) bool {
	for _, s := range d.Skipped {
		if s.Reason == want {
			return true
		}
	}
	return false
}

// peWithDebug builds a PE32+ image that records clang in a CodeView
// .debug$S payload; nil payload leaves just the linker version in the header.
func peWithDebug(payload []byte) []byte {
	const (
		peOff  = 0x40
		optOff = peOff + 4 + 20
		secOff = optOff + 240
		rawOff = 0x200
	)
	nsec := 0
	if payload != nil {
		nsec = 1
	}
	b := make([]byte, rawOff+len(payload))
	le := binary.LittleEndian
	copy(b, "MZ")
	le.PutUint32(b[0x3c:], peOff)
	copy(b[peOff:], "PE\x00\x00")
	coff := b[peOff+4:]
	le.PutUint16(coff[0:], 0x8664)
	le.PutUint16(coff[2:], uint16(nsec))
	le.PutUint16(coff[16:], 240)
	le.PutUint16(coff[18:], 0x22)
	opt := b[optOff:]
	le.PutUint16(opt[0:], 0x20b)
	opt[2], opt[3] = 14, 29 // MajorLinkerVersion, MinorLinkerVersion
	le.PutUint16(opt[68:], 3)
	le.PutUint32(opt[108:], 16)
	if nsec == 1 {
		sec := b[secOff:]
		copy(sec, ".debug$S")
		le.PutUint32(sec[8:], uint32(len(payload)))
		le.PutUint32(sec[12:], 0x1000)
		le.PutUint32(sec[16:], uint32(len(payload)))
		le.PutUint32(sec[20:], rawOff)
		le.PutUint32(sec[36:], 0x40000040)
		copy(b[rawOff:], payload)
	}
	return b
}

func producerDigest(t *testing.T, kind string, b []byte) Digest {
	t.Helper()
	d := Digest{Kind: kind}
	dispatchPost(writeTemp(t, "producer.bin", b), b, int64(len(b)), &d)
	return d
}

func TestProducerClassify(t *testing.T) {
	cases := []struct {
		in     string
		value  string
		family string
		ok     bool
	}{
		{"GCC: (GNU) 13.2.0", "gcc 13.2.0", "gcc", true},
		{"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0", "gcc 11.4.0", "gcc", true},
		{"GNU C17 13.2.0 -mtune=generic -march=x86-64 -g -O2", "gcc 13.2.0", "gcc", true},
		{"clang version 17.0.0 (https://github.com/llvm/llvm-project.git)", "clang 17.0.0", "clang", true},
		{"Apple clang version 15.0.0 (clang-1500.3.9.4)", "clang 15.0.0", "clang", true},
		// Rust's producer starts with clang, Swift's embeds a clang- version:
		// both must be named before clang is considered.
		{"clang LLVM (rustc version 1.75.0)", "rustc 1.75.0", "rustc", true},
		{"Apple Swift version 5.9.2 (swiftlang-5.9.2.2.56 clang-1500.3.9.4)", "swift 5.9.2", "swift", true},
		{"zig 0.11.0", "zig 0.11.0", "zig", true},
		{"zig version 0.12.0", "zig 0.12.0", "zig", true},
		{"ziglang", "zig (version not recorded)", "zig", true},
		{"Microsoft (R) C/C++ Optimizing Compiler Version 19.29.30153 for x64", "msvc 19.29.30153", "msvc", true},
		// Markers and shapes are not producers: no version, no candidate.
		{"lib/std/start.zig", "", "", false},
		{"builtin.default_panic", "", "", false},
		{"start.zig", "", "", false},
		{"DW.ref.rust_eh_personality", "", "", false},
		{".gcc_except_table", "", "", false},
	}
	for _, c := range cases {
		value, family, ok := classifyProducer(c.in)
		if ok != c.ok || value != c.value || family != c.family {
			t.Errorf("classify(%q) = %q/%q/%v, want %q/%q/%v", c.in, value, family, ok, c.value, c.family, c.ok)
		}
	}
}

// TestZigProducerOnlyFromRecordedString: Zig has no magic. A file that only
// looks Zig-shaped (start.zig, lib/std paths, panic markers) must not name Zig.
func TestZigProducerOnlyFromRecordedString(t *testing.T) {
	markers := "lib/std/start.zig\x00start.zig\x00builtin.default_panic\x00"
	d := producerDigest(t, "elf", elfWithComment(t, markers))
	if d.Toolchain != "" {
		t.Fatalf("toolchain = %q, want none from markers alone", d.Toolchain)
	}
	if !hasReason(d, "producer-not-recorded") {
		t.Fatalf("skipped = %+v, want producer-not-recorded", d.Skipped)
	}

	d = producerDigest(t, "elf", elfWithComment(t, "zig 0.11.0\x00"))
	if d.Toolchain != "zig 0.11.0" {
		t.Fatalf("toolchain = %q, want zig 0.11.0", d.Toolchain)
	}
	if len(d.Claims) != 1 || d.Claims[0].Value != "zig 0.11.0" {
		t.Fatalf("claims = %+v, want one zig claim", d.Claims)
	}
	joined := strings.Join(d.Notes, "\n")
	if !strings.Contains(joined, "elf:.comment") {
		t.Fatalf("notes = %v, want the mechanism named", d.Notes)
	}
}

func TestProducerDedupesRepeatedStrings(t *testing.T) {
	d := producerDigest(t, "elf", elfWithComment(t, "GCC: (GNU) 13.2.0\x00GCC: (GNU) 13.2.0\x00"))
	if d.Toolchain != "gcc 13.2.0" {
		t.Fatalf("toolchain = %q, want gcc 13.2.0", d.Toolchain)
	}
	if len(d.Claims) != 1 {
		t.Fatalf("claims = %+v, want one deduplicated claim", d.Claims)
	}
}

func TestProducerKeepsExistingToolchain(t *testing.T) {
	d := Digest{Kind: "elf", Toolchain: "go1.26.5 darwin/arm64"}
	dispatchPost(writeTemp(t, "go.bin", elfWithComment(t, "GCC: (GNU) 13.2.0\x00")), nil, 0, &d)
	if d.Toolchain != "go1.26.5 darwin/arm64" {
		t.Fatalf("toolchain = %q, want the Go answer kept", d.Toolchain)
	}
	if len(d.Claims) != 0 {
		t.Fatalf("claims = %+v, want none against a named toolchain", d.Claims)
	}
}

// TestProducerSilentWithoutRecord: absence of a producer container is not a
// refusal; only a container that fails to name a family is.
func TestProducerRefusesWithoutRecord(t *testing.T) {
	d := producerDigest(t, "elf", elfWithComment(t, ""))
	if d.Toolchain != "" || !hasReason(d, "producer-not-recorded") {
		t.Fatalf("toolchain/skipped = %q/%+v, want producer-not-recorded", d.Toolchain, d.Skipped)
	}
}

func TestProducerPE(t *testing.T) {
	d := producerDigest(t, "pe", peWithDebug(nil))
	if d.Toolchain != "linker 14.29" {
		t.Fatalf("toolchain = %q, want the recorded linker version", d.Toolchain)
	}
	if !strings.Contains(strings.Join(d.Notes, "\n"), "pe:LinkerVersion") {
		t.Fatalf("notes = %v, want pe:LinkerVersion", d.Notes)
	}

	d = producerDigest(t, "pe", peWithDebug([]byte("\x00\x00clang version 17.0.0\x00\x00")))
	if d.Toolchain != "clang 17.0.0" {
		t.Fatalf("toolchain = %q, want clang 17.0.0 from .debug$S", d.Toolchain)
	}
	for _, note := range d.Notes {
		if strings.Contains(note, "pe:.debug$s") {
			return
		}
	}
	t.Fatalf("notes = %v, want pe:.debug$s named", d.Notes)
}

func TestProducerCLIJSON(t *testing.T) {
	type skip struct {
		Reason string `json:"reason"`
	}
	type doc struct {
		Kind      string `json:"kind"`
		Toolchain string `json:"toolchain"`
		Plan      string `json:"plan"`
		Skipped   []skip `json:"skipped"`
	}
	decode := func(t *testing.T, path string) doc {
		t.Helper()
		out, code := runCLI(t, "--json", path)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("json: %v\n%s", err, out)
		}
		return d
	}

	gcc := writeTemp(t, "gcc.o", elfWithComment(t, "GCC: (GNU) 13.2.0\x00"))
	d := decode(t, gcc)
	if d.Kind != "elf" || d.Toolchain != "gcc 13.2.0" {
		t.Fatalf("gcc digest = %q/%q, want elf/gcc 13.2.0", d.Kind, d.Toolchain)
	}
	if d.Plan != "elf" {
		t.Fatalf("plan = %q, want elf", d.Plan)
	}

	zig := writeTemp(t, "zig.o", elfWithComment(t, "zig 0.11.0\x00"))
	if d := decode(t, zig); d.Toolchain != "zig 0.11.0" {
		t.Fatalf("zig toolchain = %q, want zig 0.11.0", d.Toolchain)
	}

	// A real clang object proves the DWARF path, not only .comment.
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang unavailable for the DWARF case")
	}
	src := writeTemp(t, "p.c", []byte("int p(int x){return x+1;}\n"))
	obj := filepath.Join(t.TempDir(), "p.o")
	cmd := exec.Command(clang, "-target", "x86_64-unknown-linux-gnu", "-g", "-O2", "-c", "-o", obj, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("clang cannot target elf here: %v\n%s", err, out)
	}
	d = decode(t, obj)
	if !strings.HasPrefix(d.Toolchain, "clang ") {
		t.Fatalf("dwarf toolchain = %q, want clang <version>", d.Toolchain)
	}
}
