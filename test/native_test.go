package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// TestHardeningFatMachO: /bin/ls is universal, so hardening is merged and every
// slice gets its own line with arch, minos and uuid.
func TestHardeningFatMachO(t *testing.T) {
	d := probeFixture(t, lsPath)
	if d.Slices != 2 {
		t.Fatalf("slices = %d, want 2", d.Slices)
	}
	if len(d.SliceInfo) != d.Slices {
		t.Fatalf("slice_info = %d lines, want %d", len(d.SliceInfo), d.Slices)
	}
	for i, s := range d.SliceInfo {
		if !strings.Contains(s, "minos ") || !strings.Contains(s, "uuid ") {
			t.Fatalf("slice %d = %q, want minos and uuid", i, s)
		}
	}
	if len(d.Hardening) == 0 {
		t.Fatalf("hardening empty for %s", lsPath)
	}
	want := map[string]bool{"pie": false, "nx": false}
	for _, h := range d.Hardening {
		if _, ok := want[h]; ok {
			want[h] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Fatalf("hardening %v missing %q", d.Hardening, k)
		}
	}
}

// TestHardeningGoMachO: a thin Go binary keeps its single-slice identity at the
// top level and reports no slice lines.
func TestHardeningGoMachO(t *testing.T) {
	d := probeFixture(t, goFixtureDeps(t, 1))
	if d.Slices != 0 || len(d.SliceInfo) != 0 {
		t.Fatalf("thin binary reported slices %d/%d lines", d.Slices, len(d.SliceInfo))
	}
	if d.MinOS == "" || d.UUID == "" {
		t.Fatalf("minos/uuid = %q/%q, want both", d.MinOS, d.UUID)
	}
	if len(d.Hardening) == 0 {
		t.Fatalf("hardening empty for %s", d.Path)
	}
	text := d.Text()
	if !strings.Contains(text, "\nhardening: ") {
		t.Fatalf("hardening line missing from:\n%s", text)
	}
}

// TestHardeningTrueMachO covers a second system binary: one hardening entry and
// a slice line per arch it actually carries.
func TestHardeningTrueMachO(t *testing.T) {
	d := probeFixture(t, fixtureMacho)
	if d.Kind != "macho" {
		t.Fatalf("kind = %q, want macho", d.Kind)
	}
	if len(d.Hardening) == 0 {
		t.Fatalf("hardening empty for %s", fixtureMacho)
	}
	if len(d.SliceInfo) != d.Slices {
		t.Fatalf("slice_info = %d lines, want %d", len(d.SliceInfo), d.Slices)
	}
}

// TestHardeningPE hand-writes a PE32+ DLL with a CodeView debug directory, the
// layout MSVC emits, so DLL/aslr/dep/cfg and the PDB path are all exercised.
func TestHardeningPE(t *testing.T) {
	const pdb = `C:\src\app.pdb`
	img := make([]byte, 0x700)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x40)
	copy(img[0x40:], "PE\x00\x00")
	coff := img[0x44:]
	binary.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(coff[2:], 2)
	binary.LittleEndian.PutUint16(coff[16:], 240)
	binary.LittleEndian.PutUint16(coff[18:], pe.IMAGE_FILE_EXECUTABLE_IMAGE|pe.IMAGE_FILE_DLL)
	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[56:], 0x2000)
	binary.LittleEndian.PutUint32(opt[60:], 0x200)
	binary.LittleEndian.PutUint16(opt[68:], 2) // GUI subsystem
	binary.LittleEndian.PutUint16(opt[70:], pe.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE|
		pe.IMAGE_DLLCHARACTERISTICS_NX_COMPAT|pe.IMAGE_DLLCHARACTERISTICS_GUARD_CF)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	dd := 112 + pe.IMAGE_DIRECTORY_ENTRY_DEBUG*8
	binary.LittleEndian.PutUint32(opt[dd:], 0x1200) // debug dir RVA
	binary.LittleEndian.PutUint32(opt[dd+4:], 28)

	sec := img[0x148:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], 0x400)
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)
	binary.LittleEndian.PutUint32(sec[16:], 0x400)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)

	dir := img[0x400:]                                             // raw 0x400 == RVA 0x1200
	binary.LittleEndian.PutUint32(dir[12:], 2)                     // IMAGE_DEBUG_TYPE_CODEVIEW
	binary.LittleEndian.PutUint32(dir[16:], uint32(24+len(pdb)+1)) // SizeOfData
	binary.LittleEndian.PutUint32(dir[24:], 0x440)                 // PointerToRawData
	rec := img[0x440:]
	copy(rec, "RSDS")
	binary.LittleEndian.PutUint32(rec[20:], 1) // age
	copy(rec[24:], pdb)

	// .idata: one import descriptor pulling __security_check_cookie, the only
	// post-link evidence MSVC /GS leaves behind.
	sec2 := img[0x148+40:]
	copy(sec2, ".idata")
	binary.LittleEndian.PutUint32(sec2[8:], 0x100)
	binary.LittleEndian.PutUint32(sec2[12:], 0x1400)
	binary.LittleEndian.PutUint32(sec2[16:], 0x100)
	binary.LittleEndian.PutUint32(sec2[20:], 0x600)
	binary.LittleEndian.PutUint32(sec2[36:], 0xc0000040)

	imp := 112 + pe.IMAGE_DIRECTORY_ENTRY_IMPORT*8
	binary.LittleEndian.PutUint32(opt[imp:], 0x1400)
	binary.LittleEndian.PutUint32(opt[imp+4:], 40)

	idt := img[0x600:]
	binary.LittleEndian.PutUint32(idt[0:], 0x1428)  // OriginalFirstThunk
	binary.LittleEndian.PutUint32(idt[12:], 0x1438) // Name
	binary.LittleEndian.PutUint32(idt[16:], 0x1428) // FirstThunk
	binary.LittleEndian.PutUint64(idt[0x28:], 0x1450)
	copy(idt[0x38:], "vcruntime140.dll")
	copy(idt[0x52:], "__security_check_cookie")

	d := probeFixture(t, writeTemp(t, "app.dll", img))
	if d.Subsystem != "gui" {
		t.Fatalf("subsystem = %q, want gui", d.Subsystem)
	}
	if d.PDB != pdb {
		t.Fatalf("pdb = %q, want %q", d.PDB, pdb)
	}
	for _, want := range []string{"dll", "aslr", "nx", "cfg", "canary", "debug-info:pdb"} {
		if !slices.Contains(d.Hardening, want) {
			t.Fatalf("hardening %v missing %q", d.Hardening, want)
		}
	}
}

// buildTarget cross-compiles a hello-world binary: the Go toolchain is the
// fixture factory for ELF and PE deep scans.
func buildTarget(t *testing.T, goos, goarch, name string, ldflags ...string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	if err := os.WriteFile(src, []byte("package main\n\nfunc main() { println(\"deep\") }\n"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(dir, name)
	args := append([]string{"build", "-o", out}, ldflags...)
	cmd := exec.Command("go", append(args, src)...)
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-build %s/%s: %v\n%s", goos, goarch, err, b)
	}
	return out
}

// deepOrInstallHint fails only when DeepScan neither disassembled nor honestly
// named the missing tool, so the test holds on hosts with and without llvm.
func deepOrInstallHint(t *testing.T, path string) string {
	t.Helper()
	out, err := DeepScan(path, "main.main")
	if err != nil {
		t.Fatalf("DeepScan(%s, main.main) error = %v, want pclntab disassembly", path, err)
	}
	if !strings.Contains(out, "main.main") {
		t.Fatalf("deep output for %s missing main.main:\n%s", path, out)
	}
	if !strings.Contains(out, "procedure_assembly") || !strings.Contains(out, "LRECON_NAME=main.main") {
		t.Fatalf("deep output for %s missing the Ghidra handoff hint:\n%s", path, out)
	}
	return out
}

// TestDeepELF: a cross-compiled linux binary resolves main.main by name.
func TestDeepELF(t *testing.T) {
	deepOrInstallHint(t, buildTarget(t, "linux", "amd64", "hello.elf"))
}

// TestDeepPE: the same contract on a windows binary, whose COFF symbol table
// carries main.main.
func TestDeepPE(t *testing.T) {
	deepOrInstallHint(t, buildTarget(t, "windows", "amd64", "hello.exe"))
}

// TestDeepELFBogusSymbol: a present symbol table without the name is a spelling
// error, never a stripped-binary excuse.
func TestDeepELFBogusSymbol(t *testing.T) {
	el := buildTarget(t, "linux", "amd64", "hello.elf")
	_, err := DeepScan(el, "main.notThere")
	if err == nil || !strings.Contains(err.Error(), "check the spelling") {
		t.Fatalf("bogus symbol error = %v, want check the spelling", err)
	}
}

// TestDeepELFStripped: -s -w removes the symbol table, but pclntab survives,
// so --deep resolves main.main from pclntab with a hex dump + handoff.
func TestDeepELFStripped(t *testing.T) {
	el := buildTarget(t, "linux", "amd64", "hello-stripped.elf", "-ldflags=-s -w")
	out, err := DeepScan(el, "main.main")
	if err != nil {
		t.Fatalf("stripped ELF error = %v, want pclntab fallback", err)
	}
	if !strings.Contains(out, "main.main") || !strings.Contains(out, "pclntab") || !strings.Contains(out, "LRECON_AT=") || !strings.Contains(out, "procedure_assembly") {
		t.Fatalf("stripped ELF output = %q, want pclntab dump + handoff", out)
	}
}

// elfRELRO hand-writes a minimal ELF64 with a PT_GNU_RELRO segment plus the
// optional eager-binding marker; Go's own linux binaries carry no RELRO segment.
func elfRELRO(t *testing.T, tag elf.DynTag) string {
	t.Helper()
	b := make([]byte, 448)
	bo := binary.LittleEndian
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1 // ELF64, little-endian, version 1
	bo.PutUint16(b[16:], uint16(elf.ET_EXEC))
	bo.PutUint16(b[18:], uint16(elf.EM_X86_64))
	bo.PutUint32(b[20:], 1)
	bo.PutUint64(b[32:], 64)    // e_phoff
	bo.PutUint64(b[40:], 0x100) // e_shoff
	bo.PutUint16(b[52:], 64)    // e_ehsize
	bo.PutUint16(b[54:], 56)    // e_phentsize
	bo.PutUint16(b[56:], 1)     // e_phnum
	bo.PutUint16(b[58:], 64)    // e_shentsize
	bo.PutUint16(b[60:], 3)     // e_shnum
	bo.PutUint16(b[62:], 2)     // e_shstrndx
	bo.PutUint32(b[64:], uint32(elf.PT_GNU_RELRO))
	bo.PutUint32(b[68:], uint32(elf.PF_R))
	if tag != 0 {
		flag := uint64(elf.DF_BIND_NOW)
		if tag == elf.DT_FLAGS_1 {
			flag = uint64(elf.DF_1_NOW)
		}
		bo.PutUint64(b[128:], uint64(tag))
		bo.PutUint64(b[136:], flag)
	}
	copy(b[160:], "\x00.dynamic\x00.shstrtab\x00")
	sh := b[0x100:]
	bo.PutUint32(sh[64:], 1) // .dynamic
	bo.PutUint32(sh[68:], uint32(elf.SHT_DYNAMIC))
	bo.PutUint64(sh[88:], 128)
	bo.PutUint64(sh[96:], 32)
	bo.PutUint64(sh[112:], 8)
	bo.PutUint64(sh[120:], 16)
	bo.PutUint32(sh[128:], 10) // .shstrtab
	bo.PutUint32(sh[132:], uint32(elf.SHT_STRTAB))
	bo.PutUint64(sh[152:], 160)
	bo.PutUint64(sh[160:], 20)
	return writeTemp(t, "relro.elf", b)
}

// TestELFORELRO: eager binding upgrades partial RELRO to full on both markers
// linkers emit, and neither case keeps the old bare "relro" token.
func TestELFORELRO(t *testing.T) {
	for _, tc := range []struct {
		name string
		tag  elf.DynTag
		want string
		not  string
	}{
		{"lazy", 0, "relro-partial", "relro-full"},
		{"bind-now", elf.DT_BIND_NOW, "relro-full", "relro-partial"},
		{"flags-bind-now", elf.DT_FLAGS, "relro-full", "relro-partial"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hard := probeFixture(t, elfRELRO(t, tc.tag)).Hardening
			if !slices.Contains(hard, tc.want) {
				t.Fatalf("hardening %v missing %q", hard, tc.want)
			}
			if slices.Contains(hard, tc.not) {
				t.Fatalf("hardening %v must not report %q", hard, tc.not)
			}
			if slices.Contains(hard, "relro") {
				t.Fatalf("hardening %v still reports bare relro", hard)
			}
		})
	}
}

// TestELFORelroFlags1: DT_FLAGS_1/DF_1_NOW is the third eager-binding marker,
// and a program header without PT_GNU_RELRO must stay silent instead of
// claiming partial RELRO.
func TestELFORelroFlags1(t *testing.T) {
	raw, err := os.ReadFile(elfRELRO(t, elf.DT_FLAGS_1))
	if err != nil {
		t.Fatal(err)
	}
	noRelro := append([]byte(nil), raw...)
	binary.LittleEndian.PutUint32(noRelro[64:], uint32(elf.PT_NULL)) // drop the PT_GNU_RELRO entry
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"flags1-now", raw, "relro-full"},
		{"no-relro", noRelro, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hard := probeFixture(t, writeTemp(t, tc.name+".elf", tc.data)).Hardening
			if tc.want != "" && !slices.Contains(hard, tc.want) {
				t.Fatalf("hardening %v missing %q", hard, tc.want)
			}
			for _, tok := range []string{"relro-full", "relro-partial"} {
				if slices.Contains(hard, tok) && tok != tc.want {
					t.Fatalf("hardening %v must not report %q", hard, tok)
				}
			}
		})
	}
}

func TestChkHardening(t *testing.T) {
	got := strings.Join(chkHardening([]string{"write", "__stack_chk_fail", "__sprintf_chk", "_exit"}), ",")
	if got != "canary,fortify" {
		t.Fatalf("got %q, want canary,fortify", got)
	}
	if got := chkHardening([]string{"write", "_exit"}); len(got) != 0 {
		t.Fatalf("plain libc imports must not imply hardening, got %v", got)
	}
}

// rustFixtureBytes builds a fake binary that carries a Rust marker and the given
// cargo registry source paths.
func rustFixtureBytes(paths ...string) []byte {
	b := []byte("MZ\x90\x00 rust_panic rust_begin_unwind \x00")
	for _, p := range paths {
		b = append(b, []byte(p+"\x00")...)
	}
	return b
}

func TestNativeRustCrateListRegistryPaths(t *testing.T) {
	p := writeTemp(t, "rustcrates.bin", rustFixtureBytes(
		"/Users/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aho-corasick-1.1.5/src/nfa.rs",
		"evren/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/aho-corasick-1.1.5/src/lib.rs",
		`C:\Users\u\.cargo\registry\src\github.com-1ecc6299db9ec823\memchr-2.8.3\src\memchr.rs`,
		"/Users/u/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/src/not-a-crate.rs",
	))
	got := rustCrateList(p)
	want := []string{"aho-corasick-1.1.5", "memchr-2.8.3"}
	if !slices.Equal(got, want) {
		t.Fatalf("rustCrateList = %v, want %v", got, want)
	}
}

func TestNativeRustDigestPECrates(t *testing.T) {
	p := writeTemp(t, "rustdep.exe", rustFixtureBytes(
		`C:\Users\u\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\memchr-2.8.3\src\lib.rs`,
		`C:\Users\u\.cargo\registry\src\index.crates.io-1949cf8c6b5b557f\aho-corasick-1.1.5\src\lib.rs`,
	))
	d := Digest{Kind: "pe"}
	rustDigest(p, &d)
	if !strings.HasPrefix(d.Toolchain, "rustc") {
		t.Fatalf("toolchain = %q, want a rustc producer string", d.Toolchain)
	}
	if want := []string{"aho-corasick-1.1.5", "memchr-2.8.3"}; !slices.Equal(d.RustCrates, want) {
		t.Fatalf("RustCrates = %v, want %v", d.RustCrates, want)
	}
	if len(d.Notes) == 0 || !strings.HasPrefix(d.Notes[len(d.Notes)-1], "deep: ") {
		t.Fatalf("notes = %v, want a deep: note", d.Notes)
	}
}

func TestNativeRustCrateListDepsPaths(t *testing.T) {
	p := writeTemp(t, "rustdeps.bin", rustFixtureBytes(
		"/rust/deps/addr2line-0.25.0/src/function.rs",
		"/rust/deps/gimli-0.32.0/src/lib.rs",
		"/rust/deps/object-0.37.3/src/read/mod.rs",
		`C:\rust\deps\rustc-demangle-0.1.26\src\lib.rs`,
		"/rust/deps/not-a-crate/src/lib.rs",
	))
	got := rustCrateList(p)
	want := []string{"addr2line-0.25.0", "gimli-0.32.0", "object-0.37.3", "rustc-demangle-0.1.26"}
	if !slices.Equal(got, want) {
		t.Fatalf("rustCrateList = %v, want %v", got, want)
	}
}

func TestNativeRustDigestDepsAndModFallback(t *testing.T) {
	p := writeTemp(t, "rustdeps.exe", rustFixtureBytes(
		"/rust/deps/gimli-0.32.0/src/lib.rs",
		"/rust/deps/addr2line-0.25.0/src/function.rs",
	))
	d := Digest{Kind: "pe"}
	rustDigest(p, &d)
	if d.Mod != rustModUnknown {
		t.Fatalf("mod = %q, want %q without a symbol table", d.Mod, rustModUnknown)
	}
	want := []Dep{
		{Path: "addr2line", Version: "0.25.0"},
		{Path: "gimli", Version: "0.32.0"},
	}
	if !slices.Equal(d.Deps, want) {
		t.Fatalf("deps = %v, want %v", d.Deps, want)
	}
}

func TestNativeRustDigestNoCrates(t *testing.T) {
	p := writeTemp(t, "ruststripped.exe", rustFixtureBytes())
	d := Digest{Kind: "pe"}
	rustDigest(p, &d)
	if len(d.RustCrates) != 0 {
		t.Fatalf("RustCrates = %v, want empty", d.RustCrates)
	}
	if d.Deps != nil {
		t.Fatalf("Deps = %v, want null when no dependency path was measured", d.Deps)
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "deep: ") || !strings.Contains(notes, "stripped or unavailable") {
		t.Fatalf("notes = %v, want a deep: note about a stripped crate list", d.Notes)
	}
}

func TestNativeRustCrateCap(t *testing.T) {
	var paths []string
	for i := 0; i < maxRustCrates+6; i++ {
		paths = append(paths, fmt.Sprintf("/r/.cargo/registry/src/index.crates.io-h/crate%d-1.0.0/src/lib.rs", i))
	}
	p := writeTemp(t, "rustmany.exe", rustFixtureBytes(paths...))
	d := Digest{Kind: "pe"}
	rustDigest(p, &d)
	if len(d.RustCrates) != maxRustCrates {
		t.Fatalf("len(RustCrates) = %d, want %d", len(d.RustCrates), maxRustCrates)
	}
	if notes := strings.Join(d.Notes, "\n"); !strings.Contains(notes, "crates truncated to 64 of 70") {
		t.Fatalf("notes = %v, want the truncation note", d.Notes)
	}
}

func TestNativeDeepNoteMachO(t *testing.T) {
	d := probeFixture(t, lsPath)
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "deep: ") {
		t.Fatalf("notes = %v, want a deep: note", d.Notes)
	}
	for _, tool := range []string{"ghidra", "frida", "objdump", "otool", "readelf", "llvm"} {
		if strings.Contains(strings.ToLower(notes), tool) {
			t.Fatalf("notes mention the tool %q: %v", tool, d.Notes)
		}
	}
}

// buildCTarget compiles a two-function C program: deepMachO needs a real __TEXT
// label with a body behind it, which a cross-built Go binary does not offer.
func buildCTarget(t *testing.T) string {
	t.Helper()
	cc, err := exec.LookPath("clang")
	if err != nil {
		t.Skipf("clang unavailable: %v", err)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "window.c")
	code := "int counter = 0;\nint bump(int n) {\n\tcounter += n;\n\treturn counter + n;\n}\nint main(void) { return bump(1); }\n"
	if err := os.WriteFile(src, []byte(code), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(dir, "window")
	if b, err := exec.Command(cc, src, "-o", out).CombinedOutput(); err != nil {
		t.Skipf("clang build failed: %v\n%s", err, b)
	}
	return out
}

// TestDeepMachOCRedirect: a C binary is not a Go binary, so --deep reads the
// symbol table in-process and hands the body to the Ghidra op that owns native
// code, instead of pretending to disassemble it.
func TestDeepMachOCRedirect(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs a Mach-O C fixture")
	}
	out, err := DeepScan(buildCTarget(t), "bump")
	if err != nil {
		t.Fatalf("DeepScan(bump) error: %v", err)
	}
	if !strings.Contains(out, "_bump") {
		t.Fatalf("output missing the symbol table line:\n%s", out)
	}
	if !strings.Contains(out, "LRECON_NAME=bump lrecon --op procedure_assembly") {
		t.Fatalf("output does not name the Ghidra op that prints the body:\n%s", out)
	}
}

// TestNativeExportsStrippedVisible: -s -w removes the symbol table, and a zero
// export count must still be printed, with the reason it is zero.
func TestNativeExportsStrippedVisible(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin fixture")
	}
	stripped := probeFixture(t, buildTarget(t, "darwin", runtime.GOARCH, "stripped", "-ldflags=-s -w"))
	text := stripped.Text()
	for _, want := range []string{"exports: 0\n", "symbols: stripped\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stripped digest missing %q:\n%s", want, text)
		}
	}
	plain := probeFixture(t, buildTarget(t, "darwin", runtime.GOARCH, "plain"))
	if !strings.Contains(plain.Text(), "symbols: present\n") {
		t.Fatalf("unstripped digest missing symbols: present:\n%s", plain.Text())
	}
}

// TestNativeExportsStrippedELF: the zero-count marker is not darwin-only.
func TestNativeExportsStrippedELF(t *testing.T) {
	d := probeFixture(t, buildTarget(t, "linux", "amd64", "stripped.elf", "-ldflags=-s -w"))
	text := d.Text()
	for _, want := range []string{"exports: 0\n", "symbols: stripped\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stripped ELF digest missing %q:\n%s", want, text)
		}
	}
}

// TestMachoExportsTrie: dyld's export trie, not the symbol table, is the count
// a consumer of the digest acts on.
func TestMachoExportsTrie(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macho fixture")
	}
	path := buildCTarget(t)
	f, err := macho.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	n, state := machoExports(path, 0, f)
	if n < 2 || state != symPresent { // _main and _bump at least
		t.Fatalf("machoExports = %d, %q; want >=2 and present", n, state)
	}
}

// TestTrieTerminalsCorrupt: a truncated or looping trie counts what it can and
// stops instead of panicking on hostile input.
func TestTrieTerminalsCorrupt(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input []byte
		want  int
	}{
		{"empty", nil, 0},
		{"zero byte", []byte{0}, 0},
		{"edge string runs off the end", []byte{0, 1, 0xff}, 0},
		{"truncated ULEB128", []byte{0xff, 0xff, 0xff}, 0},
		{"terminal data past the end", []byte{2, 0, 0}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trieTerminals(tc.input); got != tc.want {
				t.Fatalf("trieTerminals(% x) = %d, want %d", tc.input, got, tc.want)
			}
		})
	}
}

// goBuildinfoBlob writes the blob Go 1.18+ emits: the 14-byte magic, ptrSize,
// flags, 16 zero bytes of header padding, then the version as a varint string.
func goBuildinfoBlob(version string) []byte {
	b := make([]byte, goBuildInfoHeaderSize)
	copy(b, goBuildInfoMagic)
	b[14], b[15] = 8, goInfoVersionInline
	var v [binary.MaxVarintLen64]byte
	k := binary.PutUvarint(v[:], uint64(len(version)))
	b = append(b, v[:k]...)
	return append(b, version...)
}

// goBuildIDNote is the build id marker a Go image carries even when the linker
// wrote no build-info blob, which is how "Go without build info" is told apart
// from "not a Go binary".
var goBuildIDNote = []byte("\xff Go build ID: \"abc123\"\n\xff")

// TestGoBuildinfoInline: a well-formed inline header proves the version, the
// pointer size and the flags, and the module table stays unknown rather than
// being invented from the header.
func TestGoBuildinfoInline(t *testing.T) {
	// A real image carries both: the build id note and the blob.
	file := append(append([]byte{}, goBuildIDNote...), goBuildinfoBlob("go1.26.5")...)
	p := writeTemp(t, "goblob.bin", file)
	d := Digest{}
	if !goDigest(p, &d) {
		t.Fatal("goDigest refused an inline build-info header")
	}
	if !strings.Contains(d.Toolchain, "go1.26.5") {
		t.Fatalf("toolchain = %q, want the inline version", d.Toolchain)
	}
	joined := strings.Join(d.Capabilities, "\n")
	for _, want := range []string{"go:buildinfo=header-only", "go:ptr_size=8", "go:buildinfo_flags=0x02", "go:version=go1.26.5"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("capabilities missing %q: %v", want, d.Capabilities)
		}
	}
	if d.Mod != "unknown" || len(d.Deps) != 0 {
		t.Fatalf("mod/deps = %q/%v, want unknown and no invented module list", d.Mod, d.Deps)
	}
}

// TestGoBuildinfoTruncated cuts one blob at four places: before the magic (a Go
// build id with no blob at all) and at three header widths. Each must name a
// registered reason instead of leaving the digest silent.
func TestGoBuildinfoTruncated(t *testing.T) {
	blob := goBuildinfoBlob("go1.26.5")
	cases := []struct {
		name string
		file []byte
		want string
	}{
		{"no-blob", goBuildIDNote, "buildinfo-absent"},
		{"magic-and-ptrsize", append(append([]byte{}, goBuildIDNote...), blob[:15]...), "buildinfo-header-truncated"},
		{"header-padding", append(append([]byte{}, goBuildIDNote...), blob[:24]...), "buildinfo-header-truncated"},
		{"version-cut", append(append([]byte{}, goBuildIDNote...), blob[:33]...), "buildinfo-header-truncated"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Digest{}
			if !goDigest(writeTemp(t, "cut.bin", c.file), &d) {
				t.Fatalf("goDigest did not claim a Go-shaped file")
			}
			if len(d.Skipped) != 1 || d.Skipped[0].Reason != c.want {
				t.Fatalf("skipped = %+v, want %s", d.Skipped, c.want)
			}
			if d.Toolchain != "" || d.Mod != "" || len(d.Deps) != 0 {
				t.Fatalf("toolchain/mod/deps = %q/%q/%v, want nothing invented", d.Toolchain, d.Mod, d.Deps)
			}
		})
	}
}

// TestGoBuildinfoRealBinary keeps the free path honest: when debug/buildinfo
// reads the blob the module list must still be the real one, not a fallback.
func TestGoBuildinfoRealBinary(t *testing.T) {
	d := probeFixture(t, goFixtureDeps(t, 1))
	if len(d.Deps) == 0 || d.Mod == "" || d.Mod == "unknown" {
		t.Fatalf("mod/deps = %q/%d, want the real module graph from debug/buildinfo", d.Mod, len(d.Deps))
	}
	for _, s := range d.Skipped {
		if strings.HasPrefix(s.Reason, "buildinfo-") {
			t.Fatalf("skipped = %+v, want no buildinfo refusal for %s", d.Skipped, d.Path)
		}
	}
}

// TestGoBuildinfoForeignMagic: the magic alone is not proof. A native binary can
// contain those bytes in a string table, and claiming it would hide its real
// findings, so the fallback needs the build id note before it answers.
func TestGoBuildinfoForeignMagic(t *testing.T) {
	file := append(append([]byte{}, goBuildInfoMagic...), make([]byte, 8)...)
	d := Digest{}
	if goDigest(writeTemp(t, "foreign.bin", file), &d) {
		t.Fatalf("goDigest claimed a file with the magic but no Go build id: %+v", d.Skipped)
	}
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want silence for a non-Go file", d.Skipped)
	}
}

// TestFindObjectSymbolSpellings: a C symbol carries a leading '_' in the
// Mach-O table, so `--deep bump` and `--deep _bump` must agree on either
// platform's spelling.
func TestFindObjectSymbolSpellings(t *testing.T) {
	sets := [][]objectSymbol{
		{{Value: 0x1000, Kind: 'T', Name: "_bump"}},
		{{Value: 0x2000, Kind: 'T', Name: "bump"}},
	}
	for _, syms := range sets {
		for _, want := range []string{"bump", "_bump"} {
			got, ok := findObjectSymbol(syms, want)
			if !ok || got.Name != syms[0].Name {
				t.Fatalf("findObjectSymbol(table %q, query %q) = %+v, %v; want the one row", syms[0].Name, want, got, ok)
			}
		}
	}
	if got, ok := findObjectSymbol(sets[0], "missing"); ok {
		t.Fatalf("findObjectSymbol matched %+v for a symbol that is not in the table", got)
	}
}
