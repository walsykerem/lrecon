package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// lsdaFixtureSource is the smallest program that exercises all three things an
// LSDA can say: two catch types, a throw, and a destructor cleanup. cleanup_only
// exists because -O1 folds main's destructor into the catch landing pad; a
// separate function with no try/catch keeps a pure cleanup range alive.
const lsdaFixtureSource = `#include <stdexcept>
int sink;
struct G { ~G(); };
G::~G() { sink++; }
__attribute__((noinline)) void may_throw() { throw std::runtime_error("z"); }
__attribute__((noinline)) void cleanup_only() { G g; may_throw(); }
int main(int argc, char**) {
  G g;
  try {
    if (argc > 1) throw std::runtime_error("x");
    throw std::out_of_range("y");
  } catch (const std::runtime_error&) { return 1; }
  catch (const std::out_of_range&) { return 2; }
  try { cleanup_only(); } catch (...) { return 3; }
  return 0;
}
`

// lsdaCompile builds one fixture in a temp dir. The test may run the compiler;
// the inspector under test never runs the produced program.
func lsdaCompile(t *testing.T, file, compiler, source string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath(compiler); err != nil {
		t.Skipf("%s not installed", compiler)
	}
	dir := t.TempDir()
	src := filepath.Join(dir, file)
	if err := os.WriteFile(src, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, strings.TrimSuffix(file, filepath.Ext(file)))
	cmd := exec.Command(compiler, append(args, src, "-o", out)...)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s: %v\n%s", compiler, err, b)
	}
	return out
}

func TestLSDAFixture(t *testing.T) {
	if runtime.GOOS != "darwin" {
		// The fixture's dynamic type_info entries are resolved through Mach-O
		// chained fixups; ELF resolves them through relocations this reader
		// does not walk yet. Refusal is correct there, so do not assert success.
		t.Skip("fixture covers the Mach-O chained-fixup path")
	}
	bin := lsdaCompile(t, "t.cpp", "clang++", lsdaFixtureSource,
		"-O1", "-fexceptions", "-fasynchronous-unwind-tables")
	d, err := Probe(bin)
	if err != nil {
		t.Fatal(err)
	}
	note := strings.Join(d.Notes, "; ")
	if !strings.Contains(note, "cxx-eh ") {
		t.Fatalf("no cxx-eh note: %v", d.Notes)
	}
	if strings.Contains(note, "0 landing pads") {
		t.Fatalf("fixture produced no landing pad: %s", note)
	}
	for _, want := range []string{"std::runtime_error", "std::out_of_range", "cleanup-only ranges"} {
		if !strings.Contains(note, want) {
			t.Fatalf("note %q missing %q", note, want)
		}
	}
}

func TestLSDAAbsent(t *testing.T) {
	elf := lsdaCompile(t, "c.c", "clang", "int f(void) { return 1; }\n",
		"--target=x86_64-unknown-linux-gnu", "-O1", "-c")
	d, err := Probe(elf)
	if err != nil {
		t.Fatal(err)
	}
	if !skippedReasons(d)[lsdaAbsent] {
		t.Fatalf("ELF object without unwind tables not refused with %s: skips=%v notes=%v", lsdaAbsent, d.Skipped, d.Notes)
	}
	if runtime.GOOS != "darwin" {
		return
	}
	// A default-flag Mach-O has no __eh_frame; LSDA lives in __gcc_except_tab
	// behind __unwind_info, which lsdamacho owns. Reporting it absent here
	// would be a refusal for a shape another reader handles.
	bin := lsdaCompile(t, "cm.c", "clang", "int main(void) { return 0; }\n", "-O1")
	d, err = Probe(bin)
	if err != nil {
		t.Fatal(err)
	}
	if skippedReasons(d)[lsdaAbsent] {
		t.Fatalf("Mach-O without __eh_frame refused with %s: skips=%v", lsdaAbsent, d.Skipped)
	}
}

func TestLSDADemangle(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"__ZTISt13runtime_error", "std::runtime_error"},
		{"_ZTISt12out_of_range", "std::out_of_range"},
		{"_ZTINSt3__113runtime_errorE", "std::runtime_error"},
		{"_ZTIi", "i"},
	} {
		if got := lsdaDemangle(tc.in); got != tc.want {
			t.Errorf("lsdaDemangle(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestItaniumTypeNameShared: the vtable reader (_ZTV/_ZTI/_ZTS) and the LSDA
// catch-clause reader name the same symbol with one parser, so a class does not
// get two spellings depending on which reader looked at it.
func TestItaniumTypeNameShared(t *testing.T) {
	for _, enc := range []string{
		"6Foobar",
		"N3Foo3BarE",
		"St9exception",
		"NSt3__113runtime_errorE",
		"N10__cxxabiv117__class_type_infoE",
	} {
		viaVtable := cxxTableType("_ZTV" + enc)
		viaLSDA := lsdaDemangle("_ZTI" + enc)
		if viaVtable != viaLSDA {
			t.Errorf("%q: vtable reader says %q, LSDA reader says %q", enc, viaVtable, viaLSDA)
		}
		if viaVtable == "" {
			t.Errorf("%q decoded to nothing in both readers", enc)
		}
	}
	// A template component is outside the shared subset, and the two contracts
	// differ by design: the vtable reader refuses the name, the LSDA reader
	// prints the mangled payload it must show for the catch clause.
	if got := cxxTableType("_ZTVN3Foo3BarIiEE"); got != "" {
		t.Errorf("template type name = %q, want refusal", got)
	}
	if got := lsdaDemangle("_ZTIN3Foo3BarIiEE"); got != "N3Foo3BarIiEE" {
		t.Errorf("template payload = %q, want the raw component", got)
	}
}

func TestLSDARefusals(t *testing.T) {
	im := &lsdaImage{ptr: 8, gccAddr: 0x1000}
	sum := &lsdaSummary{seen: map[string]bool{}}

	// Call-site length runs past the end of the table.
	if reason, detail := im.parseLSDA([]byte{0xff, 0xff, 0x05, 0x7f}, 0x1000, sum); reason != lsdaTruncated {
		t.Fatalf("truncated table: reason=%q detail=%q, want %q", reason, detail, lsdaTruncated)
	}
	// LPStart uses an aligned pointer encoding the reader does not resolve.
	if reason, detail := im.parseLSDA([]byte{0x50, 0xff, 0x05, 0x00}, 0x1000, sum); reason != lsdaBadEncoding {
		t.Fatalf("aligned LPStart: reason=%q detail=%q, want %q", reason, detail, lsdaBadEncoding)
	}
}

// truncatedMachOHead is a thin 64-bit Mach-O header that declares a load
// command the file does not hold: the shape a partial download leaves behind.
// The post readers see it because dispatchPost runs on every file a magic
// reader claimed.
func truncatedMachOHead() []byte {
	b := make([]byte, 32)
	binary.LittleEndian.PutUint32(b, 0xfeedfacf)
	binary.LittleEndian.PutUint32(b[4:], 0x0100000c) // CPU_TYPE_ARM64
	binary.LittleEndian.PutUint32(b[16:], 1)         // ncmds: one command the file does not hold
	return b
}

// TestLSDATruncatedIsNotAbsent: a cut file is not a file without handlers. A
// truncated Mach-O reported as lsda-absent claims the binary carries no
// exception table when the reader never saw the table at all.
func TestLSDATruncatedIsNotAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cut-macho")
	if err := os.WriteFile(path, truncatedMachOHead(), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe(%s): %v", path, err)
	}
	reasons := skippedReasons(d)
	if !reasons[lsdaTruncated] {
		t.Fatalf("skipped = %+v, want reason %q for a cut Mach-O", d.Skipped, lsdaTruncated)
	}
	if reasons[lsdaAbsent] {
		t.Fatalf("cut Mach-O also claimed %q; absence and truncation are different claims", lsdaAbsent)
	}
}
