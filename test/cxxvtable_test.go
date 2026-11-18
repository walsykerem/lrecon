package main

import (
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The fixture is compiled by the test, never executed: the inspector reads the
// file, so the test only needs a compiler that can emit ELF x86-64. g++ with
// default flags is the real-world case; on a non-Linux host the cross target
// object carries the same vtables and relocations.
const cxxFixture = `
struct Base {
  virtual ~Base();
  virtual void f();
  virtual void g();
};
struct Derived : Base {
  ~Derived() override;
  void f() override;
  void g() override;
  virtual void h();
};
struct Third {
  virtual void a();
  virtual void b();
  virtual void c();
  virtual void d();
  virtual void e();
};
Base::~Base() {}
void Base::f() {}
void Base::g() {}
Derived::~Derived() {}
void Derived::f() {}
void Derived::g() {}
void Derived::h() {}
void Third::a() {}
void Third::b() {}
void Third::c() {}
void Third::d() {}
void Third::e() {}
void take(Base* p) { p->f(); }
int main() { Base* p = new Derived; p->g(); delete p; return 0; }
`

// cxxBuild returns the tracked object compiled by testdata/fixtures/cxx/make.sh,
// so the suite needs no C++ compiler. Without it, the fixture is compiled with
// the first compiler that yields an ELF x86-64 image: a Mach-O result is not an
// ELF failure mode the reader handles, so it is retried with the cross target.
func cxxBuild(t *testing.T) string {
	t.Helper()
	if tracked := "testdata/fixtures/cxx/vtables.o"; cxxIsElfX86(tracked) {
		return tracked
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "t.cpp")
	if err := os.WriteFile(src, []byte(cxxFixture), 0o600); err != nil {
		t.Fatal(err)
	}
	type attempt struct {
		name string
		args []string
	}
	attempts := []attempt{
		{"g++", []string{"-O1", src, "-o", filepath.Join(dir, "t")}},
		{"clang++", []string{"-target", "x86_64-unknown-linux-gnu", "-O1", "-c", src, "-o", filepath.Join(dir, "t.o")}},
	}
	for _, a := range attempts {
		bin, err := exec.LookPath(a.name)
		if err != nil {
			continue
		}
		out := a.args[len(a.args)-1]
		if err := exec.Command(bin, a.args...).Run(); err != nil {
			continue
		}
		if cxxIsElfX86(out) {
			return out
		}
	}
	t.Skip("no compiler produced an ELF x86-64 fixture")
	return ""
}

func cxxIsElfX86(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 0x14 {
		return false
	}
	return b[0] == 0x7f && b[1] == 'E' && b[2] == 'L' && b[3] == 'F' &&
		binary.LittleEndian.Uint16(b[0x12:]) == 62 // EM_X86_64
}

// cxxWithoutSymtab removes symbol-table section headers, which is the observable
// part of `strip -x` for an ET_REL object: .data.rel.ro and its relocations stay,
// but no symbol names remain to say which bytes are a vtable.
func cxxWithoutSymtab(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 0x40 {
		t.Fatalf("%s shorter than an ELF header", src)
	}
	shoff := binary.LittleEndian.Uint64(b[0x28:])
	entsize := uint64(binary.LittleEndian.Uint16(b[0x3a:]))
	num := uint64(binary.LittleEndian.Uint16(b[0x3c:]))
	if entsize < 64 || shoff == 0 {
		t.Skipf("%s has no usable section header table", src)
	}
	for i := range num {
		off := shoff + i*entsize
		if off+8 > uint64(len(b)) {
			t.Fatalf("%s section header %d outside file", src, i)
		}
		typ := binary.LittleEndian.Uint32(b[off+4:])
		if typ == 2 || typ == 11 { // SHT_SYMTAB, SHT_DYNSYM
			binary.LittleEndian.PutUint32(b[off+4:], 0)
		}
	}
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func cxxSlotCount(t *testing.T, notes []string, class string) int {
	t.Helper()
	re := regexp.MustCompile(`cxx-class ` + regexp.QuoteMeta(class) + ` slots=(\d+)`)
	for _, n := range notes {
		if m := re.FindStringSubmatch(n); m != nil {
			v, err := strconv.Atoi(m[1])
			if err != nil {
				t.Fatalf("slot count %q: %v", m[1], err)
			}
			return v
		}
	}
	t.Fatalf("no cxx-class note for %s in %v", class, notes)
	return 0
}

func cxxSkipped(d Digest, reason string) bool {
	for _, s := range d.Skipped {
		if s.Reason == reason {
			return true
		}
	}
	return false
}

func TestCxxVtable(t *testing.T) {
	bin := cxxBuild(t)
	d, err := Probe(bin)
	if err != nil {
		t.Fatalf("Probe(%s): %v", bin, err)
	}
	if d.Kind != "elf" {
		t.Fatalf("kind = %q, want elf", d.Kind)
	}

	var b, der string
	for _, n := range d.Notes {
		if !strings.Contains(n, "cxx-class ") {
			continue
		}
		switch {
		case strings.Contains(n, "cxx-class Base slots="):
			b = n
		case strings.Contains(n, "cxx-class Derived slots="):
			der = n
		}
	}
	if b == "" || der == "" {
		t.Fatalf("Base/Derived vtable notes missing: %v", d.Notes)
	}
	if !strings.Contains(der, "base=Base") {
		t.Fatalf("Derived base relationship missing: %q", der)
	}
	if cxxSlotCount(t, d.Notes, "Derived") < cxxSlotCount(t, d.Notes, "Base") {
		t.Fatalf("Derived has fewer slots than Base: %v", d.Notes)
	}
	if !notesContain(d, "cxx-class Third slots=") {
		t.Fatalf("third class missing: %v", d.Notes)
	}

	// The stripped copy keeps the vtable bytes but loses the names that would
	// let a reader call them a class. Emitting a class here would be a guess.
	stripped := filepath.Join(t.TempDir(), "t.stripped")
	cxxWithoutSymtab(t, bin, stripped)
	sd, err := Probe(stripped)
	if err != nil {
		t.Fatalf("Probe(%s): %v", stripped, err)
	}
	if !cxxSkipped(sd, cxxReasonStripped) {
		t.Fatalf("stripped image did not report %s: %v", cxxReasonStripped, sd.Skipped)
	}
	if notesContain(sd, "cxx-class ") {
		t.Fatalf("stripped image named classes without symbols: %v", sd.Notes)
	}
}
