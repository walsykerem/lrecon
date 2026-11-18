package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tracked fixtures, never host binaries: /bin/ls is a fat Mach-O only on a Mac
// and an ELF everywhere else, so a host path makes every assertion below a
// platform test instead of an lrecon test.
// lsPath is the fat Mach-O every digest assertion wants: two slices and linked
// dylibs. It used to be /bin/ls, which is ELF off a Mac.
const lsPath = fixtureFat

// goFixtureDeps builds a thin Go binary with n module dependencies. The
// Homebrew gh binary this used to read is absent on a CI runner, so dep/mod
// coverage must be built rather than borrowed from the host.
func goFixtureDeps(t *testing.T, deps int) string {
	t.Helper()
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var mod strings.Builder
	mod.WriteString("module example.com/fix\n\ngo 1.21\n\nrequire (\n")
	for i := 0; i < deps; i++ {
		fmt.Fprintf(&mod, "\texample.com/dep%02d v0.0.0\n", i)
	}
	mod.WriteString(")\n\n")
	for i := 0; i < deps; i++ {
		fmt.Fprintf(&mod, "replace example.com/dep%02d => ./dep%02d\n", i, i)
	}
	write("go.mod", mod.String())
	var src strings.Builder
	src.WriteString("package main\n\nimport (\n")
	for i := 0; i < deps; i++ {
		fmt.Fprintf(&src, "\t\"example.com/dep%02d\"\n", i)
	}
	src.WriteString(")\n\nfunc main() { println(")
	for i := 0; i < deps; i++ {
		if i > 0 {
			src.WriteString(" + ")
		}
		fmt.Fprintf(&src, "dep%02d.Hello()", i)
	}
	src.WriteString(") }\n")
	write("main.go", src.String())
	for i := 0; i < deps; i++ {
		d := fmt.Sprintf("dep%02d", i)
		write(d+"/go.mod", "module example.com/"+d+"\n\ngo 1.21\n")
		write(d+"/dep.go", "package "+d+"\n\nfunc Hello() string { return \""+d+"\" }\n")
	}
	out := filepath.Join(dir, "fix")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, ".")
	cmd.Dir = dir
	// The Mach-O readers under test must see a Mach-O whatever the host builds.
	cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("no go toolchain for the dep fixture: %v: %s", err, b)
	}
	return out
}

// probeFixture probes an absolute real-world fixture, skipping when absent.
func probeFixture(t *testing.T, path string) Digest {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Skipf("fixture %s unavailable: %v", path, err)
	}
	d, err := Probe(path)
	if err != nil {
		t.Fatalf("Probe(%s) error: %v", path, err)
	}
	return d
}

// writeFlutter writes a synthetic Dart AOT snapshot header.
func writeFlutter(t *testing.T) string {
	t.Helper()
	head := append([]byte{0xf5, 0xf5, 0xdc, 0xdc}, make([]byte, 48)...)
	copy(head[20:], "0123456789abcdef0123456789abcdef") // snapshot version string
	return writeTemp(t, "app.so", head)
}

// writeAsar writes a minimal asar archive: 3 files in the header tree and a
// package.json body carrying {"main":"index.js"}, per the asar contract.
func writeAsar(t *testing.T) string {
	t.Helper()
	const indexJS = "console.log(1)\n"
	const pkgJSON = `{"main":"index.js"}`
	const mainJS = "x=1\n"
	payload := indexJS + pkgJSON + mainJS
	header := fmt.Sprintf(
		`{"files":{"index.js":{"size":%d,"offset":"0"},"package.json":{"size":%d,"offset":"%d"},"main.js":{"size":%d,"offset":"%d"}},"main":"index.js"}`,
		len(indexJS), len(pkgJSON), len(indexJS), len(mainJS), len(indexJS)+len(pkgJSON),
	)
	jsonLen := len(header)
	buf := make([]byte, 16, 16+jsonLen+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], 4)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(8+jsonLen))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(4+jsonLen))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(jsonLen))
	buf = append(buf, header...)
	buf = append(buf, payload...)
	return writeTemp(t, "app.asar", buf)
}

// writeTemp writes bytes into the test's own temp dir and returns the path.
func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", p, err)
	}
	return p
}

func TestProbeFatMachO(t *testing.T) {
	d := probeFixture(t, lsPath)
	if d.Kind != "macho" {
		t.Fatalf("kind = %q, want macho", d.Kind)
	}
	if d.Format != "fat" {
		t.Fatalf("format = %q, want fat", d.Format)
	}
	if d.Slices != 2 {
		t.Fatalf("slices = %d, want 2", d.Slices)
	}
	if len(d.Dylibs) == 0 {
		t.Fatalf("dylibs empty for %s", lsPath)
	}
}

func TestProbeGoBinary(t *testing.T) {
	d := probeFixture(t, goFixtureDeps(t, 1))
	if d.Kind != "macho" {
		t.Fatalf("kind = %q, want macho", d.Kind)
	}
	if d.Format != "thin" {
		t.Fatalf("format = %q, want thin", d.Format)
	}
	if d.Slices != 0 {
		t.Fatalf("slices = %d, want 0 for a thin binary", d.Slices)
	}
	if !strings.Contains(d.Toolchain, "go1.") {
		t.Fatalf("toolchain = %q, want it to contain go1.", d.Toolchain)
	}
	if !strings.Contains(d.Mod, "example.com/fix") {
		t.Fatalf("mod = %q, want example.com/fix", d.Mod)
	}
	if len(d.Deps) != 1 || !strings.HasPrefix(d.Deps[0].Path, "example.com/dep") {
		t.Fatalf("deps = %v, want example.com/dep*", d.Deps)
	}
}

func TestProbeTinyAscii(t *testing.T) {
	p := writeTemp(t, "tiny.bin", []byte("abc"))
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "unknown" {
		t.Fatalf("kind = %q, want unknown for 3-byte file", d.Kind)
	}
	if len(d.Notes) == 0 {
		t.Fatalf("notes empty, expected the <4 bytes note")
	}
}

func TestProbeText(t *testing.T) {
	p := writeTemp(t, "plain.txt", []byte("hello lrecon\nsecond line\n"))
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "text" {
		t.Fatalf("kind = %q, want text", d.Kind)
	}
}

func TestProbeAsar(t *testing.T) {
	p := writeAsar(t)
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "asar" {
		t.Fatalf("kind = %q, want asar", d.Kind)
	}
	if d.AsarFiles != 3 {
		t.Fatalf("asar_files = %d, want 3", d.AsarFiles)
	}
	if d.AsarMain != "index.js" {
		t.Fatalf("asar_main = %q, want index.js", d.AsarMain)
	}
}

func TestProbeFlutter(t *testing.T) {
	p := writeFlutter(t)
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "flutter" {
		t.Fatalf("kind = %q, want flutter", d.Kind)
	}
	if d.FlutterHash == "" {
		t.Fatalf("flutter_hash empty, want 32-byte hash")
	}
	if len(d.Notes) == 0 {
		t.Fatalf("notes empty, expected the Dart AOT note")
	}
}

func TestProbeMissingFile(t *testing.T) {
	if _, err := Probe(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("Probe on missing path returned nil error")
	}
}
