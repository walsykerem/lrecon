package main

// inspect_go_binary is cross-checked against the toolchain's own readers on a
// binary this test builds from source: `go version -m` supplies the producer
// string and module path, `go tool nm` supplies the function count that the
// pclntab must agree with. A canned answer satisfies neither oracle. The
// `-s -w` build then shows which half of the answer comes from the file's
// symbol table (PE local names) and which survives its removal (pclntab).

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const tur7b15Module = "example.com/tur7b15"

func tur7b15Exec(t *testing.T, dir, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// tur7b15Build compiles the fixture module for one GOOS/GOARCH. The toolchain
// is the fixture factory, so an absent go binary is a test failure, not a skip.
func tur7b15Build(t *testing.T, dir, goos, goarch, out string, ldflags ...string) string {
	t.Helper()
	args := []string{"build", "-trimpath", "-buildvcs=false", "-o", filepath.Join(dir, out)}
	if len(ldflags) > 0 {
		args = append(args, "-ldflags="+strings.Join(ldflags, " "))
	}
	args = append(args, ".")
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOOS="+goos, "GOARCH="+goarch, "CGO_ENABLED=0",
		"GO111MODULE=on", "GOWORK=off", "GOPROXY=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s/%s %v: %v\n%s", goos, goarch, ldflags, err, b)
	}
	return filepath.Join(dir, out)
}

// tur7b15VersionMeta reads the two fields the linker wrote: the producer string
// on the first line and the main module path in the tab-separated build info.
func tur7b15VersionMeta(t *testing.T, bin string) (toolchain, module string) {
	t.Helper()
	out, err := tur7b15Exec(t, "", "go", "version", "-m", bin)
	if err != nil {
		t.Fatalf("go version -m %s: %v\n%s", bin, err, out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 {
		t.Fatalf("go version -m %s printed nothing", bin)
	}
	i := strings.LastIndex(lines[0], ": ")
	if i < 0 {
		t.Fatalf("go version -m %s first line = %q, want <file>: <toolchain>", bin, lines[0])
	}
	toolchain = lines[0][i+2:]
	for _, line := range lines[1:] {
		f := strings.Split(strings.TrimPrefix(line, "\t"), "\t")
		if len(f) >= 2 && f[0] == "path" && module == "" {
			module = f[1]
		}
	}
	if module == "" {
		t.Fatalf("go version -m %s reports no main module path:\n%s", bin, out)
	}
	return toolchain, module
}

// tur7b15NmText counts the text symbols the binary's symbol table holds.
// runtime.text and runtime.etext are linker range markers, not functions, so
// they have no pclntab entry and are not part of the function count.
func tur7b15NmText(t *testing.T, bin string) (int, string) {
	t.Helper()
	out, err := tur7b15Exec(t, "", "go", "tool", "nm", bin)
	if err != nil {
		t.Fatalf("go tool nm %s: %v\n%s", bin, err, out)
	}
	n := 0
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) != 3 || (f[1] != "T" && f[1] != "t") {
			continue
		}
		if f[2] == "runtime.text" || f[2] == "runtime.etext" {
			continue
		}
		n++
	}
	return n, out
}

func tur7b15Op(t *testing.T, bin string) map[string]any {
	t.Helper()
	res, err := runOp("inspect_go_binary", bin)
	if err != nil {
		t.Fatalf("inspect_go_binary(%s): %v", bin, err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("inspect_go_binary(%s): result does not marshal: %v", bin, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("inspect_go_binary(%s): result is not a JSON object: %s", bin, b)
	}
	if s, ok := m["skipped"]; ok {
		t.Fatalf("inspect_go_binary(%s) skipped a real Go build: %v", bin, s)
	}
	return m
}

func tur7b15Str(t *testing.T, m map[string]any, key, bin string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("inspect_go_binary(%s) field %q is %T, want string (%v)", bin, key, m[key], m)
	}
	return s
}

func TestTur7Bucket15GoBinary(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"),
		[]byte("module "+tur7b15Module+"\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "package main\n\n//go:noinline\nfunc tur7B15Marker(x int) int { return x*3 + 1 }\n\nfunc main() { println(tur7B15Marker(4)) }\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	// --- ELF: every field must equal what the toolchain reads from the file ---
	elf := tur7b15Build(t, dir, "linux", "amd64", "fixture.elf")
	goVersion, module := tur7b15VersionMeta(t, elf)
	if module != tur7b15Module {
		t.Fatalf("go version -m module = %q, want %q", module, tur7b15Module)
	}
	funcs, nmOut := tur7b15NmText(t, elf)
	if !strings.Contains(nmOut, "main.tur7B15Marker") {
		t.Fatalf("go tool nm on the fixture lacks main.tur7B15Marker:\n%s", nmOut)
	}

	got := tur7b15Op(t, elf)
	if kind := tur7b15Str(t, got, "kind", elf); kind != "elf" {
		t.Fatalf("kind = %q, want elf", kind)
	}
	wantToolchain := goVersion + " linux/amd64 trimpath"
	if toolchain := tur7b15Str(t, got, "toolchain", elf); toolchain != wantToolchain {
		t.Fatalf("toolchain = %q, go version -m says %q", toolchain, wantToolchain)
	}
	if m := tur7b15Str(t, got, "module", elf); m != module {
		t.Fatalf("module = %q, go version -m says %q", m, module)
	}
	wantNames := "pclntab:" + strconv.Itoa(funcs)
	if names := tur7b15Str(t, got, "names", elf); names != wantNames {
		t.Fatalf("names = %q, go tool nm counts %d text functions (%q)", names, funcs, wantNames)
	}

	// The same source stripped of its symbol table: the toolchain reader loses
	// the answer, while the build-info blob and pclntab keep theirs.
	elfStripped := tur7b15Build(t, dir, "linux", "amd64", "fixture-stripped.elf", "-s", "-w")
	if out, err := tur7b15Exec(t, "", "go", "tool", "nm", elfStripped); err == nil {
		t.Fatalf("go tool nm read a -s -w ELF symbol table:\n%s", out)
	}
	stripped := tur7b15Op(t, elfStripped)
	if toolchain := tur7b15Str(t, stripped, "toolchain", elfStripped); toolchain != wantToolchain {
		t.Fatalf("-s -w toolchain = %q, want the surviving build info %q", toolchain, wantToolchain)
	}
	if names := tur7b15Str(t, stripped, "names", elfStripped); names != wantNames {
		t.Fatalf("-s -w names = %q, want the same pclntab count %q", names, wantNames)
	}

	// --- PE: here stripping does change the answer, field for field ---
	pe := tur7b15Build(t, dir, "windows", "amd64", "fixture.exe")
	peStripped := tur7b15Build(t, dir, "windows", "amd64", "fixture-stripped.exe", "-s", "-w")
	before := tur7b15Op(t, pe)
	after := tur7b15Op(t, peStripped)
	beforeNames := tur7b15Str(t, before, "names", pe)
	if !strings.HasPrefix(beforeNames, "local:") {
		t.Fatalf("PE names = %q, want a local:<count> from the COFF symbol table", beforeNames)
	}
	if n, _ := strconv.Atoi(strings.TrimPrefix(beforeNames, "local:")); n <= 0 {
		t.Fatalf("PE names = %q, want a positive symbol count", beforeNames)
	}
	if afterNames := tur7b15Str(t, after, "names", peStripped); afterNames != nameNotRecovered {
		t.Fatalf("-s -w PE names = %q, want %q after the symbol table is gone", afterNames, nameNotRecovered)
	}
	peVersion, peModule := tur7b15VersionMeta(t, peStripped)
	wantPE := peVersion + " windows/amd64 trimpath"
	for _, leg := range []struct {
		bin string
		m   map[string]any
	}{{pe, before}, {peStripped, after}} {
		if toolchain := tur7b15Str(t, leg.m, "toolchain", leg.bin); toolchain != wantPE {
			t.Fatalf("PE toolchain = %q, want %q", toolchain, wantPE)
		}
		if m := tur7b15Str(t, leg.m, "module", leg.bin); m != peModule {
			t.Fatalf("PE module = %q, go version -m says %q", m, peModule)
		}
	}
}
