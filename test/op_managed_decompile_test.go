package main

// decompile_all settles the file kind before ghidra: ghidra headless decompiles
// native machine code only, so a managed assembly goes to the CIL reader and a
// bytecode target still gets an honest refusal. The finder is stubbed to fail
// the test if the native path is reached for either.
//
// The CIL test builds a real assembly with the local .NET SDK instead of
// hand-writing a PE: a synthetic image would prove nothing about a real
// compiler's headers, tokens and string heap. When the toolchain is missing the
// test skips, it does not pass. It also skips in CI and unless opted in locally
// (LRECON_OPS_DOTNET=1): the build can restore from the network.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// failGhidra replaces the finder with one that fails the test when consulted.
func failGhidra(t *testing.T) {
	t.Helper()
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) {
		t.Fatal("ghidra was consulted for a non-native kind")
		return "", "", errors.New("unreachable")
	}
}

func TestDecompileAllRefusesNonNative(t *testing.T) {
	cases := []struct {
		name string
		path string
		kind string
	}{
		{"il2cpp-metadata", writeTemp(t, "global-metadata.dat", []byte("\xaf\x1b\xb1\xfa metadata")), "il2cpp-metadata"},
	}
	failGhidra(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if d, err := Probe(c.path); err != nil || d.Kind != c.kind {
				t.Fatalf("fixture kind = %q (%v), want %s", d.Kind, err, c.kind)
			}
			res, err := ops["decompile_all"].run(c.path)
			if err != nil {
				t.Fatalf("%s is a skip, not an error: %v", c.kind, err)
			}
			s, ok := res.(*skip)
			if !ok {
				t.Fatalf("%s answered %T, want *skip", c.kind, res)
			}
			if !strings.HasPrefix(s.Reason, c.kind+": no decompiler kind here") {
				t.Errorf("skip reason %q does not name the kind", s.Reason)
			}
			if !strings.Contains(s.Reason, "ghidra headless decompiles native code only") {
				t.Errorf("skip reason %q does not name the ghidra limit", s.Reason)
			}
		})
	}
}

func TestDecompileAllNativeAbsentGhidra(t *testing.T) {
	if _, err := os.Stat(fixtureMacho); err != nil {
		t.Skipf("%s not present", fixtureMacho)
	}
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) { return "", "", errors.New("not installed") }
	res, err := ops["decompile_all"].run(fixtureMacho)
	if err != nil {
		t.Fatalf("absent ghidra is a skip, not an error: %v", err)
	}
	s, ok := res.(*skip)
	if !ok {
		t.Fatalf("absent ghidra answered %T, want *skip", res)
	}
	if !strings.Contains(s.Reason, "analyzeHeadless not installed") {
		t.Errorf("skip reason %q does not name the missing tool", s.Reason)
	}
	if strings.Contains(s.Reason, "no decompiler kind here") {
		t.Errorf("native %s took the non-native refusal: %q", fixtureMacho, s.Reason)
	}
}

// ------------------------------------------------------------ real .NET build

// cilDotnet finds a local SDK or skips: a machine without one cannot check a
// real managed image, and a fabricated PE would not be a check at all.
func cilDotnet(t *testing.T) string {
	t.Helper()
	if os.Getenv("CI") != "" {
		t.Skip("real dotnet build is not hermetic: skipped in CI")
	}
	if os.Getenv("LRECON_OPS_DOTNET") != "1" {
		t.Skip("real dotnet build is opt-in: set LRECON_OPS_DOTNET=1 locally")
	}
	for _, p := range []string{"/usr/local/share/dotnet/dotnet", "/usr/share/dotnet/dotnet"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	p, err := exec.LookPath("dotnet")
	if err != nil {
		t.Skip("dotnet SDK not installed: the CIL test needs a real managed assembly")
	}
	return p
}

// buildCILDemo compiles a small library and returns its Demo.dll path.
func buildCILDemo(t *testing.T) string {
	t.Helper()
	dotnet := cilDotnet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	ver, err := exec.CommandContext(ctx, dotnet, "--version").Output()
	if err != nil {
		t.Skipf("dotnet --version failed: %v", err)
	}
	tfm := "net" + strings.SplitN(strings.TrimSpace(string(ver)), ".", 2)[0] + ".0"

	dir := t.TempDir()
	proj := filepath.Join(dir, "Demo")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	csproj := `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Library</OutputType>
    <TargetFramework>` + tfm + `</TargetFramework>
    <AssemblyName>Demo</AssemblyName>
    <Nullable>disable</Nullable>
    <ImplicitUsings>disable</ImplicitUsings>
    <Optimize>false</Optimize>
    <Deterministic>true</Deterministic>
  </PropertyGroup>
</Project>
`
	// Source chosen so the IL stays short and hand-checkable: a field add, a
	// comparison branch and one ldstr plus a static call.
	src := `namespace Demo
{
    public static class Program
    {
        public static int Add(int a, int b)
        {
            return a + b;
        }

        public static int Choose(int x)
        {
            if (x > 0) { return 1; }
            return 0;
        }

        public static int Twice(int a)
        {
            return Add(a, a);
        }

        public static string Greet(string name)
        {
            return "hi " + name;
        }
    }
}
`
	files := map[string]string{"Demo.csproj": csproj, "Program.cs": src}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(proj, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(dir, "out")
	cmd := exec.CommandContext(ctx, dotnet, "build", filepath.Join(proj, "Demo.csproj"),
		"-c", "Release", "-o", out, "--nologo", "-v", "q")
	cmd.Env = append(os.Environ(),
		"DOTNET_CLI_TELEMETRY_OPTOUT=1", "DOTNET_NOLOGO=1", "DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("dotnet build failed: %v\n%s", err, tail(out, b, 800))
	}
	dll := filepath.Join(out, "Demo.dll")
	if _, err := os.Stat(dll); err != nil {
		t.Skipf("dotnet build produced no Demo.dll: %v", err)
	}
	return dll
}

func tail(offset string, b []byte, n int) string {
	s := string(b)
	if len(s) > n {
		s = s[len(s)-n:]
	}
	return offset + "\n" + s
}

// ------------------------------------------------------------- CIL listing

func TestDecompileAllManagedCIL(t *testing.T) {
	dll := buildCILDemo(t)
	failGhidra(t)
	if d, err := Probe(dll); err != nil || d.Kind != "pe-dotnet" {
		t.Fatalf("built assembly kind = %q (%v), want pe-dotnet", d.Kind, err)
	}
	res, err := ops["decompile_all"].run(dll)
	if err != nil {
		t.Fatalf("managed decompile errored: %v", err)
	}
	l, ok := res.(cilListing)
	if !ok {
		t.Fatalf("managed decompile answered %T, want cilListing", res)
	}
	if l.Format != "ecma-335-cil" || l.Assembly != "Demo" || l.Module != "Demo.dll" {
		t.Fatalf("header = %q %q %q, want ecma-335-cil Demo Demo.dll", l.Format, l.Assembly, l.Module)
	}
	if l.Types != 2 || l.Methods != 4 || l.Disassembled != 4 || l.NoBody != 0 || l.Failed != 0 {
		t.Errorf("counts types=%d methods=%d disassembled=%d no_body=%d failed=%d, want 2/4/4/0/0",
			l.Types, l.Methods, l.Disassembled, l.NoBody, l.Failed)
	}
	if l.Capped {
		t.Errorf("a three-method assembly was capped")
	}

	method := func(name string) cilMethod {
		t.Helper()
		for _, ty := range l.Listing {
			for _, m := range ty.Methods {
				if m.Name == name {
					return m
				}
			}
		}
		t.Fatalf("method %s missing from the listing", name)
		return cilMethod{}
	}

	// Add is the smallest body in the assembly: the raw bytes at the MethodDef
	// RVA are 00 02 03 58 0A 2B 00 06 2A (nop, ldarg.0, ldarg.1, add, stloc.0,
	// br.s +0, ldloc.0, ret), so these exact lines come from the file.
	add := method("Add")
	wantAdd := []string{
		"IL_0000: nop",
		"IL_0001: ldarg.0",
		"IL_0002: ldarg.1",
		"IL_0003: add",
		"IL_0004: stloc.0",
		"IL_0005: br.s IL_0007",
		"IL_0007: ldloc.0",
		"IL_0008: ret",
	}
	if add.Header != "fat" || add.CodeSize != 9 || add.MaxStack != 2 {
		t.Errorf("Add header=%q code_size=%d max_stack=%d, want fat/9/2", add.Header, add.CodeSize, add.MaxStack)
	}
	if got := strings.Join(add.IL, "\n"); got != strings.Join(wantAdd, "\n") {
		t.Errorf("Add IL =\n%s\nwant\n%s", got, strings.Join(wantAdd, "\n"))
	}

	choose := method("Choose")
	for _, line := range []string{
		"IL_0002: ldc.i4.0",
		"IL_0003: cgt",
		"IL_0007: brfalse.s IL_000E",
		"IL_000A: ldc.i4.1",
		"IL_000C: br.s IL_0012",
		"IL_0013: ret",
	} {
		if !containsStr(choose.IL, line) {
			t.Errorf("Choose IL missing %q, got %v", line, choose.IL)
		}
	}

	// Twice calls its own assembly's Add: the raw bytes are
	// 00 02 02 28 01 00 00 06 0A, a MethodDef token that must keep its owner.
	if twice := method("Twice"); !containsStr(twice.IL, "IL_0003: call Demo.Program::Add") {
		t.Errorf("Twice IL = %v, want the internal call resolved to Demo.Program::Add", twice.IL)
	}

	// Greet proves cross-assembly resolution: MemberRef 0x0A00000C with a
	// TypeRef parent in the System.Runtime AssemblyRef prints as a name.
	greet := method("Greet")
	for _, line := range []string{
		`IL_0001: ldstr "hi "`,
		"IL_0007: call [System.Runtime]System.String::Concat",
	} {
		if !containsStr(greet.IL, line) {
			t.Errorf("Greet IL missing %q, got %v", line, greet.IL)
		}
	}
	for _, ty := range l.Listing {
		for _, m := range ty.Methods {
			for _, line := range m.IL {
				if strings.Contains(line, "0x0A0000") || strings.Contains(line, "0x060000") {
					t.Errorf("%s left a raw token unresolved: %q", m.Name, line)
				}
			}
		}
	}
}

// TestCILTwoByteSwitchAndReserved covers operand widths that a small C# method
// does not emit: the 0xFE prefix table, InlineI8/R, ShortInlineR, a switch
// table and a reserved opcode. Bytes are ECMA-335 literals.
func TestCILTwoByteSwitchAndReserved(t *testing.T) {
	x := &cilIndex{c: &cliView{md: cliMetadata{data: map[string][]byte{}}}}
	code := []byte{
		0xFE, 0x09, 0x03, 0x00, // ldarg 3 (InlineVar is two bytes)
		0x21, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, // ldc.i8
		0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x3F, // ldc.r8 1.5
		0x22, 0x00, 0x00, 0xC0, 0x3F, // ldc.r4 1.5
		0x45, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // switch (0, +2)
		0x2B, 0xFE, // br.s -2 -> IL_0000
		0x24, // reserved
	}
	want := []string{
		"IL_0000: ldarg 3",
		"IL_0004: ldc.i8 72623859790382856",
		"IL_000D: ldc.r8 1.5",
		"IL_0016: ldc.r4 1.5",
		"IL_001B: switch (IL_0028, IL_002A)",
		"IL_0028: br.s IL_0028",
		"IL_002A: <reserved 0x24>",
	}
	lines, truncated := disassembleCIL(code, x, maxCILPerMethod)
	if truncated {
		t.Errorf("a complete body was reported truncated")
	}
	if got := strings.Join(lines, "\n"); got != strings.Join(want, "\n") {
		t.Errorf("decoded =\n%s\nwant\n%s", got, strings.Join(want, "\n"))
	}
}
