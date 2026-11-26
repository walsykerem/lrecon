package main

// Real-artifact tests: each fixture is produced by the genuine toolchain, then
// fed to Probe. They skip when the tool is absent, so the package still passes
// on a machine without it. No produced executable is ever run.

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func realFxCI(t *testing.T) {
	t.Helper()
	if os.Getenv("CI") != "" && os.Getenv("LRECON_REALFX") != "1" {
		t.Skip("RealFx: host-dependent, skipped on CI (set LRECON_REALFX=1 to run)")
	}
}

func realFxLook(t *testing.T, names ...string) string {
	t.Helper()
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	t.Skipf("RealFx: none of %s installed", strings.Join(names, ","))
	return ""
}

func realFxCap(d *Digest, prefix string) (string, bool) {
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, prefix) {
			return c, true
		}
	}
	return "", false
}

func realFxFind(t *testing.T, root, suffix string, budget time.Duration) (string, bool) {
	t.Helper()
	var hit string
	deadline := time.Now().Add(budget)
	complete := true
	_ = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil || hit != "" {
			return nil
		}
		if time.Now().After(deadline) {
			complete = false
			return filepath.SkipAll
		}
		if !e.IsDir() && strings.HasSuffix(p, suffix) {
			hit = p
			return filepath.SkipAll
		}
		return nil
	})
	return hit, complete
}

// TestRealFxOpcache compiles a script with PHP's file cache enabled and probes
// the cache entry PHP wrote.
func TestRealFxOpcache(t *testing.T) {
	realFxCI(t)
	php := realFxLook(t, "php")
	dir := t.TempDir()
	cache := filepath.Join(dir, "cache")
	if err := os.Mkdir(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "s.php")
	if err := os.WriteFile(script, []byte("<?php echo 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The header timestamp is the script mtime, so pin it and read it back.
	want := time.Unix(1700000000, 0)
	if err := os.Chtimes(script, want, want); err != nil {
		t.Fatal(err)
	}
	// PHP 8.5 needs the trailing separator; without it the file cache stays
	// empty. It also refuses to cache a script whose mtime is "just now", so the
	// backdate above is load-bearing.
	cmd := exec.Command(php,
		"-d", "opcache.enable_cli=1",
		"-d", "opcache.file_cache="+cache+string(os.PathSeparator),
		"-d", "opcache.file_cache_only=1",
		script)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("php file cache build: %v\n%s", err, out)
	}
	bin, _ := realFxFind(t, cache, ".bin", 10*time.Second)
	if bin == "" {
		t.Skip("RealFx: php wrote no opcache file cache entry")
	}

	d, err := Probe(bin)
	if err != nil {
		t.Fatalf("Probe(%s): %v", bin, err)
	}
	if d.Kind != "php-opcache" || d.Format != "php-opcache" {
		t.Fatalf("kind/format = %q/%q, want php-opcache", d.Kind, d.Format)
	}
	if d.Coverage == nil || d.Coverage.Parsed != 1 {
		t.Fatalf("coverage = %+v, want one parsed record", d.Coverage)
	}
	if d.BytesScanned != 80 {
		t.Fatalf("bytes_scanned = %d, want the 80-byte LP64 header", d.BytesScanned)
	}
	sysID, ok := realFxCap(&d, "opcache:system_id=")
	if !ok {
		t.Fatalf("no opcache:system_id capability in %v", d.Capabilities)
	}
	sysID = strings.TrimPrefix(sysID, "opcache:system_id=")
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(sysID) {
		t.Fatalf("system_id %q is not 32 hex chars", sysID)
	}
	// The system id is the directory PHP put the entry in.
	if !strings.HasPrefix(bin, cache+string(os.PathSeparator)+sysID+string(os.PathSeparator)) {
		t.Fatalf("cache entry %q is not under <cache>/%s/", bin, sysID)
	}
	memCap, ok1 := realFxCap(&d, "opcache:mem_size=")
	strCap, ok2 := realFxCap(&d, "opcache:str_size=")
	if !ok1 || !ok2 {
		t.Fatalf("missing mem/str size in %v", d.Capabilities)
	}
	mem, err1 := strconv.ParseInt(strings.TrimPrefix(memCap, "opcache:mem_size="), 10, 64)
	str, err2 := strconv.ParseInt(strings.TrimPrefix(strCap, "opcache:str_size="), 10, 64)
	if err1 != nil || err2 != nil || mem <= 0 || mem+str+80 != d.FileSize {
		t.Fatalf("mem=%d str=%d + 80-byte header != file size %d", mem, str, d.FileSize)
	}
	if cap, ok := realFxCap(&d, "opcache:script_timestamp="); !ok || cap != "opcache:script_timestamp=1700000000" {
		t.Fatalf("script_timestamp = %q, want the pinned mtime 1700000000", cap)
	}
}

// TestRealFxBun compiles a script with `bun build --compile` and probes the
// Mach-O __BUN carrier Bun 1.4.0 writes.
func TestRealFxBun(t *testing.T) {
	realFxCI(t)
	bun := realFxLook(t, "bun")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "s.js"), []byte("console.log(\"hi\");\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bun, "build", "--compile", "s.js", "--outfile", "app")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bun build --compile: %v\n%s", err, out)
	}
	app := filepath.Join(dir, "app")

	d, err := Probe(app)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "macho" {
		t.Fatalf("kind = %q, want macho", d.Kind)
	}
	for _, want := range []string{
		"bun:modules=1",
		"bun:entry_id=0",
		"bun:bytecode=0",
		"bun:flags=0xc",
	} {
		if !hasCap(&d, want) {
			t.Fatalf("missing capability %q in %v", want, d.Capabilities)
		}
	}
	if len(d.Deps) != 1 || d.Deps[0].Path != "/$bunfs/root/app" || d.Deps[0].Version == "" {
		t.Fatalf("deps = %v, want the single /$bunfs/root/app module", d.Deps)
	}
	if d.BytesScanned == 0 {
		t.Fatal("bytes_scanned is zero after a successful parse")
	}
	// Coverage is per reader, so count it on a fresh digest claimed directly.
	var one Digest
	runPkgjsReader(t, "bun", app, &one)
	if one.Coverage == nil || one.Coverage.Parsed != 1 {
		t.Fatalf("bun reader coverage = %+v, want one parsed record", one.Coverage)
	}
}

// Uncovered on purpose: `deno compile`, postject's NODE_SEA_BLOB injection and
// `pkg` have no hand-built stand-in, and no test below builds a real artifact
// with them. This used to be three *tests* that always skipped — asserting
// nothing while the package still reported PASS. If one of those artifacts is
// added to testdata, it should become a real fixture test here.

// TestRealFxKlib searches the Kotlin/Gradle caches for a genuine .klib.
func TestRealFxKlib(t *testing.T) {
	realFxCI(t)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("RealFx: no home dir: %v", err)
	}
	var searched []string
	var klib string
	complete := true
	for _, root := range []string{".konan", ".gradle", "Library"} {
		p := filepath.Join(home, root)
		if st, err := os.Stat(p); err != nil || !st.IsDir() {
			continue
		}
		searched = append(searched, p)
		var ok bool
		if klib, ok = realFxFind(t, p, ".klib", 3*time.Second); klib != "" {
			break
		}
		if !ok {
			complete = false
		}
	}
	if klib == "" {
		t.Skipf("RealFx: no .klib under %s within the 3s-per-root budget (complete=%v); kotlinc/kotlinc-native absent",
			strings.Join(searched, ", "), complete)
	}
	d, err := Probe(klib)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Format != "klib" || d.Toolchain == "" || d.Coverage == nil || d.Coverage.Parsed == 0 {
		t.Fatalf("klib digest incomplete: format=%q toolchain=%q coverage=%+v skipped=%v",
			d.Format, d.Toolchain, d.Coverage, d.Skipped)
	}
	if _, ok := realFxCap(&d, "klib:abi="); !ok {
		t.Fatalf("no klib:abi capability in %v", d.Capabilities)
	}
	if len(d.Imports) == 0 {
		t.Fatalf("no declaration names recovered from %s", klib)
	}
}
