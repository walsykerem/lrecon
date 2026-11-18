package main

import (
	"archive/zip"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// jebdFakes puts exactly the named shims on PATH and nothing else, so a tool
// the case does not name is genuinely absent (no /usr/bin fallback).
func jebdFakes(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range scripts {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	return dir
}

// jebdFakeApktoolDecode is apktool d: it creates the -o dir and logs a run, so
// a test can prove the fresh path did not decode a second time.
const jebdFakeApktoolDecode = `printf x >> "$0.calls"
out=
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
  shift
done
/bin/mkdir -p "$out/smali"
printf 'I: Using Apktool 2.9.3\n'`

// jebdDex is a synthetic DEX with two classes: Alpha (a, plus abstract b) and
// Beta (c), in class_def order. Every table the op derefs is laid out for real.
func jebdDex(t *testing.T) []byte {
	t.Helper()
	strs := []string{"Lcom/example/Alpha;", "a", "b", "Lcom/example/Beta;", "c"}
	var data []byte
	offs := make([]uint32, len(strs))
	for i, s := range strs {
		offs[i] = uint32(dexHeaderSize + len(data))
		data = append(data, byte(len(s))) // every fixture string is under 128 bytes
		data = append(data, s...)
		data = append(data, 0)
	}
	strOff := dexHeaderSize + len(data)
	typeOff := strOff + 4*len(strs)
	metOff := typeOff + 2*4
	clsOff := metOff + 3*8
	// Alpha: counts 0,0,2,0; methods (diff 0, public, code 0x10) and (diff 1,
	// abstract 0x400, code_off 0). Beta: counts 0,0,1,0; (diff 2, public, code).
	alpha := []byte{0, 0, 2, 0, 0, 0x01, 0x10, 1, 0x80, 0x08, 0}
	beta := []byte{0, 0, 1, 0, 2, 0x01, 0x10}
	cdAlpha := clsOff + 2*32
	cdBeta := cdAlpha + len(alpha)
	b := make([]byte, cdBeta+len(beta))
	copy(b, "dex\n035\x00")
	le := binary.LittleEndian
	le.PutUint32(b[0x20:], uint32(len(b)))
	le.PutUint32(b[0x24:], dexHeaderSize)
	le.PutUint32(b[0x28:], dexEndianTag)
	le.PutUint32(b[0x38:], uint32(len(strs)))
	le.PutUint32(b[0x3C:], uint32(strOff))
	le.PutUint32(b[0x40:], 2)
	le.PutUint32(b[0x44:], uint32(typeOff))
	le.PutUint32(b[0x58:], 3)
	le.PutUint32(b[0x5C:], uint32(metOff))
	le.PutUint32(b[0x60:], 2)
	le.PutUint32(b[0x64:], uint32(clsOff))
	copy(b[dexHeaderSize:], data)
	for i, o := range offs {
		le.PutUint32(b[strOff+4*i:], o)
	}
	le.PutUint32(b[typeOff:], 0)                           // Alpha descriptor
	le.PutUint32(b[typeOff+4:], 3)                         // Beta descriptor
	putMethod := func(at int, class uint16, name uint32) { // class_idx, proto_idx, name_idx
		le.PutUint16(b[at:], class)
		le.PutUint16(b[at+2:], 0)
		le.PutUint32(b[at+4:], name)
	}
	putMethod(metOff, 0, 1)
	putMethod(metOff+8, 0, 2)
	putMethod(metOff+16, 1, 4)
	le.PutUint32(b[clsOff:], 0) // class_idx, then superclass_idx at +8 and class_data_off at +24
	le.PutUint32(b[clsOff+8:], dexNoIndex)
	le.PutUint32(b[clsOff+24:], uint32(cdAlpha))
	le.PutUint32(b[clsOff+32:], 1)
	le.PutUint32(b[clsOff+40:], dexNoIndex)
	le.PutUint32(b[clsOff+56:], uint32(cdBeta))
	copy(b[cdAlpha:], alpha)
	copy(b[cdBeta:], beta)
	return b
}

func jebdWriteApk(t *testing.T, path string, dex []byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(dex); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func jebdApk(t *testing.T, dex []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "app.apk")
	jebdWriteApk(t, p, dex)
	return p
}

func jebdCalls(t *testing.T, tool string) int {
	t.Helper()
	b, err := os.ReadFile(tool + ".calls")
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "x")
}

// TestJebDYesMissingToolsSkip: every Y item refuses with a reason naming both
// the tool and its alternative, never an empty "success".
func TestJebDYesMissingToolsSkip(t *testing.T) {
	jebdFakes(t, nil)
	cases := []struct{ name, target, tool, alt string }{
		{"decompile_jeb_item", "app.apk:com.example.A", "jadx", "single-class"},
		{"open_jeb_project", "app.apk", "apktool", "apktool d"},
		{"inspect_apktool_client", t.TempDir(), "apktool", "apktool.yml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, err := runOp(c.name, c.target)
			if err != nil {
				t.Fatalf("%s with no PATH: %v", c.name, err)
			}
			sk, ok := v.(*skip)
			if !ok {
				t.Fatalf("%s = %#v, want a skip", c.name, v)
			}
			if len(sk.Reason) < 8 || strings.Contains(sk.Reason, "TODO") || strings.Contains(sk.Reason, "not implemented") {
				t.Fatalf("%s skip reason is not a sentence: %q", c.name, sk.Reason)
			}
			if !strings.Contains(sk.Reason, c.tool) || !strings.Contains(sk.Reason, c.alt) {
				t.Fatalf("%s skip reason %q does not name %q and %q", c.name, sk.Reason, c.tool, c.alt)
			}
		})
	}
}

func TestJebDDecompileReadsJadxOutput(t *testing.T) {
	const want = "package com.example;\n\npublic class A { void a() {} }\n"
	jebdFakes(t, map[string]string{"jadx": `out=
while [ $# -gt 0 ]; do
  if [ "$1" = "--single-class-output" ]; then out="$2"; shift 2; continue; fi
  shift
done
printf 'package com.example;\n\npublic class A { void a() {} }\n' > "$out"
printf 'INFO  - loading\n'`})
	v, err := runOp("decompile_jeb_item", "app.apk:com.example.A")
	if err != nil {
		t.Fatal(err)
	}
	res, ok := v.(jebdSource)
	if !ok {
		t.Fatalf("decompile_jeb_item = %#v, want jebdSource", v)
	}
	if !res.Found || res.Class != "com.example.A" || res.Source != want || res.Bytes != len(want) {
		t.Fatalf("decompile_jeb_item = %+v, want class com.example.A and %d source bytes", res, len(want))
	}
}

func TestJebDOpenProjectFreshness(t *testing.T) {
	toolDir := jebdFakes(t, map[string]string{"apktool": jebdFakeApktoolDecode})
	apk := jebdApk(t, jebdDex(t))

	v, err := runOp("open_jeb_project", apk)
	if err != nil {
		t.Fatal(err)
	}
	first, ok := v.(jebdProject)
	if !ok {
		t.Fatalf("open_jeb_project = %#v, want jebdProject", v)
	}
	if first.Fresh || !first.Decoded || first.Dir != apk+".jebproj" {
		t.Fatalf("first decode = %+v, want fresh=false decoded=true dir=%s", first, apk+".jebproj")
	}
	if st, err := os.Stat(first.Dir); err != nil || !st.IsDir() {
		t.Fatalf("project dir %s was not created: %v", first.Dir, err)
	}
	if _, err := os.Stat(filepath.Join(first.Dir, "classes.dex")); err != nil {
		t.Fatalf("project carries no classes.dex marker: %v", err)
	}
	if got := jebdCalls(t, filepath.Join(toolDir, "apktool")); got != 1 {
		t.Fatalf("apktool ran %d times, want 1", got)
	}

	v, err = runOp("open_jeb_project", apk)
	if err != nil {
		t.Fatal(err)
	}
	if again := v.(jebdProject); !again.Fresh || again.Decoded {
		t.Fatalf("unchanged APK = %+v, want fresh=true decoded=false", again)
	}
	if got := jebdCalls(t, filepath.Join(toolDir, "apktool")); got != 1 {
		t.Fatalf("apktool ran %d times on the fresh path, want 1", got)
	}

	// y6 kill test: one byte added to the APK's classes.dex must force a decode.
	jebdWriteApk(t, apk, append(jebdDex(t), '!'))
	v, err = runOp("open_jeb_project", apk)
	if err != nil {
		t.Fatal(err)
	}
	if stale := v.(jebdProject); stale.Fresh || !stale.Decoded {
		t.Fatalf("changed classes.dex = %+v, want fresh=false decoded=true", stale)
	}
	if got := jebdCalls(t, filepath.Join(toolDir, "apktool")); got != 2 {
		t.Fatalf("apktool ran %d times, want 2 after the dex changed", got)
	}
}

func TestJebDInspectApktoolClient(t *testing.T) {
	// The java probe reads <java-home>/release, so the fake is a JDK layout
	// (bin/java plus a release file), not a script that prints a version.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	java := filepath.Join(home, "bin", "java")
	if err := os.WriteFile(java, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	release := "IMPLEMENTOR=\"Fake\"\nJAVA_VERSION=\"21.0.1\"\n"
	if err := os.WriteFile(filepath.Join(home, "release"), []byte(release), 0o644); err != nil {
		t.Fatal(err)
	}
	toolDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(toolDir, "apktool"), []byte("#!/bin/sh\nprintf '2.9.3\\n'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(home, "bin")+string(os.PathListSeparator)+toolDir)
	dir := t.TempDir()
	yml := filepath.Join(dir, "apktool.yml")
	body := "!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nversion: 2.8.1\nversionInfo: 2.9.3\n"
	if err := os.WriteFile(yml, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := runOp("inspect_apktool_client", dir)
	if err != nil {
		t.Fatal(err)
	}
	res := v.(jebdClient)
	if res.Apktool != "2.9.3" {
		t.Fatalf("apktool = %q, want 2.9.3", res.Apktool)
	}
	real, err := filepath.EvalSymlinks(java)
	if err != nil {
		real = java
	}
	if want := "21.0.1 (" + real + ")"; res.Java != want {
		t.Fatalf("java = %q, want %q from the release file", res.Java, want)
	}
	if res.DecompiledBy != "2.8.1" || res.ApktoolYML != yml {
		t.Fatalf("decompiled_by = %q from %q, want 2.8.1 from %s", res.DecompiledBy, res.ApktoolYML, yml)
	}
}

// TestJebDToolFailureIsError: a failing tool is an error carrying its own
// stderr line, never a skip and never an invented result.
func TestJebDToolFailureIsError(t *testing.T) {
	const jadxErr = "ERROR - class com.example.A not found"
	t.Run("decompile_jeb_item", func(t *testing.T) {
		jebdFakes(t, map[string]string{"jadx": "printf '" + jadxErr + "\\n' >&2\nexit 3"})
		if _, err := runOp("decompile_jeb_item", "app.apk:com.example.A"); err == nil || !strings.Contains(err.Error(), jadxErr) {
			t.Fatalf("error = %v, want it to carry %q", err, jadxErr)
		}
	})
	const apktoolErr = "brut.androlib.AndrolibException: Could not decode"
	t.Run("open_jeb_project", func(t *testing.T) {
		jebdFakes(t, map[string]string{"apktool": "printf '" + apktoolErr + "\\n' >&2\nexit 3"})
		apk := jebdApk(t, jebdDex(t))
		if _, err := runOp("open_jeb_project", apk); err == nil || !strings.Contains(err.Error(), apktoolErr) {
			t.Fatalf("error = %v, want it to carry %q", err, apktoolErr)
		}
	})
	const versionErr = "Unsupported command line"
	t.Run("inspect_apktool_client", func(t *testing.T) {
		jebdFakes(t, map[string]string{"apktool": "printf '" + versionErr + "\\n' >&2\nexit 3"})
		if _, err := runOp("inspect_apktool_client", t.TempDir()); err == nil || !strings.Contains(err.Error(), versionErr) {
			t.Fatalf("error = %v, want it to carry %q", err, versionErr)
		}
	})
}

// TestJebDSilentToolSaysSo: exit 0 with nothing produced must not be reported
// as a decoded class or a project dir.
func TestJebDSilentToolSaysSo(t *testing.T) {
	t.Run("decompile_jeb_item", func(t *testing.T) {
		jebdFakes(t, map[string]string{"jadx": "exit 0"})
		v, err := runOp("decompile_jeb_item", "app.apk:com.example.A")
		if err != nil {
			t.Fatal(err)
		}
		res := v.(jebdSource)
		if res.Found || res.Class != "" || res.Source != "" {
			t.Fatalf("silent jadx = %+v, want found=false with no class claimed", res)
		}
		if !strings.Contains(res.Note, "no class.java") {
			t.Fatalf("note = %q, want it to say jadx wrote nothing", res.Note)
		}
	})
	t.Run("open_jeb_project", func(t *testing.T) {
		jebdFakes(t, map[string]string{"apktool": "exit 0"})
		apk := jebdApk(t, jebdDex(t))
		_, err := runOp("open_jeb_project", apk)
		if err == nil || !strings.Contains(err.Error(), "no project dir") {
			t.Fatalf("error = %v, want it to say no project dir was created", err)
		}
		if _, statErr := os.Stat(apk + ".jebproj"); statErr == nil {
			t.Fatal("a project dir exists after a silent apktool")
		}
	})
	t.Run("inspect_apktool_client", func(t *testing.T) {
		jebdFakes(t, map[string]string{"apktool": "exit 0"})
		v, err := runOp("inspect_apktool_client", t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		res := v.(jebdClient)
		if res.Apktool != "" {
			t.Fatalf("apktool = %q, want empty for a silent --version", res.Apktool)
		}
		if !strings.Contains(strings.Join(res.Notes, "; "), "printed nothing") {
			t.Fatalf("notes = %v, want one naming the silent --version", res.Notes)
		}
	})
}

func TestJebDListUnitsProjectDir(t *testing.T) {
	dex := jebdDex(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "classes.dex")
	if err := os.WriteFile(path, dex, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{dir, path} { // a project dir, and the dex itself
		v, err := runOp("list_jeb_units", target)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		res := v.(jebdUnits)
		if len(res.Errors) != 0 {
			t.Fatalf("%s errors = %v, want none", target, res.Errors)
		}
		if len(res.Units) != 2 {
			t.Fatalf("%s units = %+v, want 2 classes", target, res.Units)
		}
		want := []jebdUnit{
			{Class: "Lcom/example/Alpha;", Methods: []string{"a"}, Abstract: []string{"b"}},
			{Class: "Lcom/example/Beta;", Methods: []string{"c"}},
		}
		if res.Units[0].Class != want[0].Class || res.Units[1].Class != want[1].Class {
			t.Fatalf("%s class order = [%s %s], want [%s %s]", target,
				res.Units[0].Class, res.Units[1].Class, want[0].Class, want[1].Class)
		}
		for i := range want {
			if !slices.Equal(res.Units[i].Methods, want[i].Methods) || !slices.Equal(res.Units[i].Abstract, want[i].Abstract) {
				t.Fatalf("%s unit %s = methods %v abstract %v, want methods %v abstract %v", target,
					want[i].Class, res.Units[i].Methods, res.Units[i].Abstract, want[i].Methods, want[i].Abstract)
			}
		}
	}
}

func TestJebDListUnitsNoLayout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "smali"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runOp("list_jeb_units", dir)
	if err == nil || !strings.Contains(err.Error(), "no classes") {
		t.Fatalf("error = %v, want a descriptive no-classes*.dex error", err)
	}
}

// TestOpenJebProjectCleansFailedDecode: apktool that creates the temp tree and
// then fails must not leave it behind. The op refuses a temp dir that already
// exists, so a leaked tree would poison every later call for this APK.
func TestOpenJebProjectCleansFailedDecode(t *testing.T) {
	jebdFakes(t, map[string]string{"apktool": `printf x >> "$0.calls"
out=
while [ $# -gt 0 ]; do
  if [ "$1" = "-o" ]; then out="$2"; shift 2; continue; fi
  shift
done
/bin/mkdir -p "$out/smali"
printf 'brut.androlib.AndrolibException: Could not decode resources\n' >&2
exit 3`})
	apk := jebdApk(t, jebdDex(t))
	if _, err := runOp("open_jeb_project", apk); err == nil || !strings.Contains(err.Error(), "Could not decode") {
		t.Fatalf("failed decode: error = %v, want apktool's stderr", err)
	}
	left, err := filepath.Glob(apk + ".jebproj.tmp-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("failed decode left %v behind", left)
	}
	if _, err := os.Stat(apk + ".jebproj"); !os.IsNotExist(err) {
		t.Fatalf("failed decode left a project at %s.jebproj: %v", apk, err)
	}

	// The next call must decode, not refuse the temp dir the failure created.
	jebdFakes(t, map[string]string{"apktool": jebdFakeApktoolDecode})
	m := fields(t, run(t, "open_jeb_project", apk))
	if m["fresh"] != false || m["decoded"] != true || m["engine"] != "apktool" {
		t.Fatalf("second open after a failed decode = %v", m)
	}
	if _, err := os.Stat(filepath.Join(apk+".jebproj", "classes.dex")); err != nil {
		t.Fatalf("project has no classes.dex marker: %v", err)
	}
	old, err := filepath.Glob(apk + ".jebproj.old-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 0 {
		t.Fatalf("stale trees left behind: %v", old)
	}
}
