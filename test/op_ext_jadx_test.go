package main

// The APK fixture behind jadx_no_res (502) and jadx_single_class_full (506)
// must carry a real classes.dex: with no dex jadx answers "Load failed! No
// classes decompile!" and both items land on no_engine instead of ok.
// 506's measurement argument must also be a class the fixture holds.

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	jadxFixtureAPK  = "testdata/fixtures/apk/resources.apk"
	jadxFixtureFQCN = "com.example.fix.Main"
)

// TestJadxFixtureAPKHasDex: the shipped APK holds a DEX with the fixed class
// names the measurement and the docs use.
func TestJadxFixtureAPKHasDex(t *testing.T) {
	zr, err := zip.OpenReader(jadxFixtureAPK)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var dex []byte
	for _, f := range zr.File {
		if f.Name != "classes.dex" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		dex, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(dex) == 0 {
		t.Fatalf("%s has no classes.dex: jadx answers 'No classes decompile!'", jadxFixtureAPK)
	}
	if !bytes.HasPrefix(dex, []byte("dex\n")) {
		t.Fatalf("classes.dex magic = %q, want dex\\n", dex[:min(8, len(dex))])
	}
	for _, name := range []string{"Main", "Helper", "Util"} {
		desc := []byte("Lcom/example/fix/" + name + ";")
		if !bytes.Contains(dex, desc) {
			t.Errorf("classes.dex has no %s: fixture no longer holds %s", desc, name)
		}
	}
}

// TestJadxSingleClassArgIsInFixture: tools/ext_measure.py's FULL table feeds
// --ext-op jadx_single_class_full a real FQCN, so a fixture rename cannot
// silently turn the measurement into no_engine again.
func TestJadxSingleClassArgIsInFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "env", "archive", "tools", "ext_measure.py"))
	if os.IsNotExist(err) {
		t.Skipf("ext_measure.py is archived under env/, not shipped")
	}
	if err != nil {
		t.Fatal(err)
	}
	want := `"jadx_single_class_full": ("apk", ["` + jadxFixtureFQCN + `"]),`
	if !strings.Contains(string(b), want) {
		t.Fatalf("tools/ext_measure.py FULL must feed jadx_single_class_full %q (line: %s)", jadxFixtureFQCN, want)
	}
}
