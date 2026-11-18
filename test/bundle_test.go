package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The .app is the artifact a reader opens, so its format stays electron even
// though the asar scan sets asar on the same digest.
func TestBundleAppKeepsElectronFormat(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Studio.app")
	res := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAsarArchive(t, res, "app.asar", map[string][]byte{
		"package.json": []byte(`{"name":"studio","version":"1.2.3","main":"dist/main.js"}`),
		"dist/main.js": []byte("console.log(1)\n"),
	})
	d, err := Probe(app)
	if err != nil {
		t.Fatal(err)
	}
	if d.Kind != "app" || d.Format != "electron" {
		t.Fatalf("kind/format = %q/%q, want app/electron", d.Kind, d.Format)
	}
	if d.AsarMain != "dist/main.js" || d.AsarFiles == 0 {
		t.Fatalf("asar fields lost: main=%q files=%d", d.AsarMain, d.AsarFiles)
	}
}

// A .app whose asar never parsed has no electron evidence, so the wrapper must
// not claim that format.
func TestBundleAppBrokenAsarNotElectron(t *testing.T) {
	app := filepath.Join(t.TempDir(), "Broken.app")
	res := filepath.Join(app, "Contents", "Resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(res, "app.asar"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(app)
	if err != nil {
		t.Fatal(err)
	}
	if d.Format == "electron" {
		t.Fatalf("format = electron without a readable asar")
	}
}
