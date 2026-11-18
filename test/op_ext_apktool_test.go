package main

// Items 513-516 decode the APK fixture. The fixture has to be a real APK:
// a text AndroidManifest.xml is RawXmlEncounteredException ("Could not decode
// XML") and a stub resources.arsc is "Could not decode arsc file", so every
// decode item used to land on no_engine. 516 also needs the framework dir
// seeded with apktool if before -p points at it.

import (
	"archive/zip"
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const apktoolFixtureAPK = "testdata/fixtures/apk/resources.apk"

// TestApktoolFixtureIsBinaryAPK: the shipped fixture holds the binary chunks
// apktool parses, not the text/stub stand-ins that made decode fail.
func TestApktoolFixtureIsBinaryAPK(t *testing.T) {
	zr, err := zip.OpenReader(apktoolFixtureAPK)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	want := map[string]uint16{"AndroidManifest.xml": 0x0003, "resources.arsc": 0x0002}
	seen := map[string]bool{}
	for _, f := range zr.File {
		typ, ok := want[f.Name]
		if !ok {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		var hdr [2]byte
		_, err = io.ReadFull(rc, hdr[:])
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		if got := binary.LittleEndian.Uint16(hdr[:]); got != typ {
			t.Errorf("%s chunk type = 0x%04x, want 0x%04x (text/stub fixture)", f.Name, got, typ)
		}
		seen[f.Name] = true
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("%s has no %s", apktoolFixtureAPK, name)
		}
	}
}

// TestApktoolDecodeFixture runs the decode items against the fixture with the
// machine's apktool and requires a decoded tree, not a refusal.
func TestApktoolDecodeFixture(t *testing.T) {
	if _, err := exec.LookPath("apktool"); err != nil {
		t.Skip("apktool not installed")
	}
	frame := filepath.Join(t.TempDir(), "frame")
	prev := opOutput
	defer func() { opOutput = prev }()

	for _, tc := range []struct {
		name string
		args []string
	}{
		{"apktool_only_manifest", nil},
		{"apktool_no_res", nil},
		{"apktool_no_src", nil},
		{"apktool_frame_path", []string{frame}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opOutput = t.TempDir()
			res, err := runExtOp(tc.name, apktoolFixtureAPK, tc.args)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			out, ok := res.(extOut)
			if !ok {
				t.Fatalf("%s: result = %T, want extOut", tc.name, res)
			}
			if len(out.Args) == 0 || out.Args[0] != "d" {
				t.Fatalf("%s: args = %v, want a decode", tc.name, out.Args)
			}
			if strings.Contains(out.Output, "Exception in thread") || strings.Contains(out.Output, "Could not decode arsc") || strings.Contains(out.Output, "RawXmlEncountered") {
				t.Fatalf("%s: apktool still fails to decode:\n%s", tc.name, out.Output)
			}
			if _, err := os.Stat(filepath.Join(opOutput, "out", "apktool.yml")); err != nil {
				t.Fatalf("%s: no decoded apktool.yml: %v", tc.name, err)
			}
			if tc.name == "apktool_frame_path" {
				matches, _ := filepath.Glob(filepath.Join(frame, "*.apk"))
				if len(matches) == 0 {
					t.Fatalf("apktool_frame_path left %s without a framework apk", frame)
				}
			}
		})
	}
}
