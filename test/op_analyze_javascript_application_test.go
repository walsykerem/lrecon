package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A native binary lexed as JS is the bug this gate closes: pe.exe (1.6 MB)
// produced a 147k-token "application map" of nonsense. The gate is a magic
// test, so the table states the magics a reader must reject.
func TestNativeMagic(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want bool
	}{
		{"pe", []byte("MZ\x90\x00"), true},
		{"elf", []byte{0x7f, 'E', 'L', 'F'}, true},
		{"macho32be", []byte{0xfe, 0xed, 0xfa, 0xce}, true},
		{"macho64le", []byte{0xcf, 0xfa, 0xed, 0xfe}, true},
		{"fat", []byte{0xca, 0xfe, 0xba, 0xbe}, true},
		{"js", []byte("var "), false},
		{"jsx", []byte("impo"), false},
		{"short", []byte("M"), false},
	}
	for _, c := range cases {
		if got := nativeMagic(c.head); got != c.want {
			t.Errorf("%s: nativeMagic(%q) = %v, want %v", c.name, c.head, got, c.want)
		}
	}
}

// refuseCodeCache is the only caller, so the test goes through it: the file on
// disk is what the op sees, not the helper in isolation.
func TestRefuseCodeCacheNativeBinary(t *testing.T) {
	dir := t.TempDir()
	native := filepath.Join(dir, "pe.exe")
	if err := os.WriteFile(native, []byte("MZ\x90\x00rest of the binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := refuseCodeCache(native)
	if err == nil || !strings.Contains(err.Error(), "native binary") {
		t.Fatalf("refuseCodeCache(native) = %v, want a native-binary refusal", err)
	}

	src := filepath.Join(dir, "bundle.js")
	if err := os.WriteFile(src, []byte("var x = 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := refuseCodeCache(src); err != nil {
		t.Fatalf("refuseCodeCache(js) = %v, want nil", err)
	}
}
