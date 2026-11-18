package main

import (
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

type bundleEntryFixture struct {
	path string
	kind uint8
	size int64
}

// buildBundle lays out a minimal single-file bundle: MZ host bytes, the 32-byte
// marker at 0x100, the locator before it pointing at the header at 0x200, and
// the header table with hand-built FileEntries. deps.json sits at 0x300 and
// runtimeconfig at 0x400.
func buildBundle(t *testing.T, major, minor uint32, entries []bundleEntryFixture) []byte {
	t.Helper()
	deps := []byte(`{"runtimeTarget":{"name":".NETCoreApp,Version=v8.0/osx-arm64"}}`)
	rt := []byte(`{"runtimeOptions":{"tfm":"net8.0","framework":{"name":"Microsoft.NETCore.App","version":"8.0.0"}}}`)

	h := make([]byte, 0, 256)
	le32 := func(v uint32) { h = binary.LittleEndian.AppendUint32(h, v) }
	le64 := func(v int64) { h = binary.LittleEndian.AppendUint64(h, uint64(v)) }
	le32(major)
	le32(minor)
	le32(uint32(len(entries)))
	h = append(h, 4)
	h = append(h, "test"...)
	le64(0x300)
	le64(int64(len(deps)))
	le64(0x400)
	le64(int64(len(rt)))
	le64(0) // flags
	for _, e := range entries {
		le64(0)      // offset: any in-file range is accepted
		le64(e.size) // uncompressed size
		if major >= 6 {
			le64(0) // not compressed
		}
		h = append(h, e.kind)
		h = append(h, byte(len(e.path)))
		h = append(h, e.path...)
	}

	img := make([]byte, 0x600)
	copy(img, "MZ")
	copy(img[0x100:], bundleMarker)
	binary.LittleEndian.PutUint64(img[0xf8:], 0x200)
	copy(img[0x200:], h)
	copy(img[0x300:], deps)
	copy(img[0x400:], rt)
	return img
}

func TestProbeDotNetSingleFile(t *testing.T) {
	img := buildBundle(t, 6, 0, []bundleEntryFixture{
		{"App.dll", 1, 64},
		{"libnative.dylib", 2, 128},
	})
	d, err := Probe(writeTemp(t, "app", img))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe" {
		t.Fatalf("kind = %q, want pe (post reader must not claim the file)", d.Kind)
	}
	for _, cap := range []string{"dotnet-singlefile", "dotnet-singlefile:files=2", "dotnet-singlefile:major=6"} {
		if !containsStr(d.Capabilities, cap) {
			t.Fatalf("capabilities = %v, want %s", d.Capabilities, cap)
		}
	}
	if !strings.Contains(d.Toolchain, ".NETCoreApp,Version=v8.0") {
		t.Fatalf("toolchain = %q, want deps.json runtime target", d.Toolchain)
	}
	if !strings.Contains(d.Toolchain, "8.0.0") {
		t.Fatalf("toolchain = %q, want runtimeconfig framework version", d.Toolchain)
	}
	if len(d.Deps) != 2 {
		t.Fatalf("deps = %v, want 2 bundled paths", d.Deps)
	}
	if d.Deps[0].Path != "App.dll" || d.Deps[0].Version != "64B" {
		t.Fatalf("deps[0] = %+v, want App.dll 64B", d.Deps[0])
	}
	found := false
	for _, s := range d.Skipped {
		if s.Reason == "ecma335-container-singlefile" {
			found = true
		}
	}
	if !found {
		t.Fatalf("skipped = %+v, want ecma335-container-singlefile", d.Skipped)
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "container: dotnet-singlefile") {
		t.Fatalf("notes missing container kind:\n%s", notes)
	}
	claim := false
	for _, c := range d.Claims {
		if c.Source == "bundle-marker" && c.ByteOffset == 0x100 {
			claim = true
		}
	}
	if !claim {
		t.Fatalf("claims = %+v, want bundle marker at 0x100", d.Claims)
	}
}

func TestDotNetSingleFileVersionUnverified(t *testing.T) {
	img := buildBundle(t, 9, 0, []bundleEntryFixture{{"App.dll", 1, 64}})
	d := Digest{Kind: "pe"}
	inspectDotNetSingleFile(writeTemp(t, "app", img), &d)
	if containsStr(d.Capabilities, "dotnet-singlefile") {
		t.Fatalf("capabilities = %v, want no bundle capability", d.Capabilities)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "dotnetsf-version-unverified" {
		t.Fatalf("skipped = %+v, want dotnetsf-version-unverified", d.Skipped)
	}
	if !strings.Contains(d.Skipped[0].Detail, "9.0") {
		t.Fatalf("detail = %q, want the major.minor pair", d.Skipped[0].Detail)
	}
	if len(d.Claims) != 1 || d.Claims[0].ByteOffset != 0x100 {
		t.Fatalf("claims = %+v, want the marker offset reported before refusing", d.Claims)
	}
}

func TestDotNetSingleFileHeaderInvalid(t *testing.T) {
	img := buildBundle(t, 6, 0, []bundleEntryFixture{{"App.dll", 1, 64}})
	binary.LittleEndian.PutUint64(img[0xf8:], 0x9999)
	d := Digest{Kind: "pe"}
	inspectDotNetSingleFile(writeTemp(t, "app", img), &d)
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "dotnetsf-header-invalid" {
		t.Fatalf("skipped = %+v, want dotnetsf-header-invalid", d.Skipped)
	}
}

func TestDotNetSingleFileTruncatedEntries(t *testing.T) {
	img := buildBundle(t, 6, 0, []bundleEntryFixture{{"App.dll", 1, 64}, {"Second.dll", 1, 64}})
	img = img[:0x240]
	d := Digest{Kind: "pe"}
	inspectDotNetSingleFile(writeTemp(t, "app", img), &d)
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "dotnetsf-truncated" {
		t.Fatalf("skipped = %+v, want dotnetsf-truncated", d.Skipped)
	}
}

func TestDotNetSingleFileMarkerMissing(t *testing.T) {
	img := append([]byte("MZ"), make([]byte, 64)...)
	img = append(img, []byte("DOTNET_BUNDLE_EXTRACT_BASE_DIR\x00")...)
	d := Digest{Kind: "pe"}
	inspectDotNetSingleFile(writeTemp(t, "app", img), &d)
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "dotnetsf-marker-missing" {
		t.Fatalf("skipped = %+v, want dotnetsf-marker-missing", d.Skipped)
	}

	// A plain native PE without either witness stays silent: no bundle to miss.
	d = Digest{Kind: "pe"}
	inspectDotNetSingleFile(writeTemp(t, "plain", []byte("MZ\x00\x00 plain")), &d)
	if len(d.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none for a plain PE", d.Skipped)
	}
}

// TestDotNetSingleFileTruncationFuzz cuts a valid bundle at every plausible
// boundary: no prefix may panic or invent a capability.
func TestDotNetSingleFileTruncationFuzz(t *testing.T) {
	img := buildBundle(t, 6, 0, []bundleEntryFixture{{"App.dll", 1, 64}, {"Second.dll", 1, 64}})
	p := writeTemp(t, "app", img)
	for cut := 0; cut <= len(img); cut += 11 {
		if err := os.WriteFile(p, img[:cut], 0o644); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		d := Digest{Kind: "pe"}
		inspectDotNetSingleFile(p, &d)
		if d.Kind != "pe" {
			t.Fatalf("cut %d: kind = %q", cut, d.Kind)
		}
	}
}
