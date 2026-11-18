package main

// Tur 7 bucket 08: correlate_static_and_runtime joins a static Mach-O image with
// an Apple .ips crash report. The matcher is identity by normalized uuid (case
// and hyphens dropped), not string equality: an .ips writes uuids as
// "8B6282E3-B713-35B0-E0AD-6EC2A1504164" while the digest prints
// "8B6282E3B71335B0E0AD6EC2A1504164". A textual matcher reports zero matches on
// the exact same image; the real one must still pair them, and must still say
// no when one nibble really differs.

import (
	"debug/macho"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// tur7b08StaticUUID reads LC_UUID straight from the Mach-O fixture, so the
// expected value never comes from the code under test.
func tur7b08StaticUUID(t *testing.T, bin string) string {
	t.Helper()
	f, err := macho.Open(bin)
	if err != nil {
		t.Fatalf("open fixture %s: %v", bin, err)
	}
	defer f.Close()
	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) >= 24 && macho.LoadCmd(binary.LittleEndian.Uint32(raw[:4])) == lcUUID {
			u := strings.ToUpper(hex.EncodeToString(raw[8:24]))
			if len(u) != 32 {
				t.Fatalf("fixture LC_UUID = %q, want 32 hex chars", u)
			}
			return u
		}
	}
	t.Fatalf("fixture %s carries no LC_UUID", bin)
	return ""
}

// tur7b08Apple rewrites 32 hex chars as the .ips spelling: 8-4-4-4-12, upper.
func tur7b08Apple(u string) string {
	return u[0:8] + "-" + u[8:12] + "-" + u[12:16] + "-" + u[16:20] + "-" + u[20:32]
}

func tur7b08Crash(t *testing.T, body string) string {
	t.Helper()
	return writeTemp(t, "tur7b08.ips", []byte(`{"app_name":"Tur7Bucket08","timestamp":"2026-01-01 00:00:00.00 +0000"}`+"\n"+body))
}

func TestTur7Bucket08Correlate(t *testing.T) {
	bin := nativeFixture(t) // a real thin Mach-O built by the local go toolchain
	plain := tur7b08StaticUUID(t, bin)
	apple := tur7b08Apple(plain)

	// Near miss: same spelling, one nibble changed. Must stay a mismatch.
	near := apple[:len(apple)-1] + "5"
	if strings.HasSuffix(apple, "5") {
		near = apple[:len(apple)-1] + "6"
	}

	m := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{
		"file": bin,
		"crash": tur7b08Crash(t, fmt.Sprintf(
			`{"procName":"Tur7Bucket08","osVersion":"15.0","usedImages":[`+
				`{"name":"Tur7Bucket08","uuid":%q,"arch":"arm64"},`+
				`{"name":"libsystem","uuid":%q,"arch":"arm64"}]}`, apple, near)),
	}))

	static, _ := m["static"].(map[string]any)
	if got := metaStr(t, static, "uuid"); got != plain {
		t.Fatalf("static uuid = %q, want the fixture's own %q", got, plain)
	}
	if got := metaStr(t, static, "kind"); got != "macho" {
		t.Fatalf("static kind = %q, want macho", got)
	}
	runtime, _ := m["runtime"].(map[string]any)
	if got := metaNum(t, runtime, "image_count"); got != 2 {
		t.Fatalf("runtime image_count = %d, want 2", got)
	}
	if got := metaStr(t, runtime, "proc"); got != "Tur7Bucket08" {
		t.Fatalf("runtime proc = %q", got)
	}
	imgs, _ := runtime["images"].([]any)
	if len(imgs) != 2 {
		t.Fatalf("runtime images = %v, want two entries", runtime["images"])
	}
	first, _ := imgs[0].(map[string]any)
	second, _ := imgs[1].(map[string]any)
	if got := metaStr(t, first, "uuid"); got != apple {
		t.Fatalf("image uuid was rewritten: %q, want the .ips spelling %q", got, apple)
	}
	// The textual verdict: hyphenated upper-case vs 32 bare upper-case hex.
	// A string-equality matcher answers false here; identity says true.
	if first["match"] != true {
		t.Fatalf("hyphenated .ips uuid %q did not match static uuid %q: match = %v (string equality, not normalized identity)", apple, plain, first["match"])
	}
	if second["match"] != false {
		t.Fatalf("near-miss uuid %q matched: match = %v, want false", near, second["match"])
	}
	if got := metaNum(t, m, "matches"); got != 1 {
		t.Fatalf("matches = %d, want 1", got)
	}
	if got := metaNum(t, m, "mismatches"); got != 1 {
		t.Fatalf("mismatches = %d, want 1", got)
	}
	if got := metaStr(t, m, "verdict"); !strings.Contains(got, "static image matches the crashing image uuid") {
		t.Fatalf("verdict = %q", got)
	}

	// dyld shared cache: several loaded images carry the very same uuid in
	// different spellings. All three pair, and the verdict must count copies.
	copies := tur7b08Crash(t, fmt.Sprintf(
		`{"procName":"Tur7Bucket08","usedImages":[`+
			`{"name":"a","uuid":%q,"arch":"arm64"},`+
			`{"name":"b","uuid":%q,"arch":"arm64"},`+
			`{"name":"c","uuid":%q,"arch":"arm64"}]}`,
		apple, strings.ToLower(plain), "  "+apple+"  "))
	mm := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": bin, "crash": copies}))
	if got := metaNum(t, mm, "matches"); got != 3 {
		t.Fatalf("copies matches = %d, want 3", got)
	}
	if got := metaNum(t, mm, "mismatches"); got != 0 {
		t.Fatalf("copies mismatches = %d, want 0", got)
	}
	if got := metaStr(t, mm, "verdict"); !strings.Contains(got, "3 loaded images carry the probed uuid (dyld shared cache copies)") {
		t.Fatalf("copies verdict = %q", got)
	}

	// A report whose uuid is a different image must not be rescued by
	// normalization: the matcher is identity, not "anything non-empty".
	other := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{
		"file":  bin,
		"crash": tur7b08Crash(t, `{"procName":"Tur7Bucket08","usedImages":[{"name":"x","uuid":"00000000-0000-0000-0000-000000000000","arch":"arm64"}]}`),
	}))
	if got := metaNum(t, other, "matches"); got != 0 {
		t.Fatalf("unrelated uuid matches = %d, want 0", got)
	}
	if got := metaStr(t, other, "verdict"); !strings.Contains(got, "different build") {
		t.Fatalf("unrelated verdict = %q", got)
	}
}
