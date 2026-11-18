package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// restoreReaders keeps registry tests from leaking into the real table.
func restoreReaders(t *testing.T) {
	t.Helper()
	saved := readers
	t.Cleanup(func() { readers = saved })
	readers = nil
}

func TestRegisterRejectsIncompleteReaders(t *testing.T) {
	restoreReaders(t)
	cases := map[string]reader{
		"no format":  {inspect: func(string, *Digest) {}},
		"no inspect": {format: "x", match: func([]byte, int64) bool { return false }},
		"no match":   {format: "x", inspect: func(string, *Digest) {}},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("register accepted an incomplete reader")
				}
			}()
			register(r)
		})
	}
}

func TestRegisterRejectsDuplicateFormat(t *testing.T) {
	restoreReaders(t)
	noMatch := func([]byte, int64) bool { return false }
	noop := func(string, *Digest) {}
	register(reader{format: "fa", reasons: []string{"fa-broken"}, match: noMatch, inspect: noop})
	defer func() {
		if recover() == nil {
			t.Fatal("register accepted a duplicate format")
		}
	}()
	register(reader{format: "fa", reasons: []string{"fa-broken"}, match: noMatch, inspect: noop})
}

// A reader with an empty reason set would turn every refusal it emits into an
// unnamed one, so startup refuses the declaration instead of the output.
func TestRegisterRejectsEmptyReasons(t *testing.T) {
	restoreReaders(t)
	defer func() {
		got := fmt.Sprint(recover())
		want := `register: reader "fa" registered with no reasons`
		if got != want {
			t.Fatalf("panic = %q, want %q", got, want)
		}
	}()
	register(reader{
		format:  "fa",
		match:   func([]byte, int64) bool { return false },
		inspect: func(string, *Digest) {},
	})
}

func TestRegisterRejectsReasonOutsideSet(t *testing.T) {
	restoreReaders(t)
	defer func() {
		got := fmt.Sprint(recover())
		want := "register: reader fa declares reason pyc-not-code outside its set"
		if got != want {
			t.Fatalf("panic = %q, want %q", got, want)
		}
	}()
	register(reader{
		format:  "fa",
		reasons: []string{"pyc-not-code"},
		match:   func([]byte, int64) bool { return false },
		inspect: func(string, *Digest) {},
	})
}

func TestDispatchClaimsOnMatch(t *testing.T) {
	restoreReaders(t)
	var got string
	register(reader{
		format:  "fa",
		reasons: []string{"fa-broken"},
		match:   func(head []byte, size int64) bool { return size == 4 && len(head) == 4 },
		inspect: func(path string, d *Digest) {
			got = path
			d.skip("fa-broken", "unit 3")
			d.parsed()
		},
	})
	var d Digest
	if !dispatch("/x", []byte("abcd"), 4, &d) {
		t.Fatal("dispatch missed a matching file")
	}
	if d.Kind != "fa" || d.Format != "fa" || got != "/x" {
		t.Fatalf("claim incomplete: kind=%q format=%q path=%q", d.Kind, d.Format, got)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "fa-broken" {
		t.Fatalf("registered reason was not kept: %+v", d.Skipped)
	}
	if d.Coverage == nil || d.Coverage.Skipped != 1 || d.Coverage.Parsed != 1 {
		t.Fatalf("coverage not counted: %+v", d.Coverage)
	}
}

func TestDispatchUnregisteredReasonRefused(t *testing.T) {
	restoreReaders(t)
	var d Digest
	reason := "zz-" + "invented" // built at runtime: not a registry literal
	register(reader{
		format:  "fa",
		reasons: []string{"fa-broken"},
		match:   func([]byte, int64) bool { return true },
		inspect: func(_ string, d *Digest) { d.skip(reason, "detail") },
	})
	dispatch("/x", nil, 1, &d)
	if len(d.Skipped) != 1 {
		t.Fatalf("want one skip, got %+v", d.Skipped)
	}
	if d.Skipped[0].Reason != reason {
		t.Fatalf("reason was rewritten instead of kept raw: %q", d.Skipped[0].Reason)
	}
	if err := d.checkReasons(); err == nil || !strings.Contains(err.Error(), `reason "zz-invented" not in registry (field zz)`) {
		t.Fatalf("unregistered reason was not refused: %v", err)
	}
}

func TestDispatchLeavesUnmatchedFilesAlone(t *testing.T) {
	restoreReaders(t)
	register(reader{
		format:  "fa",
		reasons: []string{"fa-broken"},
		match:   func([]byte, int64) bool { return false },
		inspect: func(string, *Digest) { panic("unreachable") },
	})
	d := Digest{Kind: "unknown"}
	if dispatch("/x", nil, 0, &d) {
		t.Fatal("dispatch claimed a file that matched nothing")
	}
	if d.Kind != "unknown" || d.Coverage != nil {
		t.Fatalf("unmatched file was touched: kind=%q coverage=%+v", d.Kind, d.Coverage)
	}
}

// A post reader that names the file may do so only when no magic did: a phar
// inside a Mach-O is still a Mach-O, and the bundle lives in capabilities.
func TestPostReaderClaimsKindOnlyWhenUnclaimed(t *testing.T) {
	restoreReaders(t)
	register(reader{
		format:     "fa",
		post:       true,
		claimsKind: true,
		reasons:    []string{"fa-broken"},
		inspect:    func(string, *Digest) {},
	})
	for _, tc := range []struct{ before, want string }{
		{"unknown", "fa"},
		{"text", "fa"},
		{"macho", "macho"},
		{"elf", "elf"},
	} {
		d := Digest{Kind: tc.before}
		dispatchPost("/x", nil, 0, &d)
		if d.Kind != tc.want {
			t.Fatalf("kind %q became %q, want %q", tc.before, d.Kind, tc.want)
		}
	}
}

func TestWitnessesNeedTwoSources(t *testing.T) {
	var d Digest
	d.claim("rust", "mangling", 0x10)
	if d.witnessed("rust") {
		t.Fatal("one witness is not enough")
	}
	d.claim("rust", "mangling", 0x10) // same source twice is still one witness
	if d.witnessed("rust") {
		t.Fatal("a repeated source is not a second witness")
	}
	d.claim("rust", "__rust_alloc", 0x20)
	if !d.witnessed("rust") {
		t.Fatal("two independent sources should witness")
	}
	if d.witnessed("swift") {
		t.Fatal("unknown value cannot be witnessed")
	}
}

func TestSkipTextRenders(t *testing.T) {
	var d Digest
	d.skipGenericForTest("pyc-version-unverified", "3627")
	text := d.Text()
	if !strings.Contains(text, "skipped: pyc-version-unverified 3627") {
		t.Fatalf("skip line missing from text:\n%s", text)
	}
	if !strings.Contains(text, "coverage: parsed:0 skipped:1 unknown:0") {
		t.Fatalf("coverage line missing from text:\n%s", text)
	}
}

// skipGenericForTest emits a reason outside any reader, which is what a caller
// outside dispatch sees: the reason is kept only when no reader is active.
func (d *Digest) skipGenericForTest(reason, detail string) { d.skip(reason, detail) }

// TestNewFieldsRoundTripThroughJSON guards --diff: a digest written by the new
// build has to read back into the same struct, and a digest written by an older
// build (no coverage/skipped/claims) must still load.
func TestNewFieldsRoundTripThroughJSON(t *testing.T) {
	var d Digest
	d.Kind = "pyc"
	d.FileSize = 4096
	d.scanned(512)
	d.parsed()
	d.unparsed()
	d.skipGenericForTest("pyc-version-unverified", "3627")
	d.claim("cpython 3.13", "magic", 0)
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var back Digest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Coverage == nil || back.Coverage.Parsed != 1 || back.Coverage.Skipped != 1 || back.Coverage.Unknown != 1 {
		t.Fatalf("coverage lost: %s", b)
	}
	if len(back.Skipped) != 1 || back.Skipped[0].Reason != "pyc-version-unverified" {
		t.Fatalf("skipped lost: %s", b)
	}
	if len(back.Claims) != 1 || back.Claims[0].Source != "magic" {
		t.Fatalf("claims lost: %s", b)
	}
	if back.BytesScanned != 512 || back.FileSize != 4096 {
		t.Fatalf("byte coverage lost: %s", b)
	}
	// An old digest carries none of these keys and must still parse.
	var old Digest
	if err := json.Unmarshal([]byte(`{"path":"/x","kind":"elf"}`), &old); err != nil {
		t.Fatalf("old digest rejected: %v", err)
	}
	if old.Kind != "elf" || old.Coverage != nil || old.Skipped != nil {
		t.Fatalf("old digest misread: %+v", old)
	}
}
