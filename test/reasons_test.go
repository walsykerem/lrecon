package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// reasonLiteral finds every literal a reader can emit. Dynamic reasons are out
// of reach by design; the registry grows with the literals in the tree.
var reasonLiteral = regexp.MustCompile(`\.(?:skip|claim)\("([^"]+)"`)

func TestEverySkipLiteralIsRegistered(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range reasonLiteral.FindAllStringSubmatch(string(src), -1) {
			seen++
			if !registeredReason(m[1]) {
				t.Errorf("%s: reason %q not in registry (field %s)", f, m[1], fieldOf(m[1]))
			}
		}
	}
	if seen == 0 {
		t.Fatal("no skip/claim literals matched: the grep is broken")
	}
}

func TestReasonOutsideReaderSetRefused(t *testing.T) {
	restoreReaders(t)
	register(reader{
		format:  "fa",
		reasons: []string{"fa-broken"},
		match:   func([]byte, int64) bool { return true },
		inspect: func(_ string, d *Digest) { d.skip("pyc-not-code", "borrowed literal") },
	})
	var d Digest
	dispatch("/x", nil, 1, &d)
	want := `reason "pyc-not-code" not declared by reader (field pyc)`
	if err := d.checkReasons(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkReasons = %v, want %s", err, want)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "pyc-not-code" {
		t.Fatalf("reason was rewritten instead of kept: %+v", d.Skipped)
	}
}

// TestEveryReaderHasOwnReasonSet guards the startup contract on the real table:
// each reader names a non-empty set and every member belongs to that format.
func TestEveryReaderHasOwnReasonSet(t *testing.T) {
	if len(readers) == 0 {
		t.Fatal("no readers registered")
	}
	for _, r := range readers {
		set := reasonRegistry[r.format]
		if set == nil {
			t.Errorf("reader %s has no reason set", r.format)
			continue
		}
		if len(r.reasons) == 0 {
			t.Errorf("reader %s registered no reasons", r.format)
		}
		for _, reason := range r.reasons {
			if !set[reason] {
				t.Errorf("reader %s declares %q outside its set", r.format, reason)
			}
		}
	}
}

func TestUnregisteredReasonRefused(t *testing.T) {
	reason := "zz-" + "invented" // runtime-built, so the tree grep does not see it

	var d Digest
	d.skip(reason, "crafted")
	want := `reason "zz-invented" not in registry (field zz)`
	if err := d.checkReasons(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("checkReasons = %v, want %s", err, want)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != reason {
		t.Fatalf("reason was rewritten instead of kept: %+v", d.Skipped)
	}

	// Probe is the single wire point: a reader that invents a reason turns the
	// whole digest into an error instead of a plausible-looking answer.
	restoreReaders(t)
	register(reader{
		format:  "fa",
		reasons: []string{"fa-broken"},
		match:   func([]byte, int64) bool { return true },
		inspect: func(_ string, d *Digest) { d.skip(reason, "crafted") },
	})
	path := filepath.Join(t.TempDir(), "crafted.bin")
	if err := os.WriteFile(path, []byte("not a known magic"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Probe(path)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Probe = %v, want %s", err, want)
	}
	if len(got.Skipped) == 0 || got.Skipped[0].Reason != reason {
		t.Fatalf("Probe rewrote the reason: %+v", got.Skipped)
	}
}
