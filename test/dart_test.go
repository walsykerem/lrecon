package main

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

// dartSnapshotBytes writes the 20-byte header Dart's loader reads plus enough
// bytes for the 32-char version string detect.go records at 20:52.
func dartSnapshotBytes(magic uint32, storedLen uint64, kind uint64) []byte {
	b := make([]byte, 52)
	binary.LittleEndian.PutUint32(b[0:], magic)
	binary.LittleEndian.PutUint64(b[4:], storedLen)
	binary.LittleEndian.PutUint64(b[12:], kind)
	copy(b[20:], "0123456789abcdef0123456789abcdef") // version: 32 hex chars, not a raw digest
	return b
}

func dartDigest(t *testing.T, b []byte, kind string) Digest {
	t.Helper()
	d := Digest{Kind: kind}
	dispatchPost(writeTemp(t, "snapshot.bin", b), b, int64(len(b)), &d)
	return d
}

func TestDartHeaderKinds(t *testing.T) {
	for kind, name := range dartKinds {
		b := dartSnapshotBytes(dartMagic, 32, kind)
		d := dartDigest(t, b, "flutter")
		if len(d.Skipped) != 0 {
			t.Fatalf("kind %d: skipped = %+v, want none", kind, d.Skipped)
		}
		if d.Coverage == nil || d.Coverage.Parsed != 1 {
			t.Fatalf("kind %d: coverage = %+v, want one parsed header", kind, d.Coverage)
		}
		if !strings.Contains(strings.Join(d.Notes, "\n"), "kind="+name) {
			t.Fatalf("kind %d: notes = %v, want kind=%s", kind, d.Notes, name)
		}
	}
}

func TestDartRefusesUnmappedVariants(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		// kInvalid and anything above kModule is not a header Dart accepts.
		{"kind-invalid", dartSnapshotBytes(dartMagic, 32, 4)},
		{"kind-huge", dartSnapshotBytes(dartMagic, 32, 99)},
		// Stored length excludes the magic; 0 means a 4-byte snapshot.
		{"length-too-small", dartSnapshotBytes(dartMagic, 0, 0)},
		{"length-past-eof", dartSnapshotBytes(dartMagic, 4096, 0)},
		{"truncated", []byte{0xf5, 0xf5, 0xdc, 0xdc, 1, 2, 3, 4}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := dartDigest(t, c.b, "flutter")
			if d.Toolchain != "" || len(d.Claims) != 0 {
				t.Fatalf("invented toolchain/claims: %q/%+v", d.Toolchain, d.Claims)
			}
			if len(d.Skipped) != 1 || d.Skipped[0].Reason != "version-hash-unmapped" {
				t.Fatalf("skipped = %+v, want version-hash-unmapped", d.Skipped)
			}
		})
	}
}

// TestDartNeverClaimsForeignMagic: the reader must not rename a file whose
// header is not 0xDCDCF5F5, and a post reader never renames a claimed kind.
func TestDartNeverClaimsForeignMagic(t *testing.T) {
	r := registeredReader(t, "dart")
	if r == nil {
		t.Fatal("dart reader not registered")
	}
	foreign := dartSnapshotBytes(0x12345678, 32, 0)
	if r.match(foreign, int64(len(foreign))) {
		t.Fatal("dart match accepted a foreign magic")
	}
	d := dartDigest(t, foreign, "unknown")
	if d.Kind != "unknown" || len(d.Notes) != 0 || len(d.Skipped) != 0 {
		t.Fatalf("kind/notes/skipped = %q/%v/%+v, want untouched", d.Kind, d.Notes, d.Skipped)
	}

	// Same magic on a file another reader already named stays that kind.
	d = dartDigest(t, dartSnapshotBytes(dartMagic, 32, 0), "elf")
	if d.Kind != "elf" {
		t.Fatalf("kind = %q, want elf kept", d.Kind)
	}
	for _, note := range d.Notes {
		if strings.Contains(note, "dart snapshot") {
			t.Fatalf("notes = %v, want no dart note on a foreign kind", d.Notes)
		}
	}
	if hasReason(d, "version-hash-unmapped") {
		t.Fatalf("skipped = %+v, want no dart refusal on a foreign kind", d.Skipped)
	}
}

func registeredReader(t *testing.T, format string) *reader {
	t.Helper()
	for i := range readers {
		if readers[i].format == format {
			return &readers[i]
		}
	}
	return nil
}

func TestDartCLIJSON(t *testing.T) {
	type skip struct {
		Reason string `json:"reason"`
	}
	type doc struct {
		Kind        string `json:"kind"`
		FlutterHash string `json:"flutter_hash"`
		Plan        string `json:"plan"`
		Skipped     []skip `json:"skipped"`
	}
	decode := func(t *testing.T, b []byte) doc {
		t.Helper()
		out, code := runCLI(t, "--json", writeTemp(t, "app.snapshot", b))
		if code != 0 {
			t.Fatalf("exit %d: %s", code, out)
		}
		var d doc
		if err := json.Unmarshal([]byte(out), &d); err != nil {
			t.Fatalf("json: %v\n%s", err, out)
		}
		return d
	}

	good := decode(t, dartSnapshotBytes(dartMagic, 32, 2))
	if good.Kind != "flutter" {
		t.Fatalf("kind = %q, want flutter", good.Kind)
	}
	if len(good.FlutterHash) != 32 {
		t.Fatalf("flutter_hash = %q, want 32 hex chars", good.FlutterHash)
	}
	if good.Plan != "generic" {
		t.Fatalf("plan = %q, want generic", good.Plan)
	}
	if len(good.Skipped) != 0 {
		t.Fatalf("skipped = %+v, want none for a valid header", good.Skipped)
	}

	bad := decode(t, dartSnapshotBytes(dartMagic, 4096, 0))
	if len(bad.Skipped) != 1 || bad.Skipped[0].Reason != "version-hash-unmapped" {
		t.Fatalf("skipped = %+v, want version-hash-unmapped", bad.Skipped)
	}
}
