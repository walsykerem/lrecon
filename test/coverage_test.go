package main

import (
	"encoding/binary"
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestComplete pins the one absence rule: a scan answers for the whole file only
// when it read every byte of a non-empty file and was not cut.
func TestComplete(t *testing.T) {
	cases := []struct {
		name        string
		file, bytes int64
		truncated   bool
		want        bool
	}{
		{"empty file", 0, 0, false, false},
		{"nothing read", 100, 0, false, false},
		{"partial read", 100, 50, false, false},
		{"one byte short", 100, 99, false, false},
		{"full read", 100, 100, false, true},
		{"cut file", 100, 100, true, false},
	}
	for _, c := range cases {
		d := Digest{FileSize: c.file, BytesScanned: c.bytes, Truncated: c.truncated}
		if got := d.complete(); got != c.want {
			t.Errorf("%s: complete() = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAbsenceGate: absence after a partial scan is not-scanned, not not_detected.
// Presence evidence survives, because seeing a token is a finding regardless.
func TestAbsenceGate(t *testing.T) {
	partial := func() Digest {
		return Digest{
			FileSize:        100,
			BytesScanned:    40,
			Constants:       consts{constNotDetected},
			JIT:             jitNotDetected,
			Names:           nameNotRecovered,
			ContractVersion: contractVersion,
		}
	}
	t.Run("partial read downgrades absence", func(t *testing.T) {
		d := partial()
		d.gateAbsence()
		if len(d.Constants) != 1 || d.Constants[0] != constNotScanned {
			t.Errorf("constants = %v, want [%s]", d.Constants, constNotScanned)
		}
		if d.JIT != constNotScanned {
			t.Errorf("jit = %q, want %s", d.JIT, constNotScanned)
		}
		if d.Names != constNotScanned {
			t.Errorf("names = %q, want %s", d.Names, constNotScanned)
		}
	})
	t.Run("empty fields are absence too", func(t *testing.T) {
		d := Digest{FileSize: 100, BytesScanned: 1}
		d.gateAbsence()
		if d.JIT != constNotScanned || d.Names != constNotScanned {
			t.Errorf("jit/names = %q/%q, want %s", d.JIT, d.Names, constNotScanned)
		}
	})
	t.Run("truncated file never claims not detected", func(t *testing.T) {
		d := Digest{FileSize: 100, BytesScanned: 100, Truncated: true, Constants: consts{constNotDetected}, JIT: jitNotDetected}
		d.gateAbsence()
		if d.Constants[0] != constNotScanned || d.JIT != constNotScanned {
			t.Errorf("constants/jit = %v/%q, want %s", d.Constants, d.JIT, constNotScanned)
		}
	})
	t.Run("empty file never claims not detected", func(t *testing.T) {
		d := Digest{Constants: consts{constNotDetected}, JIT: jitNotDetected, Names: nameNotRecovered}
		d.gateAbsence()
		if d.Constants[0] != constNotScanned || d.JIT != constNotScanned || d.Names != constNotScanned {
			t.Errorf("empty file still claims a negative: %+v", d)
		}
	})
	t.Run("complete scan keeps the negative", func(t *testing.T) {
		d := partial()
		d.BytesScanned = d.FileSize
		d.gateAbsence()
		if d.Constants[0] != constNotDetected || d.JIT != jitNotDetected || d.Names != nameNotRecovered {
			t.Errorf("complete scan lost its answer: %+v", d)
		}
	})
	t.Run("presence survives a partial read", func(t *testing.T) {
		d := partial()
		d.Constants = consts{"sha256"}
		d.JIT = "luajit 2.0"
		d.Names = "local:3"
		d.gateAbsence()
		if d.Constants[0] != "sha256" || d.JIT != "luajit 2.0" || d.Names != "local:3" {
			t.Errorf("presence was downgraded: constants=%v jit=%q names=%q", d.Constants, d.JIT, d.Names)
		}
	})
}

// TestCoverageClaim: the count never stands alone. N is the sum the same scan
// attributed; without a reader there is no N, and the line says so.
func TestCoverageClaim(t *testing.T) {
	var none Digest
	if got := none.coverageClaim(); got != "of N unknown" {
		t.Errorf("claim without coverage = %q, want %q", got, "of N unknown")
	}
	if text := none.Text(); !strings.Contains(text, "coverage: of N unknown") {
		t.Errorf("text drops the denominator:\n%s", text)
	}

	d := Digest{Coverage: &Coverage{Parsed: 2, Skipped: 1, Unknown: 1}}
	want := "parsed:2 skipped:1 unknown:1 N=4"
	if got := d.coverageClaim(); got != want {
		t.Errorf("claim = %q, want %q", got, want)
	}
	if text := d.Text(); !strings.Contains(text, "coverage: "+want) {
		t.Errorf("text = %q, want the claim with its denominator", text)
	}

	// Consumers that already parse the historical prefix keep working.
	old := Digest{Coverage: &Coverage{Skipped: 1}}
	if got := old.coverageClaim(); !strings.Contains(got, "parsed:0 skipped:1 unknown:0") {
		t.Errorf("historical prefix lost: %q", got)
	}
}

// TestCoverageJSONKeysStable: the contract is frozen; the denominator is a text
// claim, not a new field.
func TestCoverageJSONKeysStable(t *testing.T) {
	b, err := json.Marshal(Coverage{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	if len(keys) != 3 {
		t.Fatalf("coverage keys = %v, want exactly parsed, skipped, unknown", keys)
	}
	for _, k := range []string{"parsed", "skipped", "unknown"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("coverage.%s missing from %s", k, b)
		}
	}
}

// TestCoverageSumIsTheUnitsSeen: the three counters are the only writers of a
// coverage unit (skip, parsed, unparsed), so the sum is the unit count and every
// skipped[] entry is exactly one of them. unknown[] is a different axis (slots
// no claim could settle), which is why it is never added to the sum.
func TestCoverageSumIsTheUnitsSeen(t *testing.T) {
	root := "testdata/fixtures"
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		// Probe refuses empty files; sqlite leaves 0-byte -wal/-shm sidecars.
		if fi, err := e.Info(); err == nil && fi.Size() == 0 {
			return nil
		}
		d, err := Probe(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if d.Coverage == nil {
			if len(d.Skipped) != 0 {
				t.Errorf("%s: %d skipped entries with no coverage", path, len(d.Skipped))
			}
			return nil
		}
		if got, want := d.Coverage.Skipped, len(d.Skipped); got != want {
			t.Errorf("%s: coverage.skipped %d but %d skipped entries", path, got, want)
		}
		if total := d.Coverage.Parsed + d.Coverage.Skipped + d.Coverage.Unknown; total <= 0 {
			t.Errorf("%s: coverage present with N=0", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// TestAbsenceOnTruncatedFatMachO: a universal binary cut after its header is a
// real probe, and it must not answer "not detected" for anything.
func TestAbsenceOnTruncatedFatMachO(t *testing.T) {
	buf := make([]byte, 64)
	binary.BigEndian.PutUint32(buf[0:4], 0xcafebabe)
	binary.BigEndian.PutUint32(buf[4:8], 1)
	binary.BigEndian.PutUint32(buf[8:12], 0x01000007) // CPU_TYPE_X86_64
	binary.BigEndian.PutUint32(buf[16:20], 4096)      // slice offset
	binary.BigEndian.PutUint32(buf[20:24], 4096)      // slice size, past EOF
	d, err := Probe(writeTemp(t, "cut-fat", buf))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "macho" || d.Format != "fat" {
		t.Fatalf("kind/format = %q/%q, want macho/fat", d.Kind, d.Format)
	}
	if !d.Truncated {
		t.Fatal("truncated universal binary not marked, so the gate cannot fire")
	}
	for field, v := range map[string]string{"constants": d.Constants[0], "jit": d.JIT, "names": d.Names} {
		if v != constNotScanned {
			t.Errorf("%s = %q, want %s on a cut read", field, v, constNotScanned)
		}
	}
}
