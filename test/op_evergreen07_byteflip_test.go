package main

// Evergreen 07: the phar verdict is byte-sensitive, not constant.
//
// php.go is a real Go source file that lrecon classifies as kind=phar: its
// pharHalt constant holds the phar stub terminator "__HALT_COMPILER();", which
// the post reader detects. A one-byte substitution inside that marker must move
// the structured verdict (kind, format, skipped, coverage, bytes_scanned); a
// one-byte substitution in an ordinary comparison constant of the same file
// must leave it alone even though the file hash changes. Hash equality is
// therefore not the evidence here.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type eg07Skip struct {
	Reason string `json:"reason"`
}

type eg07Verdict struct {
	Target struct {
		FileSHA256 string `json:"file_sha256"`
	} `json:"target"`
	Kind         string          `json:"kind"`
	Format       string          `json:"format"`
	BytesScanned int64           `json:"bytes_scanned"`
	Skipped      []eg07Skip      `json:"skipped"`
	Coverage     json.RawMessage `json:"coverage"`
}

// eg07Signature is the structured verdict compared between inputs. The file
// hash is deliberately excluded; kind/format/skipped/coverage/bytes_scanned are
// what the reader decided about the bytes.
func eg07Signature(v eg07Verdict) string {
	reasons := make([]string, 0, len(v.Skipped))
	for _, s := range v.Skipped {
		reasons = append(reasons, s.Reason)
	}
	return strings.Join([]string{
		"kind=" + v.Kind,
		"format=" + v.Format,
		"skipped=" + strings.Join(reasons, ","),
		"coverage=" + string(v.Coverage),
		"bytes_scanned=" + strconv.FormatInt(v.BytesScanned, 10),
	}, " ")
}

func eg07Run(t *testing.T, path string) eg07Verdict {
	t.Helper()
	out, code := runCLI(t, "--json", path)
	if code != 0 {
		t.Fatalf("%s: --json exit %d, want 0; output:\n%s", filepath.Base(path), code, out)
	}
	var v eg07Verdict
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%s: --json is not JSON: %v\n%s", filepath.Base(path), err, out)
	}
	if v.Target.FileSHA256 == "" {
		t.Fatalf("%s: no target.file_sha256 in envelope: %s", filepath.Base(path), out)
	}
	return v
}

func TestEvergreen07ByteFlipChangesVerdict(t *testing.T) {
	pristine, err := os.ReadFile("php.go")
	if err != nil {
		t.Fatalf("read real Go source php.go: %v", err)
	}
	if !strings.HasPrefix(string(pristine), "package main") {
		t.Fatal("php.go is not a Go source file")
	}
	if strings.Count(string(pristine), "__HALT_COMPILER();") != 1 {
		t.Fatal("php.go must hold exactly one phar stub terminator")
	}

	dir := t.TempDir()
	write := func(name string, b []byte) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	basePath := write("pristine.go", pristine)
	base := eg07Run(t, basePath)
	baseSig := eg07Signature(base)
	if base.Kind != "phar" {
		t.Fatalf("real Go source classified kind=%q, want phar; nothing to mutate", base.Kind)
	}
	if base.Format != "phar" {
		t.Fatalf("pristine format=%q, want phar", base.Format)
	}

	// One-byte substitutions only; every row keeps the file size identical, so
	// a length or offset effect cannot explain a verdict change.
	cases := []struct {
		name   string
		from   string
		to     string
		marker bool // marker bytes drive the phar verdict; controls must not
	}{
		{"stub_terminator_semicolon_to_colon", "__HALT_COMPILER();", "__HALT_COMPILER():", true},
		{"stub_name_H_to_G", "__HALT_COMPILER();", "__GALT_COMPILER();", true},
		{"stub_name_L_to_one", "__HALT_COMPILER();", "__HA1T_COMPILER();", true},
		{"comparison_gt_to_lt", "len(b) > 262", "len(b) < 262", false},
		{"literal_80_to_90", "== 80", "== 90", false},
	}

	var markerDiffs, controlSame int
	for _, c := range cases {
		if len(c.from) != len(c.to) {
			t.Fatalf("%s: not a one-byte substitution", c.name)
		}
		if strings.Count(string(pristine), c.from) != 1 {
			t.Fatalf("%s: %q is not unique in php.go", c.name, c.from)
		}
		mutant := []byte(strings.Replace(string(pristine), c.from, c.to, 1))
		if len(mutant) != len(pristine) {
			t.Fatalf("%s: mutant size %d != %d", c.name, len(mutant), len(pristine))
		}
		v := eg07Run(t, write(c.name+".go", mutant))
		if v.Target.FileSHA256 == base.Target.FileSHA256 {
			t.Fatalf("%s: mutant hash equals pristine hash; mutation did not land", c.name)
		}
		sig := eg07Signature(v)
		changed := sig != baseSig
		if !c.marker {
			if changed {
				t.Fatalf("%s: control mutation changed the verdict: %s", c.name, sig)
			}
			controlSame++
			continue
		}
		if !changed {
			t.Fatalf("%s: marker mutation left verdict unchanged: %s", c.name, sig)
		}
		markerDiffs++
		if v.Kind != "text" || v.Format != "" {
			t.Fatalf("%s: kind=%q format=%q, want text/empty", c.name, v.Kind, v.Format)
		}
		if cov := strings.TrimSpace(string(v.Coverage)); cov != "" && cov != "null" {
			t.Fatalf("%s: phar reader still ran: coverage=%s", c.name, cov)
		}
		if v.BytesScanned != 0 || len(v.Skipped) != 0 {
			t.Fatalf("%s: phar reader still ran: bytes_scanned=%d skipped=%d",
				c.name, v.BytesScanned, len(v.Skipped))
		}
	}

	if markerDiffs < 2 {
		t.Fatalf("only %d marker mutations moved the verdict, want >= 2", markerDiffs)
	}
	if controlSame != 2 {
		t.Fatalf("control mutations stable = %d, want 2", controlSame)
	}
	t.Logf("marker byte flips changing verdict: %d; control flips stable: %d; baseline %s",
		markerDiffs, controlSame, baseSig)
}
