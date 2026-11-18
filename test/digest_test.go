package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDigestInvariants(t *testing.T) {
	paths := []string{
		lsPath,
		fixtureMacho,
		goFixtureDeps(t, 40),
		writeAsar(t),
		writeFlutter(t),
		writeTemp(t, "plain.txt", []byte("hello lrecon\n")),
		writeTemp(t, "tiny.bin", []byte("abc")),
	}
	for _, path := range paths {
		t.Run(strings.TrimPrefix(path, "/"), func(t *testing.T) {
			if _, err := os.Stat(path); err != nil {
				t.Skipf("fixture %s unavailable: %v", path, err)
			}
			d, err := Probe(path)
			if err != nil {
				t.Fatalf("Probe(%s) error: %v", path, err)
			}
			if d.Path != path {
				t.Fatalf("Path = %q, want %q", d.Path, path)
			}
			if d.Kind == "" {
				t.Fatal("Kind empty")
			}

			b, err := json.Marshal(d)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var back Digest
			if err := json.Unmarshal(b, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back.Kind != d.Kind || back.Format != d.Format || back.AsarMain != d.AsarMain {
				t.Fatalf("JSON round-trip lost fields: %+v vs %+v", back, d)
			}
		})
	}
}

func TestDigestTextBudget(t *testing.T) {
	d := probeFixture(t, goFixtureDeps(t, 1))
	text := d.Text()
	if text == "" {
		t.Fatal("Text() empty for a Go binary")
	}
	if got := digestText(d, 4096); len(got) > 4096 {
		t.Fatalf("digestText(d, 4096) is %d bytes, budget is 4096", len(got))
	}
}

func TestDigestTextRenders(t *testing.T) {
	d := Digest{
		Kind:  "macho",
		Deps:  []Dep{{Path: "github.com/foo/bar", Version: "v1.2.3"}},
		Notes: []string{"hermetic note"},
	}
	text := d.Text()
	if !strings.Contains(text, "  github.com/foo/bar v1.2.3\n") {
		t.Fatalf("dep line missing from:\n%s", text)
	}
	if !strings.Contains(text, "note: hermetic note\n") {
		t.Fatalf("note line missing from:\n%s", text)
	}
	if !strings.HasPrefix(text, "kind: macho\n") {
		t.Fatalf("kind line missing from:\n%s", text)
	}
}

func TestTextStripsControlBytes(t *testing.T) {
	forged := "\x1b[2K\rforged: x"
	d := Digest{Kind: "pcap", Notes: []string{forged}, PcapURIs: []string{forged}}
	text := d.Text()
	if strings.ContainsAny(text, "\x1b\r") {
		t.Fatalf("Text() still carries a raw control byte: %q", text)
	}
	if !strings.Contains(text, `\rforged: x`) {
		t.Fatalf("Text() = %q, want the CR escaped, not dropped", text)
	}
	if !strings.Contains(text, "omitted:1") {
		t.Fatalf("Text() = %q, want the dropped ESC counted as omitted:1", text)
	}
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(line, "forged:") {
			t.Fatalf("forged line reached Text(): %q", text)
		}
	}
}

func TestTextFieldCap(t *testing.T) {
	d := Digest{Kind: "elf", Names: strings.Repeat("A", textFieldCap*4)}
	text := d.Text()
	if strings.Contains(text, strings.Repeat("A", textFieldCap+1)) {
		t.Fatalf("field not capped at %d bytes", textFieldCap)
	}
	want := textFieldCap * 3
	if !strings.Contains(text, "omitted:"+fmt.Sprint(want)) {
		t.Fatalf("Text() = %q, want omitted:%d for the cut bytes", text, want)
	}
}

func TestDigestTextOmitsEmptyFields(t *testing.T) {
	text := Digest{Kind: "elf"}.Text()
	for _, key := range []string{"format:", "slices:", "toolchain:", "mod:", "deps:", "dylibs:", "imports:", "capabilities:", "asar_files:", "asar_main:", "flutter_hash:", "note:"} {
		if strings.Contains(text, key) {
			t.Fatalf("empty field %q produced a line in %q", key, text)
		}
	}
	// The coverage line is the one line that never vanishes: a count without its
	// denominator is not a bounded claim, and "of N unknown" is the honest answer
	// when no reader ran.
	if text != "kind: elf\ncoverage: of N unknown\n" {
		t.Fatalf("Text() = %q, want the kind line and the coverage denominator", text)
	}
}
