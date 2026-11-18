package main

// Tur5 lane go11: real simulation tests for behaviors in the assigned files
// that the existing suite reaches only indirectly. No production code changed;
// every case drives real buffer/parser/driver state so a regression fails here.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// op_rt_util.go: tool failures put their reason at the end. tailBuffer must
// keep exactly the last maxExtOutput bytes across both one-shot and incremental
// writes, or the op reports a JVM banner instead of the cause.
func TestTur5Go11TailBufferKeepsTail(t *testing.T) {
	var tb tailBuffer
	if _, err := tb.Write([]byte("hello")); err != nil || tb.String() != "hello" {
		t.Fatalf("small write = %q, %v", tb.String(), err)
	}
	huge := bytes.Repeat([]byte("X"), maxExtOutput+100)
	if _, err := tb.Write(huge); err != nil {
		t.Fatal(err)
	}
	if want := string(huge[len(huge)-maxExtOutput:]); tb.String() != want {
		t.Fatalf("one-shot overflow kept %d bytes, wrong tail", len(tb.String()))
	}

	var tb2 tailBuffer
	tb2.Write(bytes.Repeat([]byte("A"), maxExtOutput-4))
	tb2.Write([]byte("WXYZ")) // now exactly maxExtOutput
	tb2.Write([]byte("12345678"))
	if got := tb2.String(); len(got) != maxExtOutput || !strings.HasSuffix(got, "WXYZ12345678") {
		t.Fatalf("incremental overflow tail = %q (len %d)", got[len(got)-24:], len(got))
	}
}

// op_rt_util.go: rtCauseLine returns the single line a reviewer can paste;
// JVM/adb banner chatter must never win over an actual error line.
func TestTur5Go11RtCauseLineFiltersBanners(t *testing.T) {
	const banner = "openjdk version \"21.0.1\"\nPicked up JAVA_TOOL_OPTIONS: -Xmx1g\nINFO starting\nWARNING: deprecated\nWARN noisy\n"
	if got := rtCauseLine(banner, "Error: cannot reach device"); got != "Error: cannot reach device" {
		t.Fatalf("error line = %q", got)
	}
	if got := rtCauseLine(banner, "just a path\n"); got != "just a path" {
		t.Fatalf("fallback line = %q", got)
	}
	if got := rtCauseLine(banner); got != "no output" {
		t.Fatalf("all-banner = %q, want no output", got)
	}
	if got := rtCauseLine("first fallback", "boom: exception thrown"); got != "boom: exception thrown" {
		t.Fatalf("error beats fallback = %q", got)
	}
}

// op_inspect_signal_decoders.go: a malformed table and a table chosen by cwd
// (rather than LRECON_DECODERS) are two real branches the suite never drives.
func TestTur5Go11DecoderTableSelection(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("LRECON_QUERY", "")

	t.Run("invalid table refused", func(t *testing.T) {
		bad := filepath.Join(dir, "bad.json")
		if err := os.WriteFile(bad, []byte("this is not JSON"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("LRECON_DECODERS", bad)
		if _, err := inspectSignalDecoders("hf"); err == nil || !strings.Contains(err.Error(), "not a decoder table") {
			t.Fatalf("malformed table: got %v", err)
		}
	})

	t.Run("cwd table used when no override", func(t *testing.T) {
		t.Setenv("LRECON_DECODERS", "")
		body := `[{"name":"CWD-ONLY","family":"hf","modulation":"FSK"}]`
		if err := os.WriteFile(filepath.Join(dir, "decoders.json"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := inspectSignalDecoders("cwd-only")
		if err != nil {
			t.Fatal(err)
		}
		h := got.(rtDecoderHits)
		if h.Table != "decoders.json" || len(h.Matches) != 1 || h.Matches[0].Name != "CWD-ONLY" {
			t.Fatalf("cwd table = %+v", h)
		}
	})

	t.Run("override wins over cwd", func(t *testing.T) {
		exp := filepath.Join(dir, "explicit.json")
		body := `[{"name":"EXPLICIT-ONLY","family":"vhf"}]`
		if err := os.WriteFile(exp, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Setenv("LRECON_DECODERS", exp)
		got, err := inspectSignalDecoders("explicit-only")
		if err != nil {
			t.Fatal(err)
		}
		if h := got.(rtDecoderHits); h.Table != exp || len(h.Matches) != 1 {
			t.Fatalf("explicit table = %+v", h)
		}
	})
}

// op_capture_web_screenshot.go: stepFailure must name a step that never ran,
// not panic or print a generic "failed".
func TestTur5Go11StepFailureOutOfRange(t *testing.T) {
	if got := stepFailure(nil, 0); got != "step never ran" {
		t.Fatalf("stepFailure(nil,0) = %q", got)
	}
	steps := []webStepResult{{Method: "Page.enable", Ok: true}}
	if got := stepFailure(steps, 1); got != "step never ran" {
		t.Fatalf("stepFailure past end = %q", got)
	}
}

// op_inspect_analysis_view.go: the raw view reads at most 128 bytes and renders
// 16-byte hex rows, for both a short target and a long one.
func TestTur5Go11AnalysisViewRawCap(t *testing.T) {
	short := writeTemp(t, "short.bin", []byte("0123456789abcdef"))
	got, err := runInspectAnalysisView(metaTestArg(t, map[string]any{"file": short, "view": "raw"}))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["bytes_shown"] != 16 || len(m["hex"].([]string)) != 1 {
		t.Fatalf("short raw = %v", m)
	}
	long := writeTemp(t, "long.bin", bytes.Repeat([]byte("Z"), 300))
	got, err = runInspectAnalysisView(metaTestArg(t, map[string]any{"file": long, "view": "raw"}))
	if err != nil {
		t.Fatal(err)
	}
	m = got.(map[string]any)
	if m["bytes_shown"] != 128 || len(m["hex"].([]string)) != 8 {
		t.Fatalf("long raw = bytes %v, rows %d", m["bytes_shown"], len(m["hex"].([]string)))
	}
}
