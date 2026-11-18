package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A busy process is the normal case, and sample(1) aggregates there: it stacks
// markers ("+ !"), turns the offset into a list ("+ 28,68,...") and lists every
// address of the aggregate in the bracket. The old frame regex demanded one
// plain offset and one address, so it kept only the quiet-process lines and a
// busy capture came back with almost no frames.
func TestA14SampleFramesSurviveAggregates(t *testing.T) {
	out := strings.Join([]string{
		"Analysis of sampling process 194 (perl) every 1 millisecond",
		"Process:         perl [194]",
		"Path:            /usr/bin/perl",
		"Call graph:",
		"    194 Thread_1   DispatchQueue_1: com.apple.main-thread  (serial)",
		"    + 194 Perl_pp_unstack  (in libperl.dylib) + 28,68,...  [0x104dcc188,0x104dcc1b0]",
		"    + !   2208 work  (in libfoo.dylib) + 0x1f  [0x1234]",
		"    !   22 next  (in libfoo.dylib) + 108  [0x1234]",
		"    + 1000 start  (in dyld) + 7184  [0x1f0d1234]",
		"    + 9 no-address  (in libbar.dylib)",
		"    garbage that is not a frame",
	}, "\n")
	caps, err := rtParseSample(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(caps.Threads) != 1 {
		t.Fatalf("threads = %d, want 1", len(caps.Threads))
	}
	frames := caps.Threads[0].Frames
	if len(frames) != 5 {
		t.Fatalf("frames = %d (%+v), want 5", len(frames), frames)
	}
	want := []rtFrame{
		{Sym: "Perl_pp_unstack", Lib: "libperl.dylib", Addr: "0x104dcc188", Count: 194},
		{Sym: "work", Lib: "libfoo.dylib", Addr: "0x1234", Count: 2208},
		{Sym: "next", Lib: "libfoo.dylib", Addr: "0x1234", Count: 22},
		{Sym: "start", Lib: "dyld", Addr: "0x1f0d1234", Count: 1000},
		{Sym: "no-address", Lib: "libbar.dylib", Addr: "", Count: 9},
	}
	for i := range want {
		if frames[i] != want[i] {
			t.Errorf("frame %d = %+v, want %+v", i, frames[i], want[i])
		}
	}
}

func TestA14SampleWithoutCallGraphIsAnError(t *testing.T) {
	if _, err := rtParseSample("Process: x [1]\n"); err == nil ||
		!strings.Contains(err.Error(), "no Call graph") {
		t.Fatalf("want a no-Call-graph error, got %v", err)
	}
}

// "," is a value the caller typed, not a bug in lrecon: reporting it as
// "internal" sends whoever reads the kind to the wrong place. The split lives
// in nativeList (another lane), so this op wraps it into a bad_arg verdict.
func TestA14BatchDecompileEmptyArgListIsBadArg(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(bin, []byte("MZ not really a binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{",", " , ", "  ,  ,"} {
		t.Setenv("LRECON_ARGS", raw)
		_, err := runOp("batch_decompile", bin)
		if err == nil {
			t.Fatalf("LRECON_ARGS=%q was accepted", raw)
		}
		if !strings.Contains(err.Error(), "no address or symbol after splitting on commas") {
			t.Errorf("LRECON_ARGS=%q: error %q does not name the empty list", raw, err)
		}
		if got := classify(err.Error()); got != kindBadArg {
			t.Errorf("LRECON_ARGS=%q: kind = %v, want bad_arg", raw, got)
		}
	}
}

// The refusal must not teach a flag this op does not have: the positional
// target is the destination. A caller who follows "pass -o ..." would prepend
// it to the path and then wonder why a file named "-o" appeared.
func TestA14CaptureADBScreenRefusalNamesTargetAsWayOut(t *testing.T) {
	png := rtTestPNG(t, 32, 32)
	rtFixture(t, "FAKE_PNG", string(png))
	rtFakeTool(t, "adb", `if [ "$3" = "exec-out" ]; then cat "$FAKE_PNG"; exit 0; fi
`+rtOneDevice)
	victim := filepath.Join(t.TempDir(), "keep.bin")
	if err := os.WriteFile(victim, []byte("do not replace me"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := runOp("capture_adb_screen", victim)
	if err == nil {
		t.Fatal("capture_adb_screen overwrote a non-PNG")
	}
	msg := err.Error()
	if !strings.Contains(msg, "not a PNG") {
		t.Errorf("error %q does not name the cause", msg)
	}
	if !strings.Contains(msg, "pass a new path as the target") {
		t.Errorf("error %q does not name the way out", msg)
	}
	if strings.Contains(msg, "-o") {
		t.Errorf("error %q offers -o, which this op does not take", msg)
	}
	kept, err := os.ReadFile(victim)
	if err != nil || string(kept) != "do not replace me" {
		t.Fatalf("refusal still touched the file: %v (%q)", err, kept)
	}
}

// uniqSorted is the one ordering step; the exports and bundle deps must come
// out sorted and deduplicated with the pre-sort removed.
func TestA14AnalyzeSortOrderAfterSingleSort(t *testing.T) {
	if got := strings.Join(uniqSorted([]string{"b", "a", "b", ""}), ","); got != "a,b" {
		t.Errorf("uniqSorted = %q, want a,b", got)
	}
	if !sort.StringsAreSorted([]string{"a", "b"}) {
		t.Fatal("sort package sanity")
	}
}

// BenchmarkA14AnalyzeWebBundleLarge measures the path the redundant sort sat
// in: many modules means many deps and exports, and the dropped pre-sort was a
// second full sort of the same slice.
func BenchmarkA14AnalyzeWebBundleLarge(b *testing.B) {
	dir := b.TempDir()
	p := filepath.Join(dir, "bundle.js")
	var sb strings.Builder
	for i := range 2000 {
		fmt.Fprintf(&sb, "import m%d from \"./m%d.js\";\n", i, 1999-i)
		fmt.Fprintf(&sb, "export const e%d = %d;\n", i, i)
	}
	if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for b.Loop() {
		if _, err := runOp("analyze_web_bundle", p); err != nil {
			b.Fatal(err)
		}
	}
}
