package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pinnedMakeCount is the number of raw make([]byte, …) sites left in non-test
// code. Every declared length goes through allocCeil; a new raw site raises the
// count, so the test fails until it is routed or the pin is argued for.
//
// 41 = 37 as of the mechanism-recovery round plus four bounded reads that need
// no ceiling: lsda.go:208 (4-byte magic), lsda.go:955 (n already checked against
// the mapped region size), lsda.go:1019 (size gated by lsdaMaxSection),
// swiftfield.go:504 (n is a call-site constant).
//
// 57 = those 41 plus the 16 sites the 229-item op batch added, every one of them
// a constant or a length already bounded before the make. Named by symbol, since
// line numbers drift: op_analyze_javascript_application (4-byte magic),
// op_analyze_swift_types (the va closure is only called with 12 and 200),
// op_inspect_electron_fuses (fixed 8 MiB scan block; fixed 40-byte trailer),
// op_inspect_erlang_beam (beamHeaderLen and beamChunkLen constants; the three
// chunk bodies are refused when body+size runs past the container),
// op_inspect_evm_interface (len(t)/2), op_native_util nativeSectionBytes (limit
// applied first), peBlock (PE section size), nativeReadAt (LRECON_LEN refuses
// above 1<<16), op_static_util readEntry and machoSectionData (file size and
// section size are both checked against opMaxFile first), op_web_util (len(src)).
// 59 = those 57 plus two sites added with the op batch, both bounded by a
// check on the line above: op_static_util machoSectionBytes refuses s.Size above
// opMaxFile before the make, and op_inspect_evm_interface decodes at most half of
// an input that opRead already capped.
//
// 63 = those 59, minus op_web_util's 64 KiB exec buffer that went away with the
// node runner, plus five sites in the CDP client and the sysctl process table:
// cdp.go:293 (fixed 16-byte nonce), cdp.go:485 and cdp.go:518 (the payload
// length is refused above cdpMaxFrame at cdp.go:476 before either make),
// cdp.go:499 (fixed 14-byte frame header), proctable_darwin.go:39 (the
// remainder is 1..darwinKinfoProcSize-1, padding one partial record).
//
// 64 = those 63 plus proctable_darwin.go:66, the same sysctl padding written a
// second time in listProcesses (the whole-table decode that list_frida_processes
// reads instead of spawning ps): b is len(sysctl) and the remainder is again
// 1..darwinKinfoProcSize-1.
// 62 = those 64 minus pyc.go's 16 MiB header buffer, which now reads through
// io.ReadAll(io.LimitReader(f, pycMaxRead)): the same ceiling is a read limit
// instead of a raw make site; and minus the second Atom/AtU8 body buffer, since
// op_inspect_erlang_beam now decodes both chunk ids through one case. Two
// separate lanes each dropped one site, so the pin drops by two.
// 61 = those 62 minus detect.go's 512-byte head buffer, which is now captured
// during the single hash pass into a stack array (headCapture) instead of a
// heap make after a second seek+read.
// 63 = those 61 plus the two body buffers readAsarSlice and readAsarTail grew
// when asar members stopped sharing the header ceiling: readAsarSlice clamps the
// declared size to limit before the make, readAsarTail allocates the caller's
// constant scan window (maxIPCScanFile).
// 64 = those 63 plus op_verify_reconstruction.go:72, which re-reads each claimed
// window at its offset (f.ReadAt into a len(want) buffer) instead of loading the
// whole artifact, so a huge file is never one allocation.

const pinnedMakeCount = 64

func TestNoUnboundedMake(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob *.go: %v (%d files)", err, len(files))
	}
	var sites []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "make([]byte") {
				sites = append(sites, fmt.Sprintf("%s:%d", name, i+1))
			}
		}
	}
	if len(sites) != pinnedMakeCount {
		t.Fatalf("%d raw make([]byte) sites, pinned %d: %v", len(sites), pinnedMakeCount, sites)
	}
}
