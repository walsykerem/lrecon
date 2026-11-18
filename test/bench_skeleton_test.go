package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// BenchmarkSkeletonResolve is the real-file simulation: it reports what the
// resolver claims on shipped binaries, how long it takes, and how its interval
// count lines up with the symbol table. A mismatch is information, not a
// failure (ICF, thunks and cold splits make the two counts legitimately
// differ), which is why this is a benchmark and not a test: with no assertions
// it must never show up as a passing test.
func BenchmarkSkeletonResolve(b *testing.B) {
	exe, _ := os.Executable()
	paths := []string{
		"/bin/ls", "/bin/sh", "/usr/bin/otool", "/usr/bin/sample",
		"/usr/bin/ssh", "/usr/local/bin/kubectl", "/opt/homebrew/bin/gh",
		"/usr/lib/dyld", exe,
		"/usr/local/lib/node_modules/systray2/traybin/tray_linux_release",
	}
	b.Logf("%-30s %10s %10s %7s %8s %6s %s", "path", "text", "attrib", "ratio", "iv", "status", "nm")
	for _, p := range paths {
		if _, err := os.Stat(p); err != nil {
			b.Logf("%-30s skipped: %v", p, err)
			continue
		}
		d, err := Probe(p)
		if err != nil {
			b.Logf("%-30s probe: %v", p, err)
			continue
		}
		if d.Skeleton == nil {
			b.Logf("%-30s no skeleton (kind %s)", p, d.Kind)
			continue
		}
		s := resolveSkeleton(p, &d)
		ratio := "-"
		if s.Ratio != nil {
			ratio = fmt.Sprintf("%.1f%%", *s.Ratio*100)
		}
		b.Logf("%-30s %10d %10d %7s %8d %6s %s",
			p, s.TextBytes, s.Attributed, ratio, s.Intervals,
			fmt.Sprintf("%-7s", s.Status), nmCount(p))
		if s.Note != "" {
			b.Logf("%-30s note: %s", "", s.Note)
		}
		digest := d
		b.Run(strings.TrimPrefix(p, "/"), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if got := resolveSkeleton(p, &digest); got == nil {
					b.Fatalf("%s: resolveSkeleton returned nil after a successful probe", p)
				}
			}
		})
	}
}

// nmCount is the oracle: how many text symbols the symbol table names. The
// resolver counts linker intervals, so parity is not expected. nm is only a
// test oracle; the product path never runs an external command.
func nmCount(path string) string {
	out, err := exec.Command("nm", "-n", path).Output()
	if err != nil {
		return "n/a"
	}
	n := 0
	for ln := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && (f[len(f)-2] == "t" || f[len(f)-2] == "T") {
			n++
		}
	}
	return fmt.Sprint(n)
}
