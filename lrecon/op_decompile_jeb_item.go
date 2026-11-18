package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

// 7. decompile_jeb_item — y1: jadx's single-class mode is the only route.
// The embedded Java API is not callable from Go, so there is no in-process
// fallback; the class source is whatever jadx wrote.
func init() {
	registerOp(op{
		name:  "decompile_jeb_item",
		route: "Y",
		desc:  "jadx --single-class <fqcn> --single-class-output <out>.java <apk>; target <apk>:<fqcn>, source of that one class (final.md y1, item 7)",
		needs: true,
		run:   opDecompileJebItem,
	})
}

const jebdJadxAlt = "install jadx and run `jadx --single-class <fqcn> --single-class-output <out>.java <apk>`; the embedded Java API cannot be called from Go (final.md y1)"

// jebdSourceCap keeps one Java class out of a several-MB JSON line while still
// showing the whole reconstructed method bodies real APKs produce.
const jebdSourceCap = 512 << 10

type jebdSource struct {
	Class string `json:"class,omitempty"`
	Bytes int    `json:"bytes"`
	// Engine names what actually produced the source: the op is a JEB item, but
	// with JEB absent the route is jadx, and the answer must not imply otherwise.
	Engine       string `json:"engine"`
	JEBInstalled bool   `json:"jeb_installed"`
	Source       string `json:"source,omitempty"`
	Found        bool   `json:"found"`
	Note         string `json:"note,omitempty"`
}

// jebInstalled reports whether a JEB CLI is on PATH. JEB's embedded Java API
// has no stable command line, so even when it is installed the route stays
// jadx and the answer says so.
func jebInstalled() bool {
	return slices.ContainsFunc([]string{"jeb", "jeb_macos", "jeb_linux", "jeb_win"}, rt2Installed)
}

// jebEngineNote is the sentence every item-level answer carries: the name of
// the op is not evidence that JEB ran.
func jebEngineNote(installed bool) string {
	if installed {
		return "JEB is installed but exposes no non-interactive class route; jadx --single-class produced this source (final.md y1)"
	}
	return "JEB is not installed on this host; jadx --single-class produced this source (final.md y1)"
}

func opDecompileJebItem(target string) (any, error) {
	apk, fqcn, err := rt2Pair(target, ":")
	if err != nil {
		return nil, fmt.Errorf("%w (want <apk>:<fqcn>)", err)
	}
	if !rt2Installed("jadx") {
		return skipf("jadx not installed: %s", jebdJadxAlt), nil
	}
	dir, err := tempDir("lrecon-jadx-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// A name without the .java suffix is read as a directory by jadx, so the
	// file name is fixed rather than derived from the class name.
	out := filepath.Join(dir, "class.java")
	// --show-bad-code keeps a class whose other methods failed from yielding no
	// source at all; --threads-count bounds jadx's per-core default. Both are
	// measured on an ApiDemos APK (14.5 s -> 11.9 s, same bytes).
	args := []string{"--threads-count", strconv.Itoa(jebdJadxThreads()), "--show-bad-code",
		"--single-class", fqcn, "--single-class-output", out, apk}
	stdout, sk, err := rt2RunTimeout("jadx", jebdJadxAlt, rt2APKTimeout(), args...)
	if sk != nil || err != nil {
		if err != nil {
			// jadx's cause is on stdout; rt2APKTimeout is the APK-decoder
			// budget rt2Timeout's 20 s probe budget replaced. The temp dir
			// carries a random suffix, so identical calls must report the
			// same <tmpdir>.
			err = jebdRedact(jebdJadxFailure(fqcn, args, stdout, err), dir)
		}
		return sk, err
	}
	b, err := os.ReadFile(out)
	if errors.Is(err, os.ErrNotExist) {
		return jebdSource{Found: false, Engine: "jadx", JEBInstalled: jebInstalled(),
			Note: "jadx exited 0 but wrote no class.java for " + fqcn}, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return jebdSource{Found: false, Engine: "jadx", JEBInstalled: jebInstalled(),
			Note: "jadx wrote an empty class.java for " + fqcn}, nil
	}
	res := jebdSource{Class: fqcn, Bytes: len(b), Engine: "jadx", JEBInstalled: jebInstalled(), Source: string(b), Found: true,
		Note: jebEngineNote(jebInstalled())}
	if len(b) > jebdSourceCap {
		res.Source = string(b[:jebdSourceCap]) + "\n// truncated: output is " + fmt.Sprint(len(b)) + " bytes\n"
		res.Note = fmt.Sprintf("source truncated at %d of %d bytes", jebdSourceCap, len(b))
	}
	return res, nil
}

// jebdJadxThreads is the --threads-count value. jadx defaults to one worker
// per core with no cap, and on a busy host the extra workers contend more than
// they decompile; 8 is where the measured gain flattened.
// LRECON_JADX_THREADS overrides it.
func jebdJadxThreads() int {
	n := min(runtime.NumCPU(), 8)
	if v := strings.TrimSpace(os.Getenv("LRECON_JADX_THREADS")); v != "" {
		if m, err := strconv.Atoi(v); err == nil && m > 0 && m <= 64 {
			n = m
		}
	}
	return n
}

// jebdJadxDiagnostic is jadx's own verdict on a failed run. jadx reports on
// stdout ("ERROR - Incorrect arguments: ...", "Failed to ...") and rt2Cause
// only knows the adb/am prefixes, so the first line a caller saw was the
// "INFO  - loading ..." banner. The first two error lines name the cause
// without the java stack.
func jebdJadxDiagnostic(text string) string {
	var picked []string
	for raw := range strings.SplitSeq(text, "\n") {
		l := strings.TrimSpace(raw)
		switch {
		case strings.Contains(l, "ERROR"):
			l = l[strings.Index(l, "ERROR"):]
		case strings.HasPrefix(l, "Failed to"), strings.HasPrefix(l, "java.lang."), strings.HasPrefix(l, "java."):
		default:
			continue
		}
		if l == "" {
			continue
		}
		picked = append(picked, l)
		if len(picked) == 2 {
			break
		}
	}
	s := strings.Join(picked, "; ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// jebdJadxFailure keeps jadx's cause. The refusal kind comes from the wording
// because main refuses with refuse(err.Error()) and classify() reads text
// only: an unknown class and a file jadx cannot open are the caller's values,
// so both say so. A deadline keeps its own text and classifies as timeout.
func jebdJadxFailure(fqcn string, args []string, out string, err error) error {
	msg := jebdJadxDiagnostic(out)
	if msg == "" {
		msg = jebdJadxDiagnostic(err.Error())
	}
	if msg == "" {
		return err
	}
	run := fmt.Sprintf("jadx %s failed: %s", strings.Join(args, " "), msg)
	apk := args[len(args)-1]
	switch {
	case strings.Contains(msg, "can't be saved"), strings.Contains(msg, "DONT_GENERATE"):
		// The class exists but jadx marks it DONT_GENERATE (synthetic or
		// generated); --single-class cannot emit it either way.
		return fmt.Errorf("%s is not a class jadx can save: %s", fqcn, run)
	case strings.Contains(msg, "File open error"):
		return fmt.Errorf("%s is not a readable DEX/APK: %s", apk, run)
	case strings.Contains(msg, "Incorrect arguments"), strings.Contains(msg, "not found"):
		return fmt.Errorf("unknown class %s in %s: %s", fqcn, apk, run)
	}
	return fmt.Errorf("%s", run)
}

// jebdRedact gives identical calls identical text: the temp dir has a random
// suffix.
func jebdRedact(err error, dir string) error {
	return fmt.Errorf("%s", strings.ReplaceAll(err.Error(), dir, "<tmpdir>"))
}
