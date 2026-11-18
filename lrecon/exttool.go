package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// Shared plumbing for the external-tool items (--ext-op). Every one of them
// drives a tool the reader installed and answers with what the tool said, or
// with an honest refusal when the tool, the device or the deadline is
// missing. None of them invents a result.
//
// The items are the addendum's 80 (451-530): adb 25, lldb 20, jadx 12,
// apktool 10, Ghidra 13. They live outside the --op table on purpose, so the
// published 229-item inventory stays byte-identical.

// The deadlines the plan names: a device or debugger item gets 60 s, a Ghidra
// import 50 s.
const (
	extTimeoutY = 60 * time.Second
	extTimeoutG = 50 * time.Second
)

// The alternatives a skip has to name, one per tool the items drive. A reader
// who hits "not installed" learns what to install, not just that it is gone.
const (
	extAdbAlt     = "install Android platform-tools (adb 1.0.41) and put it on PATH"
	extLldbAlt    = "install LLVM lldb (1703) and put it on PATH"
	extJadxAlt    = "install jadx 1.5.6 and put it on PATH"
	extApktoolAlt = "install apktool 3.0.3 and put it on PATH"
	extGhidraAlt  = "install Ghidra 12.1.4 and set LRECON_GHIDRA to its install dir"
)

// extCtx returns a context with the item's deadline.
func extCtx(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// extRefusal is an item's refusal with the kind it knows better than the
// message does. The item returns it; the CLI turns it into the envelope.
type extRefusal struct {
	kind errorKind
	msg  string
}

func (e *extRefusal) Error() string { return e.msg }

// extRefuse builds a refusal with an explicit kind, so the envelope's kind
// comes from the call site and not from a guess on the prose.
func extRefuse(kind errorKind, format string, a ...any) error {
	return &extRefusal{kind: kind, msg: fmt.Sprintf(format, a...)}
}

// extOut is the answer an item gives when its tool ran: which tool, which
// arguments, and what it printed. An item that can parse the output adds its
// own fields next to these.
type extOut struct {
	Tool   string   `json:"tool"`
	Args   []string `json:"args,omitempty"`
	Output string   `json:"output,omitempty"`
	Lines  []string `json:"lines,omitempty"`
}

// extDir is the directory an item writes into. -o names it when the caller
// gave one; without -o the item gets a fresh temp directory it removes again,
// so a sweep over 80 items leaves nothing behind.
func extDir() (dir string, cleanup func(), err error) {
	if v := strings.TrimSpace(opOutput); v != "" {
		if err := os.MkdirAll(v, 0o755); err != nil {
			return "", nil, err
		}
		return v, func() {}, nil
	}
	d, err := tempDir("lrecon-ext-")
	if err != nil {
		return "", nil, err
	}
	return d, func() { os.RemoveAll(d) }, nil
}

// extRun runs one binary and returns stdout and stderr. The tool's own
// non-zero exit is a refusal with the no_engine kind (the tool ran but could
// not produce an answer on this target: wrong artifact, tool error, closed
// device) naming the tool, its arguments and the first line it printed, so
// a reader learns why without reading a log. kindInternal must never carry
// this: internal is lrecon's own fault, and the tool's exit is not.
func extRun(ctx context.Context, name, bin string, args ...string) (stdout, stderr string, err error) {
	out, errOut, runErr := rtRunRawStreams(ctx, bin, args...)
	if runErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return string(out), string(errOut), extRefuse(kindTimeout, "%s %s: %s", name, strings.Join(args, " "), ctx.Err())
		}
		if line := extErrorLine(string(errOut)); line != "" {
			return string(out), string(errOut), extRefuse(kindNoEngine, "%s %s: %s", name, strings.Join(args, " "), line)
		}
		if line := extErrorLine(string(out)); line != "" {
			return string(out), string(errOut), extRefuse(kindNoEngine, "%s %s: %s", name, strings.Join(args, " "), line)
		}
		return string(out), string(errOut), extRefuse(kindNoEngine, "%s %s: %v", name, strings.Join(args, " "), runErr)
	}
	return string(out), string(errOut), nil
}

// extErrorLine prefers the line that names the cause: jadx and friends print
// an INFO banner before "error: ...", and the banner alone hides the reason.
func extErrorLine(s string) string {
	first := ""
	for l := range strings.SplitSeq(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if first == "" {
			first = l
		}
		if strings.Contains(strings.ToLower(l), "error:") {
			return l
		}
	}
	return first
}

// extTool runs one external tool. A tool that is not installed is a refusal
// with the no_engine kind, not an error: the item still answers, and the
// answer names the alternative.
func extTool(ctx context.Context, tool, alt string, args ...string) (stdout, stderr string, err error) {
	bin, sk := rtTool(tool, alt)
	if sk != nil {
		return "", "", extRefuse(kindNoEngine, "%s", sk.Reason)
	}
	return extRun(ctx, tool, bin, args...)
}

// extAdb runs one adb command against the host. The items that need a device
// gate on it themselves; the host-only subcommands do not.
func extAdb(ctx context.Context, args ...string) (stdout, stderr string, err error) {
	return extTool(ctx, "adb", extAdbAlt, args...)
}

// extLldb runs lldb in batch mode: one -o command per line, then the target.
// Batch mode is the only honest way to drive lldb from a program: the
// interactive console has no exit the caller can wait for.
func extLldb(ctx context.Context, commands []string, target string) (stdout, stderr string, err error) {
	bin, sk := rtTool("lldb", extLldbAlt)
	if sk != nil {
		return "", "", extRefuse(kindNoEngine, "%s", sk.Reason)
	}
	args := []string{"--batch"}
	for _, c := range commands {
		args = append(args, "-o", c)
	}
	if target != "" {
		args = append(args, "--", target)
	}
	return extRun(ctx, "lldb", bin, args...)
}

// extGhidra runs analyzeHeadless. The import is what costs minutes, so the
// item's own deadline is short and a missing Ghidra is refused before any
// JVM is started.
func extGhidra(ctx context.Context, args ...string) (stdout, stderr string, err error) {
	gh, _, err := findGhidra()
	if err != nil {
		return "", "", extRefuse(kindNoEngine, "ghidra analyzeHeadless not installed: %s; %s", err.Error(), extGhidraAlt)
	}
	return extRun(ctx, "analyzeHeadless", gh, args...)
}
