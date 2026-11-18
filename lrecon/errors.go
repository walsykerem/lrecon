package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// An error kind is the machine half of a refusal: the closed set a caller may
// switch on without reading English. The message keeps the detail; the kind
// keeps the decision. Same rule as the reader skip reasons, applied to the CLI.
type errorKind string

const (
	kindNeedsArg      errorKind = "needs_arg"      // a flag, target or environment value the call cannot do without
	kindBadArg        errorKind = "bad_arg"        // the value was given and is wrong for this call
	kindOutOfScope    errorKind = "out_of_scope"   // the request is outside what lrecon does, not an environment gap
	kindNoEngine      errorKind = "no_engine"      // the tool, device or process the route needs is not here
	kindTimeout       errorKind = "timeout"        // a step hit its deadline
	kindUsage         errorKind = "usage"          // the flags cannot be one document
	kindIO            errorKind = "io"             // the target could not be read or written
	kindStateConflict errorKind = "state_conflict" // the state tree holds a different artifact; refusing to overwrite it
	kindInternal      errorKind = "internal"       // lrecon's own fault; the message is the clue
)

// kindList is the closed set, for tests and docs that check every refusal lands
// on a kind a caller can switch on.
var kindList = []errorKind{
	kindNeedsArg, kindBadArg, kindOutOfScope, kindNoEngine, kindTimeout,
	kindUsage, kindIO, kindStateConflict, kindInternal,
}

// envelope is the refusal path's machine answer: one object on stdout, exit 2.
// --json used to be read on the success path only, so a caller had to regex
// stderr to learn why 195 of 229 ops refused. op is null when no op was named.
type envelope struct {
	// ContractVersion is the digest contract version too: a caller that only
	// ever sees refusals still learns which key set the answers belong to.
	ContractVersion int     `json:"contract_version"`
	Op              *string `json:"op"`
	// Target is the path the refusal is about, the same key the success
	// envelope carries. Without it two files that fail the same way produced
	// byte-identical refusals, so a sweep of 40 binaries could not say which
	// one refused. Absent when the call named no target (a usage refusal).
	Target string    `json:"target,omitempty"`
	Error  string    `json:"error"`
	Kind   errorKind `json:"kind"`
	// Stage is present only when a step ran out of time and can name what it
	// was doing (an asar container, an import, a post pass). A refusal without
	// a deadline carries no stage, so the old shape is not widened for every
	// caller.
	Stage string `json:"stage,omitempty"`
}

// refuseStage is set by the op that hit its own deadline, just before it
// returns the timeout error. It is read once by refuseKind and cleared, so a
// later unrelated refusal cannot inherit a stale stage.
var (
	refuseMu    sync.Mutex
	refuseStage string
)

func setRefuseStage(stage string) {
	refuseMu.Lock()
	refuseStage = stage
	refuseMu.Unlock()
}

// takeRefuseStage reads and clears the stage under the same lock: an abandoned
// op goroutine may still be writing when the deadline refusal is built.
func takeRefuseStage() string {
	refuseMu.Lock()
	defer refuseMu.Unlock()
	stage := refuseStage
	refuseStage = ""
	return stage
}

// refuseState is filled once by main, before anything can refuse. The flag
// package stops at the first positional and at the first error, so --json and
// --op are not both known at every refusal site; the raw arguments are.
var refuseState struct {
	json   bool
	op     string
	target string
}

// refuse says lrecon could not answer: exit 2, the reason on stderr plus a
// machine envelope on stdout when --json or an op asked for one. Exit 1 is
// reserved for "compared and differs" (--diff), so a refused step never passes
// for a clean result.
func refuse(msg string) {
	refuseKind(classify(stripTarget(msg)), msg)
}

// stripTarget takes the caller's path out of a message before classification:
// a file named "timeout", "not installed" or "out-of-scope" is still a bad
// file, and its name must not decide the kind a caller switches on.
func stripTarget(msg string) string {
	if refuseState.target == "" {
		return msg
	}
	msg = strings.ReplaceAll(msg, refuseState.target, "<target>")
	if abs, err := filepath.Abs(refuseState.target); err == nil && abs != refuseState.target {
		msg = strings.ReplaceAll(msg, abs, "<target>")
	}
	return msg
}

// refuseKind is refuse with a kind the caller knows better than the message
// does: a missing --extract value is needs_arg even though the text is prose.
//
// The reason always lands on stderr with the lrecon: prefix, in every mode, so a
// person at the terminal reads one line and a caller that logs stderr never has
// to guess the mode. When stdout is a machine channel (--json, or an op that
// answers JSON), the same refusal also lands there as one envelope, so a caller
// switching on kind does not have to parse prose.
func refuseKind(kind errorKind, msg string) {
	fmt.Fprintf(os.Stderr, "lrecon: %s\n", msg)
	if !refuseState.json && refuseState.op == "" {
		// Text mode: the prefixed line above is the whole answer.
		os.Exit(2)
	}
	var op *string
	if refuseState.op != "" {
		name := refuseState.op
		op = &name
	}
	stage := takeRefuseStage()
	e := envelope{ContractVersion: contractVersion, Op: op, Target: refuseState.target, Error: msg, Kind: kind, Stage: stage}
	var b []byte
	var err error
	if refuseState.json {
		b, err = json.MarshalIndent(e, "", "  ")
	} else {
		// Text mode already printed the line above; a compact envelope keeps the
		// kind machine-readable without paying for indentation (item 70).
		b, err = json.Marshal(e)
	}
	if err != nil {
		// A fixed three-field struct cannot fail, but half a document is a parse
		// error: the prefix line above is the whole honest answer then.
		os.Exit(2)
	}
	fmt.Println(string(b))
	os.Exit(2)
}

// decline is refuse for a request lrecon will not answer at all: an out-of-scope
// target, or two modes that cannot be one document. --json still promises one
// machine answer, so a caller sweeping the ops gets an envelope here too
// instead of bare stderr text.
func decline(msg string) {
	kind := kindBadArg
	switch {
	case containsAny(strings.ToLower(msg), "cannot be combined", "cannot be one", "mutually exclusive"):
		// Two modes cannot be one document: that is a usage error, not a bad target.
		kind = kindUsage
	case containsAny(strings.ToLower(msg), "out of scope", "out-of-scope", "out scope"):
		// The request is outside the product: nothing to install, nothing to fix.
		kind = kindOutOfScope
	}
	declineKind(kind, msg)
}

// declineKind is decline with the kind named by the call site, for refusals
// whose prose would otherwise classify as internal.
func declineKind(kind errorKind, msg string) {
	refuseKind(kind, msg)
}

// formatRefusal refuses a target that is not the format the op reads. A path
// that is not there was never read, so it keeps its io error instead of
// masquerading as a wrong-format file: the kind has to name the first problem.
func formatRefusal(path, msg string) error {
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return fmt.Errorf("%s %s", path, msg)
}

// classify names a refusal from its message. Ops return errors and skips from
// their own files, so the text is the only contract between them and the
// envelope: the rules are ordered, first match wins. The order runs from the
// most specific cause to the most general: a deadline is never a device
// problem, a device problem is never a missing argument, and a state conflict
// must not be read as a bad path ("... is not a state directory").
func classify(msg string) errorKind {
	m := strings.ToLower(msg)
	switch {
	case containsAny(m, "needs a target", "needs target", "needs: ", "needs a value", "needs an argument",
		"needs -o ", "is not set", "is not configured", "missing argument",
		"flag needs an argument", "requires an argument", "requires a value",
		"job needs ", "job has no ", "needs at least one", "this op needs "):
		return kindNeedsArg
	case containsAny(m, "timed out", "timeout", "deadline exceeded"):
		return kindTimeout
	case containsAny(m, "killed: 9", "killed:9", "signal: killed", "signal 9", "sigkill"):
		return kindNoEngine
	case containsAny(m, "state conflict"):
		return kindStateConflict
	case strings.Contains(m, "failure [not installed") || strings.Contains(m, "delete_failed"):
		// `pm uninstall` on an absent package and a failed delete are facts
		// about the *target*, not about a missing engine: the device answered,
		// the package is not there. Without this the phrase "not installed"
		// below filed it under no_engine and a caller went looking for adb.
		return kindBadArg
	case containsAny(m, "out of scope", "out-of-scope", "out scope"):
		// Scope is the product contract: the request is not a wrong value and
		// the machine is not missing an engine, so a caller reading this kind
		// must not go install a tool it does not need.
		return kindOutOfScope
	case strings.Contains(m, " cap") && containsAny(m, " above ", " over ", " larger than "):
		// A numeric value past its documented cap is a bad request the caller
		// can fix, not a surprise inside lrecon. Three readers word it three
		// ways: an env value ("above the"), opRead ("over the") and readCapped
		// ("larger than").
		return kindBadArg
	case strings.Contains(m, "lrecon_arch="):
		// A universal binary is analysed slice by slice, and only the first
		// slice is importable: a request for another one is the caller's to fix,
		// not an internal failure.
		return kindBadArg
	case containsAny(m, "not installed", "command not found", "executable file not found",
		"no device", "no live process", "not on path", "no decompiler", "not available",
		"not ready", "no session", "decoders.json not found", "decoder table",
		"not found: ship ",
		// Ghidra imported the file and its own GoRttiMapper analyzer refused the
		// target's Go version ("Untested Go version [1.26.5]"). The engine
		// answered, lrecon did not fail: same class as the analyzeHeadless exit
		// path in exttool.go, so a caller does not hunt a fault in the op.
		"untested go version",
		"can't find service", "cannot find service", "listed no windows",
		"failed to connect to ", "connection refused"):
		return kindNoEngine
	case engineExitFailed(m):
		// A device or browser step that ran and failed is a missing engine, not
		// a bad file: adb/cdp/logcat report through their own exit status.
		return kindNoEngine
	case strings.Contains(m, "set lrecon_"):
		// A message that says how to name the missing environment value is a
		// missing argument, but a tool that is not here still wins (see the
		// decoder-table message), so this needle stays after no_engine.
		return kindNeedsArg
	case containsAny(m, "no such file", "does not exist", "permission denied", "operation not permitted", "is a directory",
		"read-only file system", "cannot read", "cannot write", "cannot be read",
		"invalid argument"):
		return kindIO
	case containsAny(m, "no function contains", "no function named"):
		// Meta.java IllegalStateException naming an address/name the program
		// does not have is a caller-supplied value, not a lrecon surprise.
		return kindBadArg
	case containsAny(m, "unknown ", "invalid value", "flag provided but not defined",
		"unable to resolve intent", "activity not started", "no process named",
		"cannot be combined", "takes one target", "not a ", "not an ", "is not ",
		"with no ", "unsupported", "not supported", "implemented for this variant",
		"is neither", "neither a ",
		"has no ", "carries no ", "does not carry", "no end-of-central-directory",
		"the file was not recognized", "not recognized as a valid object file",
		"doesn't end .apk", "no sourcemappingurl trailer", "nothing to recover",
		"header json length", "asar header json", "asar header: ",
		"are covered by ", "is covered by ", "shorter than one 4 kib block",
		"shorter than the dart header", "has an empty header or an empty body", "has one json line", "too short for a dispatcher", "shorter than the 8-byte header length",
		"must be ", "is one file:", "script files, want", "no page to load",
		"no capture directory:", "no static bundle:", "no line to break on",
		"takes two targets", "takes a pid target", "takes a target", "refused:", "no mz header",
		"no push4", "bytes, file holds", "devices ready", "is not attached",
		"reads on-disk headers only"):
		return kindBadArg
	}
	return kindInternal
}

// engineExitFailed reports a tool that exists and ran, but could not reach its
// device, page or service. The tool name keeps a bare "exit status 1" from a
// local command out of no_engine.
func engineExitFailed(m string) bool {
	if !strings.Contains(m, "exit status ") {
		return false
	}
	return containsAny(m, "adb ", "adb:", "cdp ", "dumpsys", "logcat ", "frida", "gdb ")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// sawJSON reads the raw arguments because parsing stops early: --json after a
// target, or after a flag error, still promises machine output on stdout.
func sawJSON(args []string) bool {
	for _, a := range args {
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if name != "json" {
			continue
		}
		if !hasValue {
			return true
		}
		v, err := strconv.ParseBool(value)
		return err != nil || v
	}
	return false
}

// swallowedFlag reports a value flag whose value is another flag: `--op --json`
// gives op the text "--json" and leaves --json unset, so a missing argument
// looked like an empty target. Booleans take no value and are not checked.
func swallowedFlag(fs *flag.FlagSet) (name, value string) {
	type boolFlag interface{ IsBoolFlag() bool }
	fs.Visit(func(f *flag.Flag) {
		if name != "" {
			return
		}
		if b, ok := f.Value.(boolFlag); ok && b.IsBoolFlag() {
			return
		}
		v := f.Value.String()
		if v == "" || !strings.HasPrefix(v, "-") || v == "-" {
			return
		}
		// A negative number is a value; another flag name is not.
		if strings.HasPrefix(v, "--") || fs.Lookup(strings.TrimLeft(v, "-")) != nil {
			name, value = f.Name, v
		}
	})
	return name, value
}
