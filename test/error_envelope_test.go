package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeEnvelope reads the one JSON object the refusal path promises on stdout:
// exactly op, error and kind (plus target when the call named one), so a
// consumer switches on kind and never parses English.
func decodeEnvelope(t *testing.T, stdout string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, stdout)
	}
	if len(m) != 4 && len(m) != 5 {
		t.Fatalf("envelope = %v, want exactly contract_version, op, error, kind (+ target)", m)
	}
	for _, key := range []string{"contract_version", "op", "error", "kind"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("envelope has no %q: %s", key, stdout)
		}
	}
	if v, ok := m["target"]; ok {
		if s, _ := v.(string); s == "" {
			t.Fatalf("envelope target = %v, want the path it is about: %s", v, stdout)
		}
	}
	if m["contract_version"] != float64(contractVersion) {
		t.Fatalf("contract_version = %v, want %d", m["contract_version"], contractVersion)
	}
	return m
}

// opNeedingTarget picks a registered op that wants a path, so the needs_arg
// case does not hard-code one item's name.
func opNeedingTarget() string {
	for _, name := range opNames() {
		if ops[name].needs {
			return name
		}
	}
	return "list_procedures"
}

// A refusal used to be prose on stderr even under --json, so a caller had to
// regex the reason out. The same three facts now travel on stdout, exit 2.
func TestRefusalEnvelope(t *testing.T) {
	a := writeTemp(t, "one.txt", []byte("one\n"))
	b := writeTemp(t, "two.txt", []byte("two\n"))
	wantsTarget := opNeedingTarget()

	cases := []struct {
		name string
		args []string
		kind string
		op   any // nil when no op was named
		says string
	}{
		{"unknown op", []string{"--op", "no_such_op_for_test", "--json"}, "bad_arg", "no_such_op_for_test", "unknown op"},
		{"missing op value", []string{"--op", "--json"}, "needs_arg", nil, "--op"},
		{"op needs a target", []string{"--op", wantsTarget, "--json"}, "needs_arg", wantsTarget, "needs a target"},
		{"no target", []string{"--json"}, "usage", nil, "no target"},
		{"two targets", []string{"--json", a, b}, "usage", nil, "targets given"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			m := decodeEnvelope(t, stdout)
			if m["kind"] != c.kind {
				t.Fatalf("kind = %v, want %s: %s", m["kind"], c.kind, stdout)
			}
			if m["op"] != c.op {
				t.Fatalf("op = %v, want %v: %s", m["op"], c.op, stdout)
			}
			if detail, _ := m["error"].(string); !strings.Contains(detail, c.says) {
				t.Fatalf("error = %q, want it to say %q", detail, c.says)
			}
		})
	}
}

// flag parsing stops at the first positional, so --json after a target used to
// be missed; the raw-argument scan must still answer as JSON.
func TestRefusalEnvelopeAfterPositional(t *testing.T) {
	target := writeTemp(t, "pos.txt", []byte("x\n"))
	stdout, _, code := runCLIAll(t, target, "--op", "no_such_op_for_test", "--json")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stdout:\n%s", code, stdout)
	}
	m := decodeEnvelope(t, stdout)
	if m["kind"] != "bad_arg" || m["op"] != "no_such_op_for_test" {
		t.Fatalf("envelope = %v, want bad_arg for the named op", m)
	}
}

// A1: two targets that refuse for the same reason must not answer with
// byte-identical envelopes, or a sweep of 40 binaries cannot say which one
// refused. The failure here is target-independent on purpose: only the target
// key can tell the two apart.
func TestRefusalEnvelopeNamesTarget(t *testing.T) {
	t.Setenv("LRECON_AT", "")
	a := writeTemp(t, "a.txt", []byte("a\n"))
	b := writeTemp(t, "b.txt", []byte("b\n"))
	var got [2]map[string]any
	for i, target := range []string{a, b} {
		stdout, _, code := runCLIAll(t, target, "--op", "procedure_info", "--json")
		if code != 2 {
			t.Fatalf("exit %d, want 2; stdout:\n%s", code, stdout)
		}
		got[i] = decodeEnvelope(t, stdout)
		if got[i]["target"] != target {
			t.Fatalf("target = %v, want %s: %s", got[i]["target"], target, stdout)
		}
	}
	if got[0]["error"] != got[1]["error"] || got[0]["kind"] != got[1]["kind"] {
		t.Fatalf("premise broken: the two files refused differently: %v vs %v", got[0], got[1])
	}
	if a1, a2 := got[0]["target"], got[1]["target"]; a1 == a2 {
		t.Fatalf("both envelopes name %v, want each its own target", a1)
	}
}

// The machine kind must come from the failure, not from the target path: a
// wrapper that retries on "timeout" or probes adb on "no_engine" must not be
// steered by a directory the caller happened to name that way.
func TestRefusalKindIgnoresTargetName(t *testing.T) {
	for _, name := range []string{"timeout", "out-of-scope", "not installed"} {
		dir := filepath.Join(t.TempDir(), name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		stdout, _, code := runCLIAll(t, dir, "--op", "inspect_native_api", "--json")
		if code != 2 {
			t.Fatalf("%s: exit %d, want 2; stdout:\n%s", name, code, stdout)
		}
		m := decodeEnvelope(t, stdout)
		if m["kind"] != "bad_arg" {
			t.Fatalf("%s: kind = %v, want bad_arg (the path name is not a failure kind): %s", name, m["kind"], stdout)
		}
		if m["target"] != dir {
			t.Fatalf("%s: target = %v, want %s: %s", name, m["target"], dir, stdout)
		}
	}
}

// Text mode carries one line on stderr and a compact one-line envelope on
// stdout: the pretty envelope doubled the retry cost of a swept op.
func TestRefusalTextIsOneLine(t *testing.T) {
	stdout, stderr, code := runCLIAll(t, "--op", "no_such_op_for_test")
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr:\n%s", code, stderr)
	}
	if strings.Count(stdout, "\n") != 1 {
		t.Fatalf("text-mode refusal stdout is not one line:\n%s", stdout)
	}
	var env struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil || env.Kind == "" {
		t.Fatalf("stdout = %q, want a kind", stdout)
	}
	if !strings.HasPrefix(stderr, "lrecon: ") || !strings.Contains(stderr, "unknown op") {
		t.Fatalf("stderr = %q, want the lrecon: prefix and the reason", stderr)
	}
}

// classify is the only bridge between the ops' prose and the closed kind set,
// so every kind a message can select is pinned here. usage is not in the table:
// call sites choose it, text cannot.
func TestClassify(t *testing.T) {
	cases := []struct {
		msg  string
		kind errorKind
	}{
		{"ghidra import timed out after 120s", kindTimeout},
		{"context deadline exceeded", kindTimeout},
		{"gdb not installed: brew install gdb", kindNoEngine},
		{"no device attached: connect one and retry; adb devices", kindNoEngine},
		{`op "list_procedures" needs a target path`, kindNeedsArg},
		{"LRECON_AT is not set: export LRECON_AT=<address>", kindNeedsArg},
		{"--extract needs a value", kindNeedsArg},
		{"open /no/such/file: no such file or directory", kindIO},
		{"read /etc/shadow: permission denied", kindIO},
		{`unknown op "zzz" (254 registered; see --list-ops)`, kindBadArg},
		{"/tmp/x.apk: zip, not an Android package (apk/aab)", kindBadArg},
		{"flag provided but not defined: -nope", kindBadArg},
		{"runtime error: index out of range [1] with length 0", kindInternal},
		// Caller-caused refusals the old vocabulary let fall through to internal.
		{"set_comment: job needs \"address\" and \"text\"", kindNeedsArg},
		{"this op needs <apk-or-dex>#<com.example.Class>", kindNeedsArg},
		{"/bin/ls: no MZ header", kindBadArg},
		{"/bin/ls is neither a pcap nor a pcapng capture", kindBadArg},
		{"ghidra script \"analyze_function\" refused: no function named main", kindBadArg},
		{"Meta.java: java.lang.IllegalStateException: no function contains 100000000", kindBadArg},
		{"Meta.java: no function named _main", kindBadArg},
		{"target must be two capture files: \"first.json,second.json\"", kindBadArg},
		{"decoder table decoders.json not found: ship decoders.json beside lrecon", kindNoEngine},
	}
	for _, c := range cases {
		if got := classify(c.msg); got != c.kind {
			t.Errorf("classify(%q) = %s, want %s", c.msg, got, c.kind)
		}
	}
}
