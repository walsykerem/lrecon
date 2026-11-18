package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sessionCLIEnvelope is the one object the CLI prints under --json, success or
// refusal, so these tests read the same keys a caller does.
type sessionCLIEnvelope struct {
	Op     string         `json:"op"`
	Error  string         `json:"error"`
	Kind   string         `json:"kind"`
	Target string         `json:"target"`
	Result map[string]any `json:"result"`
}

func sessionCLI(t *testing.T, args ...string) (sessionCLIEnvelope, int) {
	t.Helper()
	stdout, stderr, code := runCLIAll(t, args...)
	var env sessionCLIEnvelope
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("%v: stdout is not one JSON envelope: %v\nstdout:\n%s\nstderr:\n%s", args, err, stdout, stderr)
	}
	return env, code
}

func sessionFileBytes(t *testing.T, path string) ([]byte, bool) {
	t.Helper()
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b, true
}

// TestBinarySessionAdapter pins the difference the session flag used to hide:
// a written session is not an opened target. /bin/true is a real Mach-O or ELF;
// a missing path must say the open failed in machine-readable form instead of
// leaving the caller to assume it worked.
func TestBinarySessionAdapter(t *testing.T) {
	metaTestState(t)
	var raw []byte
	for _, candidate := range []string{"/bin/true", "/usr/bin/true"} {
		if b, err := os.ReadFile(candidate); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		t.Skip("/bin/true and /usr/bin/true unavailable")
	}
	target := writeTemp(t, "true.bin", raw)

	ok := metaMustRun(t, "binary_session", target)
	if !metaBool(t, ok, "adapter_ok") {
		t.Fatalf("real target: adapter_ok = false, reason = %v", ok["adapter_reason"])
	}
	if name := metaStr(t, ok, "adapter"); name == "" || name == "unknown" {
		t.Fatalf("real target: adapter = %q, want a named reader", name)
	}
	if metaStr(t, ok, "document") != target || metaStr(t, ok, "opened") == "" {
		t.Fatalf("real target: document/opened lost: %v", ok)
	}

	missing := filepath.Join(t.TempDir(), "no-such-binary")
	bad := metaMustRun(t, "binary_session", missing)
	if metaBool(t, bad, "adapter_ok") {
		t.Fatalf("missing target: adapter_ok = true, want false")
	}
	if metaStr(t, bad, "adapter") != "unknown" || metaStr(t, bad, "adapter_reason") == "" {
		t.Fatalf("missing target: adapter/reason = %v/%v, want unknown plus a reason", bad["adapter"], bad["adapter_reason"])
	}
	if metaStr(t, bad, "document") != missing || metaStr(t, bad, "opened") == "" {
		t.Fatalf("missing target: document/opened lost: %v", bad)
	}
}

// sessionTempHome ISOLATES the CLI from the developer's ~/.lrecon. The state
// directory is the only session root these tests may touch, and the real
// session.json is snapshotted so a regression that leaks into HOME fails here
// instead of quietly deleting a user's session (report B11).
func sessionTempHome(t *testing.T) (realSession string, before []byte, existed bool) {
	t.Helper()
	realHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("real home: %v", err)
	}
	realSession = filepath.Join(realHome, ".lrecon", "session.json")
	before, existed = sessionFileBytes(t, realSession)

	t.Setenv("HOME", t.TempDir())
	t.Setenv("LRECON_STATE", t.TempDir())
	return realSession, before, existed
}

func sessionRealStateUnchanged(t *testing.T, path string, before []byte, existed bool) {
	t.Helper()
	after, stillThere := sessionFileBytes(t, path)
	if stillThere != existed || !bytes.Equal(after, before) {
		t.Fatalf("real %s changed during the test (before %d B, existed=%v; after %d B, existed=%v)",
			path, len(before), existed, len(after), stillThere)
	}
}

// TestBinarySessionForeignFileUntouched: an older session.json has no "kind"
// field. binary_session must not overwrite it, and close_binary must report
// the session closed without deleting or rewriting bytes it does not own.
func TestBinarySessionForeignFileUntouched(t *testing.T) {
	realSession, before, existed := sessionTempHome(t)
	state, _ := os.LookupEnv("LRECON_STATE")
	file := filepath.Join(state, "session.json")
	legacy := []byte("{\n  \"project\": \"bin\",\n  \"document\": \"/usr/bin/true\",\n  \"cursor\": 4294967296,\n  \"procedure\": \"__mh_execute_header\"\n}\n")
	if err := os.WriteFile(file, legacy, 0o644); err != nil {
		t.Fatal(err)
	}

	opened, code := sessionCLI(t, "--op", "binary_session", "--json", "/bin/ls")
	if code != 0 {
		t.Fatalf("binary_session exited %d: %+v", code, opened)
	}
	if opened.Result["session_persisted"] != false {
		t.Fatalf("binary_session rewrote a foreign session.json: %+v", opened.Result)
	}
	if opened.Result["session_note"] == nil || opened.Result["document"] != "/bin/ls" {
		t.Fatalf("binary_session lost document/note: %+v", opened.Result)
	}
	if got, _ := sessionFileBytes(t, file); !bytes.Equal(got, legacy) {
		t.Fatalf("binary_session changed the foreign bytes:\n%s", got)
	}

	closed, code := sessionCLI(t, "--op", "close_binary", "--json", "/bin/ls")
	if code != 0 {
		t.Fatalf("close_binary exited %d: %+v", code, closed)
	}
	if closed.Result["closed"] != true || closed.Result["target"] != "/usr/bin/true" {
		t.Fatalf("close_binary did not confirm the legacy session: %+v", closed.Result)
	}
	if closed.Result["session_removed"] != false || closed.Result["removed"] != "" {
		t.Fatalf("close_binary claimed to remove a foreign file: %+v", closed.Result)
	}
	if got, ok := sessionFileBytes(t, file); !ok || !bytes.Equal(got, legacy) {
		t.Fatalf("close_binary deleted or rewrote the foreign session.json (exists=%v):\n%s", ok, got)
	}
	sessionRealStateUnchanged(t, realSession, before, existed)
}

// TestCloseBinaryOwnSession: a session this path wrote is closed with the
// document echoed back (report B11's {closed:true,target:...}) and removed.
func TestCloseBinaryOwnSession(t *testing.T) {
	realSession, before, existed := sessionTempHome(t)
	state, _ := os.LookupEnv("LRECON_STATE")

	opened, code := sessionCLI(t, "--op", "binary_session", "--json", "/bin/ls")
	if code != 0 || opened.Result["session_persisted"] != true {
		t.Fatalf("binary_session did not persist: exit %d %+v", code, opened.Result)
	}
	file := filepath.Join(state, "session.json")
	disk, ok := sessionFileBytes(t, file)
	if !ok {
		t.Fatalf("binary_session did not write %s", file)
	}
	var doc map[string]any
	if err := json.Unmarshal(disk, &doc); err != nil || doc["kind"] != "lrecon.session/1" {
		t.Fatalf("session.json is not lrecon.session/1: %v %s", err, disk)
	}

	closed, code := sessionCLI(t, "--op", "close_binary", "--json", "/bin/ls")
	if code != 0 {
		t.Fatalf("close_binary exited %d: %+v", code, closed)
	}
	if closed.Result["closed"] != true || closed.Result["target"] != "/bin/ls" {
		t.Fatalf("close_binary result = %+v, want closed:true target:/bin/ls", closed.Result)
	}
	if closed.Result["session_removed"] != true {
		t.Fatalf("close_binary did not report removing its own session: %+v", closed.Result)
	}
	if _, exists := sessionFileBytes(t, file); exists {
		t.Fatalf("close_binary left its own session.json behind")
	}
	sessionRealStateUnchanged(t, realSession, before, existed)
}

// TestCloseBinaryDifferentArtifactRefused: a JSON state file with another kind
// is not a session. It stays a conflict, and its bytes survive the refusal.
func TestCloseBinaryDifferentArtifactRefused(t *testing.T) {
	realSession, before, existed := sessionTempHome(t)
	state, _ := os.LookupEnv("LRECON_STATE")
	file := filepath.Join(state, "session.json")
	other := []byte(`{"kind":"other.tool/9","document":"/x"}`)
	if err := os.WriteFile(file, other, 0o644); err != nil {
		t.Fatal(err)
	}

	closed, code := sessionCLI(t, "--op", "close_binary", "--json", "/bin/ls")
	if code != 2 {
		t.Fatalf("close_binary exited %d, want 2 for a foreign artifact: %+v", code, closed)
	}
	if !strings.Contains(closed.Error, "state conflict") || closed.Kind == "" {
		t.Fatalf("close_binary refusal = %+v, want a state conflict with a kind", closed)
	}
	if got, ok := sessionFileBytes(t, file); !ok || !bytes.Equal(got, other) {
		t.Fatalf("close_binary touched another artifact (exists=%v):\n%s", ok, got)
	}
	sessionRealStateUnchanged(t, realSession, before, existed)
}
