package main

// Tur5/Go28: real simulation tests for the assigned .go files. Each case drives
// the real op body (or its helper) with a synthetic-but-valid target and checks
// the exact observable claim: header fields, refusal kind, stage or error text.

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func tur5DartSnap(kind uint64, hash string, declaredDelta int64) []byte {
	b := make([]byte, 20+32)
	binary.LittleEndian.PutUint32(b, dartMagic)
	binary.LittleEndian.PutUint64(b[4:], uint64(int64(len(b)-4)+declaredDelta))
	binary.LittleEndian.PutUint64(b[12:], kind)
	copy(b[20:], hash)
	return b
}

// op_inspect_dart_aot.go: the header's own claims drive kind, app_jit and the
// declared-vs-actual check; a missing version hash is a skip, not a guess.
func TestTur5Go28DartHeaderClaims(t *testing.T) {
	hash := "0123456789abcdef0123456789abcdef"
	o := ops["inspect_dart_aot"]
	if o.route != "L" || !o.needs {
		t.Fatalf("registry = %+v", o)
	}

	// full-jit (kind 1) must set app_jit and report the exact numbers it read.
	p := writeTemp(t, "snapshot.jit", tur5DartSnap(1, hash, 0))
	v, err := o.run(p)
	if err != nil {
		t.Fatalf("full-jit snapshot: %v", err)
	}
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m["kind"] != "full-jit" || m["app_jit"] != true || m["length_consistent"] != true {
		t.Fatalf("full-jit claims = %s", b)
	}
	if m["version_hash"] != hash || m["actual_bytes"] != float64(52) || m["declared_bytes"] != float64(52) {
		t.Fatalf("full-jit numbers = %s", b)
	}

	// A header that declares more bytes than the file holds is refused.
	p = writeTemp(t, "snapshot.short", tur5DartSnap(2, hash, 8))
	if _, err := o.run(p); err == nil || !strings.Contains(err.Error(), "is not the size its header declares") {
		t.Fatalf("declared > actual: want size error, got %v", err)
	}

	// An unmapped kind is a caller error, not a fallback to "full".
	p = writeTemp(t, "snapshot.kind", tur5DartSnap(99, hash, 0))
	if _, err := o.run(p); err == nil || !strings.Contains(err.Error(), "unknown Dart snapshot kind 99") {
		t.Fatalf("kind 99: want unknown-kind error, got %v", err)
	}

	// No readable 32-char hex hash: the op skips instead of inventing one.
	p = writeTemp(t, "snapshot.nohash", tur5DartSnap(0, strings.Repeat("\x00", 32), 0))
	res, err := o.run(p)
	if err != nil {
		t.Fatalf("no-hash snapshot: %v", err)
	}
	sk, ok := res.(*skip)
	if !ok || !strings.Contains(sk.Reason, "carries no readable Dart version hash") {
		t.Fatalf("no-hash snapshot = %+v, want skip", res)
	}
}

// op_asar_budget.go: the budget parser and the stage named on a fired deadline.
func TestTur5Go28DeadlineBudgetAndStage(t *testing.T) {
	t.Setenv(opDeadlineEnv, "250ms")
	if got := opDeadline(); got != 250*time.Millisecond {
		t.Fatalf("opDeadline = %v, want 250ms", got)
	}
	t.Setenv(opDeadlineEnv, "not-a-duration")
	if got := opDeadline(); got != opDeadlineDefault {
		t.Fatalf("invalid env = %v, want default %v", got, got)
	}

	// A real asar header has first uint32 == 4 and a JSON header at byte 16.
	var h [20]byte
	binary.LittleEndian.PutUint32(h[0:], 4)
	binary.LittleEndian.PutUint32(h[12:], 20)
	h[16] = '{'
	asar := writeTemp(t, "app.asar", h[:])
	if targetStage(asar) != "asar" {
		t.Fatal("synthetic asar header not recognised as asar")
	}

	t.Setenv(opDeadlineEnv, "0s")
	ran := false
	_, err := runOpDeadline(asar, func() (any, error) { ran = true; return nil, nil })
	if ran || !isOpTimeout(err) {
		t.Fatalf("spent budget: ran=%v err=%v", ran, err)
	}
	if got := takeRefuseStage(); got != "asar" {
		t.Fatalf("refuse stage = %q, want asar", got)
	}
}

// op_list_adb_directory.go: an ls with only a total line owes an error, not an
// empty table that a caller could mistake for a directory with no entries.
func TestTur5Go28ListADBDirectoryNoRows(t *testing.T) {
	rtFakeTool(t, "adb", `if [ "$3" = "shell" ]; then printf 'total 0\n'; exit 0; fi
`+rtOneDevice)
	_, err := runOp("list_adb_directory", "/sdcard")
	if err == nil || !strings.Contains(err.Error(), "produced no long-format rows") {
		t.Fatalf("ls with no rows: want error, got %v", err)
	}
}

// op_ext_apktool.go: inventory items that name no file refuse a target instead
// of dropping it silently; needs-items refuse an absent target before any tool.
func TestTur5Go28ApktoolTargetRules(t *testing.T) {
	for _, name := range []string{"apktool_clean_frameworks", "apktool_list_frameworks"} {
		o, ok := extOps[name]
		if !ok || o.needs {
			t.Fatalf("%s: ext registry = %+v (ok=%v)", name, o, ok)
		}
	}
	for _, tc := range []struct {
		name string
		run  func(string, []string) (any, error)
	}{
		{"apktool_clean_frameworks", apktoolCleanFrameworks},
		{"apktool_list_frameworks", apktoolListFrameworks},
	} {
		_, err := tc.run("/tmp/should-not-be-used", nil)
		r, ok := err.(*extRefusal)
		if !ok || r.kind != kindBadArg || !strings.Contains(err.Error(), "takes no target") {
			t.Fatalf("%s with target: %v (%T), want kindBadArg", tc.name, err, err)
		}
	}
	_, err := runExtOp("apktool_build", "", nil)
	if err == nil || !strings.Contains(err.Error(), `op "apktool_build" needs a target path`) {
		t.Fatalf("needs op without target: %v", err)
	}
}

// op_procedure_callers.go: the G item takes its function reference from the
// environment; no reference must fail before any Ghidra work starts.
func TestTur5Go28ProcedureCallersRef(t *testing.T) {
	o := ops["procedure_callers"]
	if o.route != "G" || !o.needs {
		t.Fatalf("registry = %+v", o)
	}
	t.Setenv("LRECON_AT", "0x100000798")
	t.Setenv("LRECON_NAME", "")
	if got, err := nativeRef(); err != nil || got != "0x100000798" {
		t.Fatalf("LRECON_AT ref = %q, %v", got, err)
	}
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "main")
	if got, err := nativeRef(); err != nil || got != "main" {
		t.Fatalf("LRECON_NAME ref = %q, %v", got, err)
	}
	t.Setenv("LRECON_NAME", "")
	if _, err := nativeRef(); err == nil {
		t.Fatal("no ref set: want an error, not an empty reference")
	}
}
