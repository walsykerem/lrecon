package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- op_decode_interface_builder.go ----------

// nibVInt is the little-endian 7-bit VInt32: the high bit is set on the LAST
// byte, not on continuation bytes. Exercise both the 1-byte and multi-byte
// forms plus each documented failure path.
func TestLane05NibVInt(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		want uint32
		next int
		err  string
	}{
		{"one byte", []byte{0x85}, 5, 1, ""}, // 5 | high bit terminates
		{"high bit terminates", []byte{0x80}, 0, 1, ""},
		{"two bytes", []byte{0x01, 0x81}, 129, 2, ""}, // 1 + (1<<7), high bit on last byte
		{"five bytes", []byte{0x7f, 0x7f, 0x7f, 0x7f, 0x8f}, 0xffffffff, 5, ""},
		{"past end", nil, 0, 0, "runs past the end"},
		{"too long", []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01}, 0, 5, "longer than 5 bytes"},
		{"overflow", []byte{0x7f, 0x7f, 0x7f, 0x7f, 0xff}, 0, 5, "does not fit in 32 bits"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, next, err := nibVInt(c.b, 0)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("nibVInt: got err=%v, want %q", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("nibVInt: %v", err)
			}
			if v != c.want || next != c.next {
				t.Fatalf("nibVInt = (%d,%d), want (%d,%d)", v, next, c.want, c.next)
			}
		})
	}
}

// writeVInt encodes a uint32 as a NIBArchive VInt32 (7 bits/byte, high bit on
// the last byte). Test-only helper; the production reader is nibVInt above.
func writeVInt(v uint32) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v == 0 {
			return append(out, b|0x80)
		}
		out = append(out, b)
	}
}

// buildNIB constructs a minimal but fully valid NIBArchive: two class names,
// one label-carrying string object, and one connector referencing it. It
// mirrors the on-disk layout nibParse reads so the parser is exercised end to
// end, not only its individual helpers.
func buildNIB(t *testing.T, className, label string, connectorIsOutlet bool) []byte {
	t.Helper()
	const hdr = nibHeaderSize
	put32 := func(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }

	keys := []string{"NSLabel"}
	var keyBlob []byte
	for _, k := range keys {
		keyBlob = append(keyBlob, writeVInt(uint32(len(k)))...)
		keyBlob = append(keyBlob, k...)
	}

	// values: [0] NSLabel reference -> object 1; [1] bytes label.
	var valBlob []byte
	valBlob = append(valBlob, writeVInt(0)...)
	valBlob = append(valBlob, nibValueReference)
	valBlob = append(valBlob, []byte{1, 0, 0, 0}...) // ref = object 1
	valBlob = append(valBlob, writeVInt(0)...)
	valBlob = append(valBlob, nibValueBytes)
	valBlob = append(valBlob, writeVInt(uint32(len(label)))...)
	valBlob = append(valBlob, label...)

	// objects: [0] connector (class 0), values 0..1; [1] label string (class 1).
	var objBlob []byte
	objBlob = append(objBlob, writeVInt(0)...) // obj0 class = connector
	objBlob = append(objBlob, writeVInt(0)...) // obj0 valueStart
	objBlob = append(objBlob, writeVInt(1)...) // obj0 valueCount = NSLabel ref only
	objBlob = append(objBlob, writeVInt(1)...) // obj1 class = NSString
	objBlob = append(objBlob, writeVInt(1)...) // obj1 valueStart = the bytes value
	objBlob = append(objBlob, writeVInt(1)...) // obj1 valueCount

	// class names (no fallbacks): connector class then NSString class.
	cn0, cn1 := className, "NSString"
	var classBlob []byte
	classBlob = append(classBlob, writeVInt(uint32(len(cn0)))...)
	classBlob = append(classBlob, writeVInt(0)...)
	classBlob = append(classBlob, cn0...)
	classBlob = append(classBlob, writeVInt(uint32(len(cn1)))...)
	classBlob = append(classBlob, writeVInt(0)...)
	classBlob = append(classBlob, cn1...)

	buf := make([]byte, hdr+len(objBlob)+len(keyBlob)+len(valBlob)+len(classBlob))
	copy(buf[:10], "NIBArchive")
	put32(buf, 10, 1) // version
	put32(buf, 14, 2) // coder version
	objOff := hdr
	keyOff := objOff + len(objBlob)
	valOff := keyOff + len(keyBlob)
	classOff := valOff + len(valBlob)
	put32(buf, 18, 2) // object count
	put32(buf, 22, uint32(objOff))
	put32(buf, 26, uint32(len(keys)))
	put32(buf, 30, uint32(keyOff))
	put32(buf, 34, 2) // value count
	put32(buf, 38, uint32(valOff))
	put32(buf, 42, 2) // class count
	put32(buf, 46, uint32(classOff))
	copy(buf[objOff:], objBlob)
	copy(buf[keyOff:], keyBlob)
	copy(buf[valOff:], valBlob)
	copy(buf[classOff:], classBlob)
	return buf
}

func TestLane05NibParseAndConnections(t *testing.T) {
	a, err := nibParse(buildNIB(t, "NSNibOutletConnector", "statusLabel", true))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.version != 1 || a.coder != 2 {
		t.Fatalf("version/coder = %d/%d, want 1/2", a.version, a.coder)
	}
	if len(a.objects) != 2 || len(a.keys) != 1 || len(a.values) != 2 || len(a.classes) != 2 {
		t.Fatalf("table sizes = %d/%d/%d/%d", len(a.objects), len(a.keys), len(a.values), len(a.classes))
	}
	outlets, actions := nibConnections(a)
	if len(outlets) != 1 || outlets[0] != "statusLabel" || len(actions) != 0 {
		t.Fatalf("outlet connectors: outlets=%v actions=%v", outlets, actions)
	}

	a, err = nibParse(buildNIB(t, "NSNibControlConnector", "save:", false))
	if err != nil {
		t.Fatalf("parse action: %v", err)
	}
	outlets, actions = nibConnections(a)
	if len(actions) != 1 || actions[0] != "save:" || len(outlets) != 0 {
		t.Fatalf("control connectors: outlets=%v actions=%v", outlets, actions)
	}
}

// nibLabel must reject non-printable labels, out-of-range references and
// objects with no values — the untrusted-file trust boundary.
func TestLane05NibLabelRejectsBadRefs(t *testing.T) {
	a := &nibArchive{
		keys:    []string{"NSLabel"},
		values:  []nibValue{{key: 0, typ: nibValueReference, ref: 9}},
		objects: []nibObject{{class: 0, valueStart: 0, valueCount: 1}},
		classes: []string{"NSNibOutletConnector"},
	}
	if _, ok := a.nibLabel(a.objects[0]); ok {
		t.Fatal("accepted a label reference to object 9 of 1")
	}
	// A label pointing at an object whose bytes are non-printable is rejected.
	a.values[0].ref = 1
	a.objects = append(a.objects, nibObject{class: 1, valueStart: 1, valueCount: 1})
	a.values = append(a.values, nibValue{key: 0, typ: nibValueBytes, data: []byte{0x01, 0x02}})
	if _, ok := a.nibLabel(a.objects[0]); ok {
		t.Fatal("accepted a non-printable label")
	}
}

func TestLane05NibParseRejectsGarbage(t *testing.T) {
	if _, err := nibParse([]byte("not a nib at all, short")); err == nil || !strings.Contains(err.Error(), "not a NIBArchive") {
		t.Fatalf("garbage: got %v, want not-a-NIBArchive", err)
	}
	b := buildNIB(t, "NSNibOutletConnector", "x", true)
	binary.LittleEndian.PutUint32(b[18:], 0) // zero objects
	if _, err := nibParse(b); err == nil || !strings.Contains(err.Error(), "zero objects") {
		t.Fatalf("zero objects: got %v", err)
	}
}

// ---------- op_decompile_jeb_item.go ----------

func TestLane05JebThreads(t *testing.T) {
	t.Run("default capped at 8", func(t *testing.T) {
		t.Setenv("LRECON_JADX_THREADS", "")
		if n := jebdJadxThreads(); n < 1 || n > 8 {
			t.Fatalf("jebdJadxThreads = %d, want 1..8", n)
		}
	})
	for _, c := range []struct {
		v    string
		want int
	}{{"4", 4}, {"64", 64}, {"0", min(8, 1)}, {"65", min(8, 1)}, {"-1", min(8, 1)}, {"abc", min(8, 1)}} {
		t.Run("override_"+c.v, func(t *testing.T) {
			t.Setenv("LRECON_JADX_THREADS", c.v)
			got := jebdJadxThreads()
			if c.v == "4" || c.v == "64" {
				if got != c.want {
					t.Fatalf("threads(%q)=%d, want %d", c.v, got, c.want)
				}
			} else if got < 1 || got > 8 {
				t.Fatalf("threads(%q)=%d, want default 1..8", c.v, got)
			}
		})
	}
}

func TestLane05JebEngineNote(t *testing.T) {
	if !strings.Contains(jebEngineNote(true), "JEB is installed") {
		t.Fatal("installed note does not say JEB is installed")
	}
	if !strings.Contains(jebEngineNote(false), "JEB is not installed") {
		t.Fatal("absent note does not say JEB is absent")
	}
}

func TestLane05JebJadxDiagnostic(t *testing.T) {
	text := "INFO - loading classes.dex\nERROR - Incorrect arguments: bad class\n  Failed to write class\njava.lang.RuntimeException: boom\n"
	got := jebdJadxDiagnostic(text)
	if !strings.Contains(got, "ERROR - Incorrect arguments: bad class") || !strings.Contains(got, "Failed to write class") {
		t.Fatalf("diagnostic = %q, want the first two error lines joined", got)
	}
	if strings.Contains(got, "INFO - loading") || strings.Contains(got, "RuntimeException") {
		t.Fatalf("diagnostic included a banner or third line: %q", got)
	}
	if jebdJadxDiagnostic("all good") != "" {
		t.Fatal("a clean log produced a diagnostic")
	}
	long := "ERROR - " + strings.Repeat("x", 400)
	if got := jebdJadxDiagnostic(long); !strings.HasSuffix(got, "...") || len(got) != 303 {
		t.Fatalf("long diagnostic len=%d tail=%q", len(got), got[len(got)-3:])
	}
}

func TestLane05JebJadxFailure(t *testing.T) {
	args := []string{"--single-class", "com.x.Y", "--single-class-output", "out.java", "app.apk"}
	cases := []struct {
		name, out, want string
	}{
		{"unsaveable", "ERROR - class DONT_GENERATE", "not a class jadx can save"},
		{"bad dex", "ERROR - File open error app.apk", "not a readable DEX/APK"},
		{"unknown class", "ERROR - Incorrect arguments: class not found", "unknown class"},
		{"plain diagnostic", "ERROR - some other cause", "failed: ERROR - some other cause"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := jebdJadxFailure("com.x.Y", args, c.out, fmt.Errorf("exit 1"))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("failure = %v, want %q", err, c.want)
			}
		})
	}
	// With no diagnostic at all the underlying error is preserved.
	base := fmt.Errorf("plain timeout")
	if err := jebdJadxFailure("com.x.Y", args, "", base); err != base {
		t.Fatalf("no diagnostic: got %v, want the original error", err)
	}
}

func TestLane05JebRedact(t *testing.T) {
	dir := "/tmp/lrecon-jadx-ABC123"
	err := fmt.Errorf("write failed in %s/class.java", dir)
	got := jebdRedact(err, dir).Error()
	if strings.Contains(got, dir) || !strings.Contains(got, "<tmpdir>") {
		t.Fatalf("redact = %q", got)
	}
}

// opDecompileJebItem's real behaviour is driven by a fake jadx on PATH: it
// writes class.java with the exact --single-class-output argument. Verify the
// whole op path — target parsing, args, source capture and the engine note.
func TestLane05DecompileJebItemWithFakeJadx(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
out=""
while [ $# -gt 0 ]; do
  if [ "$1" = "--single-class-output" ]; then out="$2"; shift; fi
  shift
done
printf '%s' 'class Y { void ok() {} }' > "$out"
`
	if err := os.WriteFile(filepath.Join(dir, "jadx"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("LRECON_JADX_THREADS", "2")
	t.Setenv("LRECON_APK_TIMEOUT", "10s")

	res, err := opDecompileJebItem("app.apk:com.x.Y")
	if err != nil {
		t.Fatalf("opDecompileJebItem: %v", err)
	}
	src, ok := res.(jebdSource)
	if !ok {
		t.Fatalf("result type %T, want jebdSource", res)
	}
	if !src.Found || src.Engine != "jadx" || src.Class != "com.x.Y" || src.Bytes != len("class Y { void ok() {} }") {
		t.Fatalf("source = %+v", src)
	}
	if src.Source != "class Y { void ok() {} }" || !strings.Contains(src.Note, "jadx --single-class") {
		t.Fatalf("source/note = %q / %q", src.Source, src.Note)
	}

	// A malformed target names the required shape instead of guessing.
	if _, err := opDecompileJebItem("no-colon"); err == nil || !strings.Contains(err.Error(), "want <apk>:<fqcn>") {
		t.Fatalf("bad target: got %v", err)
	}
}

// ---------- op_discover_webmcp_tools.go ----------

// evaluateValue must unwrap CDP's result.value and reject missing/failed steps
// instead of silently returning an empty object.
func TestLane05EvaluateValue(t *testing.T) {
	ok := webOut{Steps: []webStepResult{
		{Method: "Runtime.enable", Ok: true},
		{Method: "Runtime.evaluate", Ok: true,
			Result: map[string]any{"result": map[string]any{"value": map[string]any{"secure": true}}}},
	}}
	val, err := evaluateValue(ok, 1) // step 1 is Runtime.evaluate
	if err != nil {
		t.Fatalf("evaluateValue: %v", err)
	}
	if v, _ := val["secure"].(bool); !v {
		t.Fatalf("value = %v, want secure=true", val)
	}
	noValue := webOut{Steps: []webStepResult{
		{Method: "Runtime.enable", Ok: true},
		{Method: "Runtime.evaluate", Ok: true}, // no result.value
	}}
	if _, err := evaluateValue(noValue, 1); err == nil || !strings.Contains(err.Error(), "pass returnByValue") {
		t.Fatalf("step with no returnByValue object: got %v", err)
	}
	failed := webOut{Steps: []webStepResult{{Method: "Runtime.enable", Ok: true}, {Method: "Runtime.evaluate", Ok: false, Error: &webStepError{Code: 5, Message: "boom"}}}}
	if _, err := evaluateValue(failed, 1); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("failed step: got %v", err)
	}
	if _, err := evaluateValue(ok, 5); err == nil {
		t.Fatal("accepted an out-of-range step")
	}
}

// The mediated/native/polyfill labelling is the whole point of this op. Mock
// webTransport (the one seam) and assert every branch of the CDP answer.
func TestLane05DiscoverWebmcpTools(t *testing.T) {
	run := func(val map[string]any) webmcpDiscovery {
		prev := webTransport
		webTransport = func(context.Context, webSpec) (webOut, error) {
			return webOut{Steps: []webStepResult{
				{Method: "Runtime.enable", Ok: true},
				{Method: "Runtime.evaluate", Ok: true, Result: map[string]any{"result": map[string]any{"value": val}}},
			}}, nil
		}
		t.Cleanup(func() { webTransport = prev })
		res, err := opDiscoverWebmcpTools("9222")
		if err != nil {
			t.Fatalf("opDiscoverWebmcpTools: %v", err)
		}
		d, ok := res.(webmcpDiscovery)
		if !ok {
			t.Fatalf("result type %T", res)
		}
		return d
	}

	native := run(map[string]any{"secure": true, "native": true, "names": []any{"bookFlight", "findHotel"}})
	if !native.Secure || !native.Native || native.Source != "native" || native.Refused != "" {
		t.Fatalf("native = %+v", native)
	}
	if len(native.Tools) != 2 || native.Tools[0].Name != "bookFlight" || !native.Tools[0].Mediated || native.Tools[0].Source != "native" {
		t.Fatalf("native tools = %+v", native.Tools)
	}

	insecure := run(map[string]any{"secure": false})
	if !strings.EqualFold(insecure.Refused, "insecure-context") {
		t.Fatalf("insecure = %+v", insecure)
	}

	none := run(map[string]any{"secure": true, "native": false, "names": []any{}})
	if none.Native || none.Source != "none" || len(none.Tools) != 0 {
		t.Fatalf("no model context = %+v", none)
	}
}

// ---------- op_evaluate_reconstruction_coverage.go ----------

func TestLane05MetaLocalNames(t *testing.T) {
	for _, c := range []struct {
		v    string
		want int
	}{{"local:12", 12}, {"local:0", 0}, {"not_recovered", 0}, {"pclntab:9", 0}, {"local:-3", 0}, {"local:oops", 0}} {
		if got := metaLocalNames(c.v); got != c.want {
			t.Fatalf("metaLocalNames(%q)=%d, want %d", c.v, got, c.want)
		}
	}
}

// A job's explicit resolved/unresolved lists win over state and file. This is
// the core counting claim: 3 of 5 = 60%, reasons tallied, claim text exact.
func TestLane05CoverageFromJob(t *testing.T) {
	job := map[string]any{
		"resolved": []string{"a", "b", "c"},
		"unresolved": []metaObligation{
			{Symbol: "x", Reason: "opaque"},
			{Symbol: "y", Reason: "opaque"},
		},
	}
	res := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, job))
	cov, ok := res["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("coverage field missing: %#v", res)
	}
	if metaStr(t, cov, "source") != "job" || metaNum(t, cov, "resolved") != 3 || metaNum(t, cov, "unresolved") != 2 || metaNum(t, cov, "total") != 5 {
		t.Fatalf("coverage = %#v", cov)
	}
	if p, _ := cov["percent"].(float64); p != 60 {
		t.Fatalf("percent = %v, want 60", cov["percent"])
	}
	reasons, _ := res["reasons"].([]any)
	if len(reasons) != 1 || reasons[0] != "opaque" {
		t.Fatalf("reasons = %v", reasons)
	}
	if claim := metaStr(t, cov, "claim"); !strings.Contains(claim, "3 of 5 symbols resolved (60.0%)") || !strings.Contains(claim, "source: job") {
		t.Fatalf("claim = %q", claim)
	}
}

// With no job lists, a saved state ledger supplies the counts. Resolved
// unknowns (+resolution) are the resolved side; open unknowns and ledger rows
// are unresolved. The claim must name source:ledger and tally by reason.
func TestLane05CoverageFromState(t *testing.T) {
	state := metaTestState(t)
	if err := os.WriteFile(filepath.Join(state, "unknowns.json"), []byte(`{
  "kind":"lrecon.unknowns/1",
  "unknowns":[
    {"address":"0x10","hypothesis":"code","resolved":true,"resolution":"printf thunk"},
    {"address":"0x20","hypothesis":"data","resolved":false},
    {"address":"0x30","hypothesis":"padding","resolved":true,"resolution":"  "}
  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "obligations.json"), []byte(`{
  "kind":"lrecon.obligations/1","artifact":"","sha256":"","rows":[
    {"symbol":"extA","reason":"external"},
    {"symbol":"extB","reason":""}
  ]}`), 0o644); err != nil {
		t.Fatal(err)
	}

	res := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{"state": state}))
	cov, _ := res["coverage"].(map[string]any)
	if metaStr(t, cov, "source") != "ledger" || metaNum(t, cov, "resolved") != 1 || metaNum(t, cov, "unresolved") != 4 || metaNum(t, cov, "total") != 5 {
		t.Fatalf("coverage = %#v", cov)
	}
	byReason, _ := cov["by_reason"].(map[string]any)
	if byReason["unresolved-unknown"] != float64(2) || byReason["external"] != float64(1) || byReason["unstated"] != float64(1) {
		t.Fatalf("by_reason = %#v", byReason)
	}
}

// A bare artifact with neither lists nor ledger falls back to its own digest:
// exports + recovered local names are resolved, skipped readers unresolved.
func TestLane05CoverageFromFile(t *testing.T) {
	state := metaTestState(t) // empty state dir: no ledger
	digest := map[string]any{
		"contract_version": contractVersion,
		"kind":             "elf",
		"exports":          7,
		"names":            "local:5",
		"skipped": []map[string]string{
			{"reason": "reader-skip", "detail": "unsupported section"},
		},
	}
	b, _ := json.Marshal(digest)
	artifact := writeTemp(t, "digest.json", b)

	res := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{"file": artifact, "state": state}))
	cov, _ := res["coverage"].(map[string]any)
	if metaStr(t, cov, "source") != "file" || metaNum(t, cov, "resolved") != 12 || metaNum(t, cov, "unresolved") != 1 || metaNum(t, cov, "total") != 13 {
		t.Fatalf("coverage = %#v", cov)
	}
	basis, _ := cov["basis"].(map[string]any)
	if basis["exports"] != float64(7) || basis["local_names"] != float64(5) || basis["skipped_readers"] != float64(1) {
		t.Fatalf("basis = %#v", basis)
	}
	if note := metaStr(t, cov, "note"); !strings.Contains(note, "file mode") {
		t.Fatalf("note = %q", note)
	}
}

// A ledger naming a different artifact must be set aside, not used to claim
// coverage of bytes it never read. Verify the SHA guard on the fallback path.
func TestLane05CoverageIgnoresForeignLedger(t *testing.T) {
	state := metaTestState(t)
	artifact := writeTemp(t, "victim.bin", []byte("the bytes actually measured"))
	sum, _, err := metaObjectSHA(artifact)
	if err != nil {
		t.Fatal(err)
	}
	// Ledger names a different sha256 than the artifact under test.
	if err := os.WriteFile(filepath.Join(state, "obligations.json"), []byte(fmt.Sprintf(
		`{"kind":"lrecon.obligations/1","artifact":"other.bin","sha256":"%s","rows":[{"symbol":"ghost","reason":"foreign"}]}`,
		strings.Repeat("0", 64))), 0o644); err != nil {
		t.Fatal(err)
	}
	// Provide a digest fallback so the op measures something after ignoring
	// the ledger; the ghost row must not appear and the note must say why.
	digest := map[string]any{"contract_version": contractVersion, "kind": "elf", "exports": 4, "names": "local:1", "skipped": []any{}}
	b, _ := json.Marshal(digest)
	df := writeTemp(t, "digest.json", b)

	res := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{"file": df, "state": state}))
	cov, _ := res["coverage"].(map[string]any)
	if metaStr(t, cov, "source") != "file" || metaNum(t, cov, "resolved") != 5 || metaNum(t, cov, "unresolved") != 0 {
		t.Fatalf("coverage = %#v", cov)
	}
	if note := metaStr(t, cov, "note"); !strings.Contains(note, "ignored the ledger") {
		t.Fatalf("note does not explain the ignored ledger: %q", note)
	}
	if sum == strings.Repeat("0", 64) {
		t.Fatal("test setup: digest collision with the foreign sha")
	}
}

func TestLane05CoverageRejectsEmpty(t *testing.T) {
	state := metaTestState(t)
	_, err := runOp("evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{"state": state}))
	if err == nil || !strings.Contains(err.Error(), "no \"resolved\" or \"unresolved\"") {
		t.Fatalf("empty job: got %v", err)
	}
}
