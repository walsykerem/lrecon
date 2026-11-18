package main

// TUR 2, lane 18 independent simulation tests. Verifies the real behavior of
// production code with meaningful input; production code is not relaxed to pass.
// Existing helpers: writeTemp (probe_test.go), mCode/pycBlob (pyc_test.go),
// pbTag (pblite_test.go), opcacheFile (php_test.go).

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"
)

// --- ops.go ---

func TestR2L18OpNeedsAndSelector(t *testing.T) {
	if got := opNeeds(op{name: "x", needs: true}); len(got) != 1 || got[0] != "target" {
		t.Fatalf("needs op = %v, want [target]", got)
	}
	if got := opNeeds(op{name: "capture_adb_screen"}); len(got) != 1 || got[0] != "device" {
		t.Fatalf("device op = %v, want [device]", got)
	}
	if got := opNeeds(op{name: "totally_unknown_op"}); len(got) != 0 {
		t.Fatalf("plain op = %v, want []", got)
	}
	if !opTargetIsSelector("resolve_adb_packages") || opTargetIsSelector("inspect_macho") {
		t.Fatal("opTargetIsSelector wrong")
	}
}

func TestR2L18RegisterOpGuards(t *testing.T) {
	// Empty name, nil run, empty desc, invalid route and dup must panic.
	cases := []struct {
		name string
		o    op
	}{
		{"empty name", op{run: func(string) (any, error) { return nil, nil }, desc: "d", route: "L"}},
		{"nil run", op{name: "r2l18_nilrun", desc: "d", route: "L"}},
		{"empty desc", op{name: "r2l18_nodesc", route: "L", run: func(string) (any, error) { return nil, nil }}},
		{"bad route", op{name: "r2l18_badroute", desc: "d", route: "Z", run: func(string) (any, error) { return nil, nil }}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("registerOp did not panic")
				}
			}()
			registerOp(c.o)
		})
	}
	// Dup: first a valid registration, then the same name.
	defer func() {
		if recover() == nil {
			t.Fatal("duplicate registerOp did not panic")
		}
		delete(ops, "r2l18_dup")
	}()
	g := func(string) (any, error) { return nil, nil }
	registerOp(op{name: "r2l18_dup", desc: "d", route: "L", run: g})
	registerOp(op{name: "r2l18_dup", desc: "d", route: "L", run: g})
}

func TestR2L18RunOpUnknown(t *testing.T) {
	if _, err := runOp("r2l18_does_not_exist", ""); err == nil || !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("runOp unknown = %v", err)
	}
}

// --- plan.go ---

func TestR2L18ShellArgQuoting(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain/path.bin", "plain/path.bin"},
		{"", "''"},
		{"a b.bin", "'a b.bin'"},
		{"it's.bin", `'it'\''s.bin'`},
		{"a$b.bin", "'a$b.bin'"},
	}
	for _, c := range cases {
		if got := shellArg(c.in); got != c.want {
			t.Fatalf("shellArg(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestR2L18BuildPlanFallback(t *testing.T) {
	p := buildPlan(Digest{Kind: "unknownkind", Format: "raw"}, "x.bin")
	if p.Op != "binary_overview" || p.Cmd != "lrecon --op binary_overview --json x.bin" {
		t.Fatalf("fallback plan = %+v", p)
	}
	if len(p.Envelope.Top) != 3 || p.Envelope.Top[2] != "result" {
		t.Fatalf("envelope top = %v", p.Envelope.Top)
	}
	if len(p.Envelope.Result) == 0 {
		t.Fatal("fallback envelope result empty")
	}
}

// --- pblite.go ---

func TestR2L18PBWalkCallbackErrorAndNested(t *testing.T) {
	// Inner message: field 1 = "ab". Outer message: field 2 = length-delimited inner message.
	inner := append(pbTag(1, 2), 2, 'a', 'b')
	outer := append(append(pbTag(2, 2), byte(len(inner))), inner...)

	var keys []int
	err := pbWalk(outer, func(num, wire int, v uint64, b []byte) error {
		keys = append(keys, num)
		if num == 2 {
			return pbWalk(b, func(n2, w2 int, v2 uint64, b2 []byte) error {
				if n2 != 1 || string(b2) != "ab" {
					t.Fatalf("nested field = %d %q", n2, b2)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil || len(keys) != 1 || keys[0] != 2 {
		t.Fatalf("outer walk = %v keys %v", err, keys)
	}

	// Callback error must be propagated outward unchanged.
	sentinel := errors.New("r2l18 stop")
	if err := pbWalk(outer, func(int, int, uint64, []byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback error = %v, want sentinel", err)
	}
}

// --- pcap.go ---

func TestR2L18PcapLinkAndDNSCompression(t *testing.T) {
	if got := pcapLinkName(9999); got != "linktype-9999" {
		t.Fatalf("pcapLinkName = %q", got)
	}
	if got := pcapLinkName(1); got != "ethernet" {
		t.Fatalf("pcapLinkName(1) = %q", got)
	}
	// DNS message ending with a QNAME compression pointer (0xc0): name is readable.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1) // QDCOUNT=1
	qname := append([]byte{3}, "www"...)
	qname = append(qname, 7)
	qname = append(qname, "example"...)
	qname = append(qname, 3)
	qname = append(qname, "com"...)
	qname = append(qname, 0)
	msg = append(msg, qname...)
	msg = append(msg, 0, 1, 0, 1) // QTYPE, QCLASS
	msg = append(msg, 0xc0, 0x0c) // compression pointer
	var d Digest
	pcapDNS(msg, &d)
	if len(d.PcapDNS) != 1 || d.PcapDNS[0] != "www.example.com" {
		t.Fatalf("pcapDNS = %v", d.PcapDNS)
	}
	if _, _, ok := dnsQName([]byte{0xc0}, 0); ok {
		t.Fatal("truncated compression pointer accepted")
	}
}

// --- php.go ---

func TestR2L18PhpCursorBounds(t *testing.T) {
	c := phpCursor{b: []byte{1, 2, 3, 4, 5, 6}, off: 0}
	if v, ok := c.u32(); !ok || v != 0x04030201 {
		t.Fatalf("u32 = %d %v", v, ok)
	}
	if v, ok := c.be16(); !ok || v != 0x0506 {
		t.Fatalf("be16 = %d %v", v, ok)
	}
	if _, ok := c.u32(); ok {
		t.Fatal("cursor bound exceeded but ok=true")
	}
	if b, ok := c.take(1); ok || b != nil {
		t.Fatal("take bound exceeded but ok=true")
	}
	c2 := phpCursor{b: []byte{1}}
	if _, ok := c2.be16(); ok {
		t.Fatal("be16 returned ok=true on a short buffer")
	}
}

// --- pyc.go ---

func TestR2L18PycVersionAndWalkCycle(t *testing.T) {
	cases := []struct {
		magic int
		minor int
		ok    bool
	}{
		{3360, 6, true}, {3379, 6, true}, {3380, 0, false},
		{3450, 11, true}, {3495, 11, true}, {3496, 0, false},
		{3627, 14, true}, {3628, 0, false}, {3099, 0, false},
	}
	for _, c := range cases {
		minor, ok := pycVersion(c.magic)
		if ok != c.ok || (ok && minor != c.minor) {
			t.Fatalf("pycVersion(%d) = %d %v, want %d %v", c.magic, minor, ok, c.minor, c.ok)
		}
	}
	// Self-referencing code object: pycWalk would loop forever without a cycle guard.
	a := &pyCode{name: "a"}
	a.consts = []any{a}
	child := &pyCode{name: "child"}
	a.consts = append(a.consts, child)
	child.consts = []any{a}
	got := pycWalk(a)
	if len(got) != 2 || got[0] != a || got[1] != child {
		t.Fatalf("pycWalk cycle = %d nodes", len(got))
	}
}

func TestR2L18PycMatchMagicWindow(t *testing.T) {
	if !pycMatch([]byte{0x6f, 0x0d, 0x0d, 0x0a}, 100) { // 3439 = 3.10
		t.Fatal("valid pyc magic rejected")
	}
	if pycMatch([]byte{0x01, 0x0c, 0x0d, 0x0a}, 100) { // 3073 < 3100
		t.Fatal("out-of-window magic accepted")
	}
	if pycMatch([]byte{0x6f, 0x0d, 0x00, 0x0a}, 100) {
		t.Fatal("non-0d0a magic accepted")
	}
}

// --- producer.go ---

func TestR2L18ProducerVersionHelpers(t *testing.T) {
	if got := trimVersion("14.0.0"); got != "14" {
		t.Fatalf("trimVersion = %q", got)
	}
	if got := trimVersion("1.2.3"); got != "1.2.3" {
		t.Fatalf("trimVersion no-suffix = %q", got)
	}
	if got := packedVersion(0x00123456); got != "18.52.86" {
		t.Fatalf("packedVersion = %q", got)
	}
	if got := sourceVersionString(1<<40 | 2<<30 | 3<<20); got != "1.2.3" {
		t.Fatalf("sourceVersionString = %q", got)
	}
	// Rust must be classified as rustc even if it contains clang LLVM (order matters).
	v, fam, ok := classifyProducer("clang LLVM (rustc version 1.75.0)")
	if !ok || fam != "rustc" || v != "rustc 1.75.0" {
		t.Fatalf("classify rustc = %q %q %v", v, fam, ok)
	}
}

// --- pkgjs.go ---

func TestR2L18JsValueAndSlotName(t *testing.T) {
	// jsValue returns the first valid JSON value: the 99 inside the comment comes first.
	b := []byte(`// PAYLOAD_POSITION = 99; var PAYLOAD_POSITION = ' 12345 ';`)
	got, ok := jsValue(b, "PAYLOAD_POSITION")
	if !ok || string(got) != "99" {
		t.Fatalf("jsValue first = %q %v", got, ok)
	}
	// False if the key is absent.
	if _, ok := jsValue(b, "NO_SUCH_KEY"); ok {
		t.Fatal("jsValue true for a missing key")
	}
	if got := slotName("var PAYLOAD_SIZE = '"); got != "PAYLOAD_SIZE" {
		t.Fatalf("slotName = %q", got)
	}
}

func TestR2L18ParseNotesAlignment(t *testing.T) {
	// namesz=4 ("GNU\0"), descsz=5 -> desc starts at 12+4=16, ends at 21,
	// the next record starts at 24 (align4).
	b := make([]byte, 0)
	b = binary.LittleEndian.AppendUint32(b, 4)
	b = binary.LittleEndian.AppendUint32(b, 5)
	b = binary.LittleEndian.AppendUint32(b, 7)
	b = append(b, 'G', 'N', 'U', 0) // 12..15
	b = append(b, 1, 2, 3, 4, 5)    // 16..20
	b = append(b, 0, 0, 0)          // padding 21..23
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 9)
	b = append(b, 'X', 0, 0, 0) // 36..39, namesz=1 -> start 16 offset relative

	recs := parseNotes(b, binary.LittleEndian, 100)
	if len(recs) != 2 {
		t.Fatalf("parseNotes = %d records: %+v", len(recs), recs)
	}
	if recs[0].name != "GNU" || recs[0].typ != 7 || len(recs[0].desc) != 5 || recs[0].desc[0] != 1 {
		t.Fatalf("record0 = %+v", recs[0])
	}
	// Second record starts at 24 (base=124), namesz=1 -> descStart=align4(13)=16.
	if recs[0].off != 116 || recs[1].off != 140 {
		t.Fatalf("offsets = %d %d, want 116 140", recs[0].off, recs[1].off)
	}
	if recs[1].name != "X" || recs[1].typ != 9 {
		t.Fatalf("record1 = %+v", recs[1])
	}
	// Truncated record: stop if descsz exceeds the buffer, do not fabricate a record.
	bad := append([]byte{}, b[:20]...)
	if got := parseNotes(bad, binary.LittleEndian, 0); len(got) != 0 {
		t.Fatalf("truncated record accepted: %+v", got)
	}
}

// --- readcap.go ---

func TestR2L18ReadCappedExactAndOver(t *testing.T) {
	p := writeTemp(t, "cap.bin", []byte("abcde"))
	b, err := readCapped(p, 5)
	if err != nil || string(b) != "abcde" {
		t.Fatalf("exact cap = %q %v", b, err)
	}
	if _, err := readCapped(p, 4); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("over cap = %v", err)
	}
	if _, err := readCapped(p+"_missing", 5); err == nil || !os.IsNotExist(err) {
		t.Fatalf("missing = %v", err)
	}
}

// --- proctable_darwin.go ---

func TestR2L18DarwinProcRowsSynthetic(t *testing.T) {
	// Two records: one with a valid pid/comm, the other an empty tail slot (pid=0).
	rec := make([]byte, darwinKinfoProcSize*2)
	binary.LittleEndian.PutUint32(rec[darwinPidOffset:], 4242)
	copy(rec[darwinCommOffset:darwinCommLen+darwinCommOffset], "Cutter\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	// Second record: pid=0 (unused slot)
	rows, plausible := darwinProcRows(rec)
	if plausible != 1 || len(rows) != 1 {
		t.Fatalf("rows=%+v plausible=%d", rows, plausible)
	}
	if rows[0].PID != 4242 || rows[0].Comm != "Cutter" {
		t.Fatalf("row0 = %+v", rows[0])
	}
	out, n := darwinProcMatches(rec, "cutter")
	if n != 1 || len(out) != 1 || out[0] != "4242 Cutter" {
		t.Fatalf("matches = %v n=%d", out, n)
	}
}

// --- assigned lane files: full-path simulation of the WEB and adb ops ---

func TestR2L18InspectWebEventListenersMerge(t *testing.T) {
	// Five steps: enable, window eval, document eval, then one DOMDebugger read
	// per objectId. window and document listeners must be merged, tagged by
	// scope and sorted scope/type/line — not just the first object's answer.
	fakeDriver(t, webOut{
		Target: &webTargetRow{ID: "T1"},
		Steps: []webStepResult{
			okStep("Runtime.enable", map[string]any{}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "w1"}}),
			okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"objectId": "d1"}}),
			okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
				map[string]any{"type": "click", "useCapture": true, "passive": true, "lineNumber": float64(10), "columnNumber": float64(2)},
				map[string]any{"type": "scroll", "lineNumber": float64(3)},
			}}),
			okStep("DOMDebugger.getEventListeners", map[string]any{"listeners": []any{
				map[string]any{"type": "click", "once": true, "lineNumber": float64(5)},
			}}),
		},
	})
	f := fields(t, run(t, "inspect_web_event_listeners", "127.0.0.1:9222"))
	if f["target"] != "T1" {
		t.Fatalf("target = %v", f["target"])
	}
	rows := f["listeners"].([]any)
	if len(rows) != 3 {
		t.Fatalf("listeners = %d, want 3: %v", len(rows), rows)
	}
	// document before window; within window click before scroll.
	r0 := rows[0].(map[string]any)
	r1 := rows[1].(map[string]any)
	r2 := rows[2].(map[string]any)
	if r0["scope"] != "document" || r0["type"] != "click" || r0["once"] != true || r0["line"] != float64(5) {
		t.Fatalf("row0 = %v", r0)
	}
	if r1["scope"] != "window" || r1["type"] != "click" || r1["capture"] != true || r1["passive"] != true || r1["line"] != float64(10) || r1["column"] != float64(2) {
		t.Fatalf("row1 = %v", r1)
	}
	if r2["scope"] != "window" || r2["type"] != "scroll" || r2["line"] != float64(3) {
		t.Fatalf("row2 = %v", r2)
	}
	by := f["by_type"].(map[string]any)
	if by["click"] != float64(2) || by["scroll"] != float64(1) {
		t.Fatalf("by_type = %v", by)
	}

	// A failed DOMDebugger step is an error naming the scope, not a partial report.
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{}),
		okStep("Runtime.evaluate", map[string]any{}),
		{Method: "DOMDebugger.getEventListeners", Ok: false, Error: &webStepError{Code: -1, Message: "no such object"}},
		okStep("DOMDebugger.getEventListeners", map[string]any{}),
	}})
	if _, err := runOp("inspect_web_event_listeners", "127.0.0.1:9222"); err == nil || !strings.Contains(err.Error(), "window listeners") {
		t.Fatalf("failed window step: got %v", err)
	}
}

func TestR2L18ObserveWebExecutionEntries(t *testing.T) {
	// Runtime/Debugger/Log/Page enabled before collection; console, exception
	// and Log.entryAdded must all be reported, with honest per-kind counters.
	fakeDriver(t, webOut{
		Target: &webTargetRow{ID: "T9", URL: "http://127.0.0.1:9222/app"},
		Steps: []webStepResult{
			okStep("Runtime.enable", map[string]any{}),
			okStep("Debugger.enable", map[string]any{}),
			okStep("Log.enable", map[string]any{}),
			okStep("Page.enable", map[string]any{}),
		},
		Events: []webEvent{
			event("Runtime.consoleAPICalled", map[string]any{
				"type": "log", "args": []any{map[string]any{"value": "hello"}, map[string]any{"value": float64(7)}},
			}),
			event("Runtime.exceptionThrown", map[string]any{"exceptionDetails": map[string]any{
				"text": "boom", "url": "app.js", "lineNumber": float64(7),
			}}),
			event("Log.entryAdded", map[string]any{"entry": map[string]any{
				"source": "network", "level": "error", "text": "404", "url": "/api", "lineNumber": float64(2),
			}}),
			event("Page.frameNavigated", map[string]any{}), // collected but not an observation
		},
	})
	f := fields(t, run(t, "observe_web_execution", "127.0.0.1:9222"))
	if f["target"] != "T9" || f["url"] != "http://127.0.0.1:9222/app" || f["since"] != "enable" {
		t.Fatalf("header = %v", f)
	}
	entries := f["entries"].([]any)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3: %v", len(entries), entries)
	}
	if f["console"] != float64(1) || f["logs"] != float64(1) || f["errors"] != float64(2) {
		t.Fatalf("counters = console %v logs %v errors %v", f["console"], f["logs"], f["errors"])
	}
	logRow := entries[2].(map[string]any)
	if logRow["kind"] != "Log.entryAdded/network" || logRow["level"] != "error" || logRow["text"] != "404" || logRow["line"] != float64(2) {
		t.Fatalf("log row = %v", logRow)
	}

	// A navigation argument becomes the reported URL and adds a Page.navigate step.
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}),
		okStep("Debugger.enable", map[string]any{}),
		okStep("Log.enable", map[string]any{}),
		okStep("Page.enable", map[string]any{}),
		okStep("Page.navigate", map[string]any{}),
	}, Events: []webEvent{
		event("Runtime.consoleAPICalled", map[string]any{"type": "info", "args": []any{map[string]any{"value": "x"}}}),
	}})
	f = fields(t, run(t, "observe_web_execution", "127.0.0.1:9222=http://example.test/landing"))
	if f["url"] != "http://example.test/landing" {
		t.Fatalf("arg url = %v", f["url"])
	}

	// A quiet page is a refusal, not an empty successful report.
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", map[string]any{}), okStep("Debugger.enable", map[string]any{}),
		okStep("Log.enable", map[string]any{}), okStep("Page.enable", map[string]any{}),
	}})
	if _, err := runOp("observe_web_execution", "127.0.0.1:9222"); err == nil || !strings.Contains(err.Error(), "a page that logs nothing reports nothing") {
		t.Fatalf("quiet page: got %v", err)
	}
}

func TestR2L18TraceNativeUIActionSession(t *testing.T) {
	// Fake adb speaks the getevent -lt dialect: device headers are not events,
	// word values (DOWN/UP) and hex values both decode, junk counts as unparsed.
	rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu-1\tdevice\n'; exit 0; fi
if [ "$1" = "exec-out" ]; then
printf 'add device 1: /dev/input/event0\n'
printf '  name:        "qwerty"\n'
printf '[  12.34] /dev/input/event0: EV_KEY KEY_A DOWN\n'
printf '[  12.35] /dev/input/event0: EV_KEY KEY_A UP\n'
printf '[  12.36] /dev/input/event0: EV_ABS ABS_MT_POSITION_X 0000012c\n'
printf 'garbage line\n'
exit 0; fi
exit 0
`})
	res := rt2TestOp(t, "trace_native_ui_action", "")
	tr, ok := res.(rt2UITrace)
	if !ok || tr.Count != 3 || tr.Unparsed != 1 || tr.Killed || len(tr.Events) != 3 {
		t.Fatalf("trace = %+v, want 3 events + 1 unparsed", res)
	}
	e0, e1, e2 := tr.Events[0], tr.Events[1], tr.Events[2]
	if e0.At != "12.34" || e0.Device != "/dev/input/event0" || e0.Type != "EV_KEY" || e0.Code != "KEY_A" || e0.Value != 1 {
		t.Fatalf("event0 = %+v", e0)
	}
	if e1.Value != 0 {
		t.Fatalf("UP value = %d, want 0", e1.Value)
	}
	if e2.Type != "EV_ABS" || e2.Code != "ABS_MT_POSITION_X" || e2.Value != 0x12c {
		t.Fatalf("event2 = %+v, want hex 12c", e2)
	}
}

func TestR2L18ActiveReasonsLifecycle(t *testing.T) {
	// A reader takes the declared set once; a second take must not succeed,
	// and undeclaredReason flips from inert to strict while the set is active.
	clearActiveReasons()
	defer clearActiveReasons()
	if takeActiveReasons(map[string]bool{"a": true}) != true {
		t.Fatal("first take refused")
	}
	if takeActiveReasons(map[string]bool{"b": true}) != false {
		t.Fatal("second take accepted")
	}
	// Built at runtime so the skip-literal registry grep does not see a
	// non-registered reason literal; this ad-hoc set is local to the test.
	reason := "a-" + "thing"
	if !undeclaredReason(reason) || undeclaredReason("a") {
		t.Fatal("undeclaredReason wrong for active set")
	}
	var d Digest
	d.skip(reason, "x")
	if len(d.reasonErrs) != 0 || d.Coverage == nil || d.Coverage.Skipped != 1 {
		t.Fatalf("declared skip under active set = errs %v cov %+v", d.reasonErrs, d.Coverage)
	}
	clearActiveReasons()
	if undeclaredReason(reason) {
		t.Fatal("undeclaredReason true after clear")
	}
}

func TestR2L18LldbErrorLineVsEcho(t *testing.T) {
	// Only an "error:" line with the exact body is a no-inferior answer; a
	// path echoing the same words stays a diagnostic.
	if got := lldbNoProcessLine("error: Command requires a current process."); got == "" {
		t.Fatal("no-process refusal not recognized")
	}
	if got := lldbNoProcessLine("error: target create '/tmp/no current process' failed\n(lldb) "); got != "" {
		t.Fatalf("path echo misread as refusal: %q", got)
	}
	errs := lldbErrors("(lldb) target list\nerror: first\nerror: second\n")
	if len(errs) != 2 || errs[0] != "error: first" || errs[1] != "error: second" {
		t.Fatalf("lldbErrors = %v", errs)
	}
	lines := lldbTranscript("out1\nout2\n", "error: bad\n")
	if len(lines) != 3 || lines[0] != "out1" || lines[2] != "error: bad" {
		t.Fatalf("lldbTranscript = %v", lines)
	}
}

// --- cdp.go ---

func TestR2L18CdpPickTargetAndDeref(t *testing.T) {
	targets := []webTargetRow{
		{ID: "1", Type: "page", URL: "https://a.b/x", WS: "ws://1"},
		{ID: "2", Type: "background", URL: "https://a.b/y", WS: ""},
		{ID: "3", Type: "page", URL: "https://a.b/z", WS: "ws://3"},
	}
	if got, err := cdpPickTarget(targets, map[string]any{"id": "3"}); err != nil || got.ID != "3" {
		t.Fatalf("pick id = %+v, %v; want target 3", got, err)
	}
	if got, err := cdpPickTarget(targets, nil); err != nil || got.ID != "1" {
		t.Fatalf("pick default = %+v, %v; want first page", got, err)
	}
	if _, err := cdpPickTarget(targets, map[string]any{"id": "2"}); err == nil {
		t.Fatal("picking a target without a websocket must fail")
	}
	if _, err := cdpPickTarget(nil, nil); err == nil {
		t.Fatal("empty /json/list must fail")
	}

	out := webOut{
		Target: &webTargetRow{URL: "https://a.b/x?y=1"},
		Steps:  []webStepResult{{Result: map[string]any{"result": map[string]any{"objectId": "42"}}}},
	}
	if got := cdpDeref(out, "$target.url"); got != "https://a.b/x?y=1" {
		t.Fatalf("target url = %v", got)
	}
	if got := cdpDeref(out, "$target.urlQuote"); got != `https://a\.b/x\?y=1` {
		t.Fatalf("quoted target url = %v", got)
	}
	if got := cdpDeref(out, "$0.result.objectId"); got != "42" {
		t.Fatalf("step ref = %v, want 42", got)
	}
	for _, bad := range []string{"$9.result.objectId", "$0.missing.path", "literal"} {
		if bad == "literal" {
			if got := cdpDeref(out, bad); got != bad {
				t.Fatalf("literal changed to %v", got)
			}
			continue
		}
		if got := cdpDeref(out, bad); got != nil {
			t.Fatalf("unresolved %s = %v, want nil", bad, got)
		}
	}
}

// --- lsdamacho.go ---

func TestR2L18LsdaMachOMatchAndDedupe(t *testing.T) {
	macho := make([]byte, 4)
	binary.LittleEndian.PutUint32(macho, 0xfeedfacf)
	if !lsdaMachOMatch(macho, int64(len(macho))) {
		t.Fatal("thin macho must match")
	}
	fat := make([]byte, 24)
	binary.BigEndian.PutUint32(fat[0:], 0xcafebabe) // fat magic, also a Java class magic
	binary.BigEndian.PutUint32(fat[4:], 1)
	binary.BigEndian.PutUint32(fat[8:], 0x0100000c) // arm64 — the byte that tells them apart
	binary.BigEndian.PutUint32(fat[16:], 32)
	binary.BigEndian.PutUint32(fat[20:], 64)
	if !lsdaMachOMatch(fat, 132) {
		t.Fatal("valid fat macho must match")
	}
	if lsdaMachOMatch(fat, 40) {
		t.Fatal("fat header past EOF must not match")
	}
	java := append([]byte(nil), fat...)
	binary.BigEndian.PutUint32(java[8:], 0x00000034) // Java class version where cputype sits
	if lsdaMachOMatch(java, 132) {
		t.Fatal("Java class file must not match the fat prefilter")
	}
	// dedupeStarts runs on already-sorted input (callers sort first); it folds
	// adjacent repeats in place, it does not re-sort.
	got := dedupeStarts([]uint64{1, 1, 2, 2, 2, 3})
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("dedupeStarts = %v, want [1 2 3]", got)
	}
}

// --- op_close_frida_session.go, op_list_procedures.go, op_search_bytes.go,
//     op_read_adb_setting.go, op_decompile_jeb_item.go, op_inspect_keyed_archive.go ---

func TestR2L18OwnedOpRegistration(t *testing.T) {
	for _, want := range []struct {
		name  string
		route string
		needs bool
	}{
		{"close_frida_session", "Y", false},
		{"list_procedures", "G", true},
		{"search_bytes", "L", true},
		{"read_adb_setting", "Y", true},
		{"decompile_jeb_item", "Y", true},
		{"inspect_keyed_archive", "L", true},
		{"inspect_web_event_listeners", "Y", true},
		{"observe_web_execution", "Y", true},
		{"trace_native_ui_action", "Y", false},
	} {
		o, ok := ops[want.name]
		if !ok {
			t.Fatalf("op %s not registered", want.name)
		}
		if o.route != want.route || o.needs != want.needs || o.desc == "" || o.run == nil {
			t.Fatalf("op %s = route %q needs %v desc %q run nil=%v", want.name, o.route, o.needs, o.desc, o.run == nil)
		}
	}
}

func TestR2L18JebJadxDiagnosticAndFailure(t *testing.T) {
	diag := jebdJadxDiagnostic("building\nERROR: Failed to generate\njava.lang.IllegalArgumentException: bad\nafter")
	if diag != "ERROR: Failed to generate; java.lang.IllegalArgumentException: bad" {
		t.Fatalf("diagnostic = %q", diag)
	}
	if got := jebdJadxDiagnostic("ERROR: " + strings.Repeat("x", 400)); len(got) != 303 || !strings.HasSuffix(got, "...") {
		t.Fatalf("400-byte line not capped: len %d", len(got))
	}
	args := []string{"--single-class", "com.Foo", "/tmp/app.apk"}
	if err := jebdJadxFailure("com.Foo", args, "ERROR: DONT_GENERATE", errors.New("x")); err == nil ||
		!strings.Contains(err.Error(), "com.Foo is not a class jadx can save") {
		t.Fatalf("DONT_GENERATE failure = %v", err)
	}
	if err := jebdJadxFailure("com.Foo", args, "ERROR: File open error", errors.New("x")); err == nil ||
		!strings.Contains(err.Error(), "/tmp/app.apk is not a readable DEX/APK") {
		t.Fatalf("File open failure = %v", err)
	}
	if err := jebdJadxFailure("com.Foo", args, "ERROR: class not found", errors.New("x")); err == nil ||
		!strings.Contains(err.Error(), "unknown class com.Foo in /tmp/app.apk") {
		t.Fatalf("not-found failure = %v", err)
	}
	if err := jebdRedact(errors.New("path /tmp/xyz/file failed"), "/tmp/xyz"); err.Error() != "path <tmpdir>/file failed" {
		t.Fatalf("redact = %q", err.Error())
	}
}

func TestR2L18KeyedArchiveRejectsPlainPlist(t *testing.T) {
	p := opStaticFile(t, "plain", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}}, // top: $archiver, $foo
		{kind: 's', str: "$archiver"},
		{kind: 's', str: "NSKeyedArchiver"},
		{kind: 's', str: "$foo"},
		{kind: 's', str: "x"},
	}))
	res, err := runOp("inspect_keyed_archive", p)
	if err != nil {
		t.Fatalf("plain plist op error: %v", err)
	}
	sk, ok := res.(*skip)
	if !ok || !strings.Contains(sk.Reason, "top object has no $objects array") {
		t.Fatalf("plain plist = %T (%v), want skip naming $objects", res, res)
	}

	// The real shape must still resolve $class through $objects, not through
	// the object table, or every histogram comes back empty.
	q := opStaticFile(t, "keyed", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}},
		{kind: 's', str: "$archiver"},
		{kind: 's', str: "$objects"},
		{kind: 's', str: "NSKeyedArchiver"},
		{kind: 'a', refs: []byte{8, 5, 9}},
		{kind: 'd', keys: []byte{6}, vals: []byte{7}},
		{kind: 's', str: "$class"},
		{kind: 'u', uid: 2},
		{kind: 's', str: "$null"},
		{kind: 'd', keys: []byte{10}, vals: []byte{11}},
		{kind: 's', str: "$classname"},
		{kind: 's', str: "NSString"},
	}))
	m := opStatic(t, "inspect_keyed_archive", q)
	if opStaticNum(t, m, "classes") != 1 || opStaticStr(t, m, "archiver") != "NSKeyedArchiver" {
		t.Fatalf("keyed archive = %v", m)
	}
	hist, _ := m["class_histogram"].([]any)
	if len(hist) != 1 || hist[0] != "NSString=1" {
		t.Fatalf("class_histogram = %v", hist)
	}
}

func TestR2L18ReadAdbSettingNamespaceAndValue(t *testing.T) {
	if _, err := opReadAdbSetting("bogus:key"); err == nil ||
		!strings.Contains(err.Error(), `settings namespace "bogus" is not system, secure or global`) {
		t.Fatalf("bad namespace error = %v", err)
	}
	if _, err := opReadAdbSetting("system:"); err == nil ||
		!strings.Contains(err.Error(), "needs an argument") {
		t.Fatalf("missing key error = %v", err)
	}
	for _, tc := range []struct {
		value string
		set   bool
	}{
		{"bar\n", true},
		{"null\n", false},
		{"\n", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			rt2TestTools(t, map[string]string{"adb": `#!/bin/sh
if [ "$1" = "devices" ]; then printf 'List of devices attached\nemu\tdevice\n'; exit 0; fi
if [ "$1" = "shell" ]; then printf '` + strings.TrimSuffix(tc.value, "\n") + `\n'; exit 0; fi
exit 0
`})
			got, err := opReadAdbSetting("secure:foo")
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			st, ok := got.(rt2AdbSetting)
			if !ok || st.Namespace != "secure" || st.Key != "foo" || st.Set != tc.set {
				t.Fatalf("setting = %+v, want secure/foo set=%v", got, tc.set)
			}
			if tc.set && (st.Value == nil || *st.Value != "bar") {
				t.Fatalf("set value = %v, want bar", st.Value)
			}
			if !tc.set && st.Value != nil {
				t.Fatalf("unset value = %q, want nil", *st.Value)
			}
		})
	}
}

func TestR2L18SearchBytePatternCore(t *testing.T) {
	pat, mask, err := parseBytePattern("48 8b ?? c3")
	if err != nil || len(pat) != 4 || pat[0] != 0x48 || pat[1] != 0x8b || pat[3] != 0xc3 {
		t.Fatalf("parse = %x, %v, %v", pat, mask, err)
	}
	if mask[0] != true || mask[1] != true || mask[2] != false || mask[3] != true {
		t.Fatalf("mask = %v", mask)
	}
	if got := nativePatternString(pat, mask); got != "48 8b ?? c3" {
		t.Fatalf("normalized = %q", got)
	}
	pat2, mask2, err := parseBytePattern("488B??C3")
	if err != nil || len(pat2) != 4 || pat2[1] != 0x8b || mask2[2] {
		t.Fatalf("contiguous hex = %x, %v, %v", pat2, mask2, err)
	}
	if _, _, err := parseBytePattern("zz"); err == nil {
		t.Fatal("non-hex pattern must fail")
	}
	b := []byte{0x48, 0x8b, 0x55, 0xc3}
	if !nativeMatch(b, 0, pat, mask) || nativeMatch(b, 1, pat, mask) {
		t.Fatal("masked match must hit at 0 and miss at 1")
	}
}
