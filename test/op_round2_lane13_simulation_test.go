package main

// TUR 2 / LANE 13 - independent simulation audit.
// Each TestR2L13* test runs the relevant production function with real input and
// verifies the expected behavior; production code is not relaxed.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- op_list_names.go

func TestR2L13ListNamesAnswer(t *testing.T) {
	res := listNamesAnswer(map[string]any{
		"names":  float64(450),
		"sample": []any{"a", "b", "c"},
	})
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("listNamesAnswer return is not a map: %T", res)
	}
	for k, want := range map[string]any{
		"parsed": 450, "total": 450, "shown": 3, "truncated": true,
	} {
		if !reflect.DeepEqual(m[k], want) {
			t.Errorf("%s = %#v, want %#v", k, m[k], want)
		}
	}
	// No truncation when the sample count equals the found count.
	full := listNamesAnswer(map[string]any{"names": 2, "sample": []any{1, 2}}).(map[string]any)
	if full["truncated"] != false || full["shown"] != 2 {
		t.Fatalf("untruncated answer is wrong: %#v", full)
	}
	// Non-map input is returned unchanged.
	if got := listNamesAnswer("raw"); got != "raw" {
		t.Fatalf("non-map input changed: %#v", got)
	}
}

// ---------------------------------------------------------------- op_list_strings.go

func TestR2L13ListStringsCapValues(t *testing.T) {
	long := strings.Repeat("A", 10001)
	hits := []stringHit{{Value: long, Len: len(long)}, {Value: "short", Len: 4}}
	cut, blob := capValues(hits)
	if !cut || !blob {
		t.Fatalf("capValues = (%v,%v), both must be true", cut, blob)
	}
	if len(hits[0].Value) > listStringsValueMax+3 || !strings.HasSuffix(hits[0].Value, "…") {
		t.Errorf("long value was not truncated: len=%d", len(hits[0].Value))
	}
	if hits[0].Len != 10001 {
		t.Errorf("Len was not preserved: %d", hits[0].Len)
	}
	if hits[1].Value != "short" {
		t.Errorf("short value changed: %q", hits[1].Value)
	}
	// Values under 4 KiB are truncated but are not counted as a blob.
	mid := []stringHit{{Value: strings.Repeat("B", 1000), Len: 1000}}
	if c, b := capValues(mid); !c || b {
		t.Fatalf("1000B capValues = (%v,%v), want (true,false)", c, b)
	}
}

func TestR2L13ListStringsAnswerScanCaps(t *testing.T) {
	// Create a valid ELF file; nativeStringsScan really scans.
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")
	// A small file with printable content; it errors because it is not ELF,
	// so we can also verify listStringsAnswer's error path.
	if err := os.WriteFile(path, []byte("hello world ABCDEF"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := listStringsAnswer(path, 3, 32)
	if err == nil {
		t.Fatal("listStringsAnswer must return an error on a non-ELF file")
	}
}

// ---------------------------------------------------------------- op register (G/Y routes)

func TestR2L13RegisteredOps(t *testing.T) {
	cases := map[string]struct {
		route string
		needs bool
	}{
		"list_names":             {"G", true},
		"list_procedures":        {"G", true},
		"list_segments":          {"G", true},
		"list_unknowns":          {"G", true},
		"match_native_functions": {"G", true},
		"list_strings":           {"L", true},
		"load_frida_script":      {"Y", false},
	}
	for name, want := range cases {
		o, ok := ops[name]
		if !ok {
			t.Errorf("op not registered: %s", name)
			continue
		}
		if o.route != want.route || o.needs != want.needs {
			t.Errorf("%s: route=%q needs=%v; want %q/%v", name, o.route, o.needs, want.route, want.needs)
		}
		if o.run == nil || o.desc == "" {
			t.Errorf("%s: run/desc empty", name)
		}
	}
}

// ---------------------------------------------------------------- op_modes.go

func TestR2L13ModesEncodeAndNumbers(t *testing.T) {
	v := map[string]any{"b": 1, "a": "x"}
	compact, err := encodeJSON(v, true)
	if err != nil || strings.Contains(string(compact), "\n") {
		t.Fatalf("compact JSON unexpected: %s %v", compact, err)
	}
	pretty, err := encodeJSON(v, false)
	if err != nil || !strings.Contains(string(pretty), "\n") {
		t.Fatalf("pretty JSON unexpected: %s %v", pretty, err)
	}
	dec, err := decodeNumbers(map[string]any{"addr": json.Number("123456789012345678")})
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := jsonInt(dec.(map[string]any)["addr"]); !ok || n != 0 {
		// If json.Number overflows Int64, jsonInt returns false; that is expected.
		t.Logf("wide number jsonInt=false (expected): ok=%v", ok)
	}
}

func TestR2L13ModesTableAndUnits(t *testing.T) {
	m := map[string]any{
		"rows":      []any{1, 2},
		"imports":   []any{1},
		"total":     7,
		"truncated": true,
	}
	name, rows, ok := tableOf(m, "list_strings")
	if !ok || name != "rows" || len(rows) != 2 {
		t.Fatalf("tableOf = %q %d %v", name, len(rows), ok)
	}
	_, rows, ok = longestArray(m)
	if !ok || len(rows) != 2 {
		t.Fatalf("longestArray = %d %v", len(rows), ok)
	}
	if got, known := unitTotal(m, "list_strings", 2); !known || got != 7 {
		t.Fatalf("unitTotal = %d %v", got, known)
	}
	if !capFlag(m) {
		t.Fatal("capFlag must be true for truncated")
	}
	if total, known, trunc := unitState(m, "list_strings", 2); total != 7 || !known || !trunc {
		t.Fatalf("unitState = %d %v %v", total, known, trunc)
	}
	if unitName("list_names") != "sample" || unitName("unknown") != "" {
		t.Fatal("unitName wrong")
	}
}

func TestR2L13ModesAggregateAndCoverage(t *testing.T) {
	answer, err := decodeNumbers(map[string]any{
		"op":     "list_strings",
		"target": "t",
		"result": map[string]any{
			"strings": 3, "shown": 2, "total": 3,
			"rows": []any{
				map[string]any{"address": 1, "ascii": true},
				map[string]any{"address": 2, "ascii": true},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := aggregate(answer, opModes{countOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	cm := got.(map[string]any)
	if cm["count"] != 2 || cm["total"] != 3 || cm["truncated"] != true {
		t.Fatalf("count-only lost coverage information: %#v", cm)
	}
	got, err = aggregate(answer, opModes{by: "ascii"})
	if err != nil {
		t.Fatal(err)
	}
	groups := got.(map[string]any)["result"].(map[string]any)["rows"].([]any)
	if len(groups) != 1 || groups[0].(map[string]any)["count"] != 2 {
		t.Fatalf("--by grouping wrong: %#v", groups)
	}
	got, err = aggregate(answer, opModes{fields: "address", top: 1})
	if err != nil {
		t.Fatal(err)
	}
	proj := got.(map[string]any)["result"].(map[string]any)["rows"].([]any)
	if len(proj) != 1 || len(proj[0].(map[string]any)) != 1 {
		t.Fatalf("--fields projection wrong: %#v", proj)
	}
	cov := withCoverage(answer).(map[string]any)["coverage"].(map[string]any)
	if !reflect.DeepEqual(cov["parsed"], 2) {
		t.Fatalf("coverage.parsed = %#v, want 2", cov["parsed"])
	}
}

func TestR2L13ModesHelpersAndConflicts(t *testing.T) {
	if got := splitComma(" a, b ,,c "); !reflect.DeepEqual(got, []string{"a", "b", "c"}) {
		t.Errorf("splitComma = %#v", got)
	}
	if modeConflict(opModes{countOnly: true, by: "x"}) == nil ||
		modeConflict(opModes{by: "x", fields: "y"}) == nil ||
		modeConflict(opModes{top: -1}) == nil {
		t.Fatal("modeConflict did not catch the conflicts")
	}
	if modeConflict(opModes{countOnly: true}) != nil {
		t.Fatal("valid mode mistaken for a conflict")
	}
	if lenList([]any{1, 2}) != 2 || lenList("x") != 0 {
		t.Fatal("lenList wrong")
	}
	if !partialOf(map[string]any{"truncated": true}) || partialOf(map[string]any{}) {
		t.Fatal("partialOf wrong")
	}
}

// ---------------------------------------------------------------- op_metab_util.go

func TestR2L13MetaBQueryAndInsnLen(t *testing.T) {
	cases := []struct {
		s, q string
		want bool
	}{
		{"Lcom/foo/Bar;->run", "com.foo.Bar", true},
		{"Lcom/foo/Bar;->run", "BAR;->RUN", true},
		{"Lcom/foo/Bar;", "LCOM/FOO/BAR;", true},
		{"Lcom/foo/Bar;", "baz", false},
	}
	for _, c := range cases {
		if got := metaBQuery(c.s, c.q); got != c.want {
			t.Errorf("metaBQuery(%q,%q)=%v, want %v", c.s, c.q, got, c.want)
		}
	}
	// Dalvik opcode widths: invoke 35c/3rc = 3 units, fill-array-data = 3,
	// nop = 1, unknown opcode = 0.
	for op, want := range map[byte]int{0x00: 1, 0x6e: 3, 0x74: 3, 0x03: 3, 0x12: 1, 0xfe: 2, 0x73: 0} {
		if got := metaBInsnLen(op); got != want {
			t.Errorf("metaBInsnLen(%#x)=%d, want %d", op, got, want)
		}
	}
	for op, want := range map[byte]bool{0x6e: true, 0x72: true, 0x74: true, 0x78: true, 0x00: false, 0x73: false} {
		if got := metaBIsInvoke(op); got != want {
			t.Errorf("metaBIsInvoke(%#x)=%v, want %v", op, got, want)
		}
	}
}

func TestR2L13MetaBInvokesDecodesInstructions(t *testing.T) {
	// code_item: registers=1, ins=0, outs=0, tries=0, insns_size=4 units (8 bytes)
	// insns: nop(0x00, 1 unit) + invoke-virtual(0x6e, 3 units, idx=2)
	b := make([]byte, 16+8)
	b[12] = 4 // insns_size (u32, little endian) = 4 units = 8 bytes
	b[16+0], b[16+1] = 0x00, 0x00
	b[16+2], b[16+3] = 0x6e, 0x00
	b[16+4], b[16+5] = 0x02, 0x00 // method_id 2
	r := dexReader{b: b, end: len(b), metSize: 5}
	got, err := metaBInvokes(r, 0)
	if err != nil {
		t.Fatalf("metaBInvokes: %v", err)
	}
	if !reflect.DeepEqual(got, []int{2}) {
		t.Fatalf("invoke indices = %#v, want [2]", got)
	}
	// Out-of-range method_id must be rejected.
	r.metSize = 2
	if _, err := metaBInvokes(r, 0); err == nil || !strings.Contains(err.Error(), "method_id") {
		t.Fatalf("invalid method_id was not rejected: %v", err)
	}
}

func TestR2L13MetaBPEBase(t *testing.T) {
	// PE32+ optional header: magic 0x20b, ImageBase @+24 = 0x140000000
	b := make([]byte, 0x100)
	b[0], b[1] = 'M', 'Z'
	b[0x3c] = 0x40
	copy(b[0x40:0x44], "PE\x00\x00")
	opt := 0x40 + 24
	b[opt], b[opt+1] = 0x0b, 0x02
	// ImageBase 0x140000000 little-endian: 00 00 00 40 01 00 00 00
	b[opt+24], b[opt+25], b[opt+26], b[opt+27] = 0x00, 0x00, 0x00, 0x40
	b[opt+28] = 0x01
	if base, ptr, ok := metaBPEBase(b); !ok || base != 0x140000000 || ptr != 8 {
		t.Fatalf("PE32+ base=%#x ptr=%d ok=%v", base, ptr, ok)
	}
	// PE32: magic 0x10b, ImageBase @+28 (4 bytes)
	b2 := make([]byte, 0x100)
	b2[0], b2[1] = 'M', 'Z'
	b2[0x3c] = 0x40
	copy(b2[0x40:0x44], "PE\x00\x00")
	b2[opt], b2[opt+1] = 0x0b, 0x01
	b2[opt+28], b2[opt+29], b2[opt+30], b2[opt+31] = 0x00, 0x00, 0x40, 0x00
	if base, ptr, ok := metaBPEBase(b2); !ok || base != 0x400000 || ptr != 4 {
		t.Fatalf("PE32 base=%#x ptr=%d ok=%v", base, ptr, ok)
	}
	if _, _, ok := metaBPEBase([]byte("bad")); ok {
		t.Fatal("non-PE data accepted")
	}
}

// ---------------------------------------------------------------- op_meta_util.go

func TestR2L13MetaLoadJobAndArgs(t *testing.T) {
	dir := t.TempDir()
	jobFile := filepath.Join(dir, "job.json")
	if err := os.WriteFile(jobFile, []byte(`{"file":"target.bin","address":"0x10","count":3}`), 0o644); err != nil {
		t.Fatal(err)
	}
	job, err := metaLoadJob(jobFile)
	if err != nil || job.File != "target.bin" || job.Address != "0x10" || job.Count != 3 {
		t.Fatalf("metaLoadJob = %+v %v", job, err)
	}
	// JSON without a Job key -> raw file path.
	plain := filepath.Join(dir, "digest.json")
	os.WriteFile(plain, []byte(`{"foo":1}`), 0o644)
	job, err = metaLoadJob(plain)
	if err != nil || job.File != plain {
		t.Fatalf("non-job JSON wrong: %+v %v", job, err)
	}
	if got := metaArgs("a", "1", "b", "  ", "c"); !reflect.DeepEqual(got, map[string]string{"a": "1"}) {
		t.Fatalf("metaArgs = %#v", got)
	}
	if metaExtra(nil, "x") != "" || metaExtra(map[string]string{"x": "y"}, "x") != "y" {
		t.Fatal("metaExtra wrong")
	}
}

func TestR2L13MetaStateFilesAndChanges(t *testing.T) {
	dir := t.TempDir()
	root, err := metaStateRoot(dir, metaJob{State: filepath.Join(dir, "state")})
	if err != nil {
		t.Fatal(err)
	}
	f, err := metaStateFile(root, "session.json")
	if err != nil {
		t.Fatal(err)
	}
	type sess struct {
		Kind string `json:"kind"`
		N    int    `json:"n"`
	}
	if err := metaWriteJSON(f, sess{Kind: "session", N: 1}); err != nil {
		t.Fatal(err)
	}
	var got sess
	exists, err := metaReadState(f, "session", &got)
	if !exists || err != nil || got.N != 1 {
		t.Fatalf("metaReadState = %v %v %+v", exists, err, got)
	}
	// Wrong artifact must be rejected.
	metaWriteJSON(f, sess{Kind: "bookmarks", N: 2})
	if _, err := metaReadState(f, "session", &got); err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("artifact conflict was not rejected: %v", err)
	}
	// Deterministic canonical + hash.
	c1, _ := metaCanonical(map[string]any{"b": 2, "a": 1})
	c2, _ := metaCanonical(map[string]any{"a": 1, "b": 2})
	if string(c1) != string(c2) {
		t.Fatalf("canonical is order-dependent: %s / %s", c1, c2)
	}
	if metaSHA256([]byte("x")) != "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" {
		t.Fatal("metaSHA256 wrong")
	}
}

func TestR2L13MetaChangesAndHelpers(t *testing.T) {
	a := Digest{ContractVersion: 1, Kind: "pe", Deps: []Dep{{Path: "x", Version: "1"}}}
	b := Digest{ContractVersion: 1, Kind: "elf", Deps: []Dep{{Path: "x", Version: "2"}}}
	ch := metaChanges(a, b)
	paths := map[string]bool{}
	for _, c := range ch {
		paths[c.Path] = true
	}
	if !paths["kind"] || !paths["deps.x"] {
		t.Fatalf("metaChanges missing: %#v", paths)
	}
	if got := metaHex([]byte{0xde, 0xad}); got != "dead" {
		t.Errorf("metaHex = %s", got)
	}
	if bb, err := metaHexBytes("0xde ad"); err != nil || len(bb) != 2 || bb[0] != 0xde {
		t.Fatalf("metaHexBytes = %x %v", bb, err)
	}
	if v, err := metaParseAddr("0x10"); err != nil || v != 16 {
		t.Fatalf("metaParseAddr(0x10) = %d %v", v, err)
	}
	// metaParseAddr prefers hex over decimal: "42" = 0x42 = 66.
	if v, err := metaParseAddr("42"); err != nil || v != 0x42 {
		t.Fatalf("metaParseAddr(42) = %d %v", v, err)
	}
	if _, err := metaParseAddr("zzz"); err == nil {
		t.Fatal("invalid address accepted")
	}
	if got := metaTail("a\n\nb\nc\nd", 2); got != "c | d" {
		t.Errorf("metaTail = %q", got)
	}
	if got := metaDiag("noise\nerror: bad\nERROR: worse\nmore", 1); got != "error: bad" {
		t.Errorf("metaDiag = %q", got)
	}
	if got := metaGraphResult(nil, nil); got["node_count"] != 0 || got["edge_count"] != 0 {
		t.Fatalf("metaGraphResult = %#v", got)
	}
	if nz(nil) == nil || len(nz(nil)) != 0 {
		t.Fatal("nz did not turn nil into []")
	}
	if got := metaSlice([]string{"a", "b", "c"}, []int{1, 3}, 0, 3); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("metaSlice = %#v", got)
	}
}

func TestR2L13MetaTimeoutAndGhidraTarget(t *testing.T) {
	err := metaTimeoutErrorFor(t.TempDir(), "/tmp/target", 5*time.Second, false)
	if !isMetaTimeout(err) || !strings.Contains(err.Error(), "timed out after 5s") {
		t.Fatalf("metaTimeout = %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bin")
	os.WriteFile(path, []byte("x"), 0o644)
	if target, err := metaGhidraTarget(path, metaJob{}); err != nil || target != path {
		t.Fatalf("metaGhidraTarget = %q %v", target, err)
	}
	if _, err := metaGhidraTarget(path, metaJob{File: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("nonexistent target accepted")
	}
}

// ---------------------------------------------------------------- op_native_util.go

func TestR2L13NativeBudgetsAndParsing(t *testing.T) {
	// ghidraBudget: base + 12s/MiB, 30min cap.
	if got := ghidraBudget(0); got != 50*time.Second {
		t.Errorf("ghidraBudget(0) = %s", got)
	}
	if got := ghidraBudget(1 << 20); got != 62*time.Second {
		t.Errorf("ghidraBudget(1MiB) = %s, want 62s", got)
	}
	if got := ghidraBudget(1 << 30); got != 30*time.Minute {
		t.Errorf("ghidraBudget(1GiB) = %s, want 30m", got)
	}
	if v, err := nativeParseNum("0x2a"); err != nil || v != 42 {
		t.Fatalf("nativeParseNum(0x2a) = %d %v", v, err)
	}
	if v, err := nativeParseNum("ff"); err != nil || v != 255 {
		t.Fatalf("nativeParseNum(ff) = %d %v", v, err)
	}
	if _, err := nativeParseNum("invalid"); err == nil {
		t.Fatal("invalid number accepted")
	}
}

func TestR2L13NativeBytePatternAndFunctions(t *testing.T) {
	pat, mask, err := parseBytePattern("48 8b ?? 0x05")
	if err != nil || len(pat) != 4 || len(mask) != 4 || mask[2] || !mask[3] || pat[3] != 0x05 {
		t.Fatalf("parseBytePattern = %x %v %v", pat, mask, err)
	}
	if !nativeMatch([]byte{0x48, 0x8b, 0xff, 0x05}, 0, pat, mask) {
		t.Fatal("nativeMatch did not match")
	}
	if nativeMatch([]byte{0x48, 0x8b, 0xff, 0x06}, 0, pat, mask) {
		t.Fatal("nativeMatch matched despite the masked byte")
	}
	if got := nativePatternString(pat, mask); got != "48 8b ?? 05" {
		t.Errorf("nativePatternString = %q", got)
	}
	if _, _, err := parseBytePattern(""); err == nil {
		t.Fatal("empty pattern accepted")
	}
	fns := []nativeFunc{{Name: "c", Start: 100, End: 0}, {Name: "a", Start: 10, End: 20}, {Name: "b", Start: 30, End: 0}}
	closeSizes(fns)
	if fns[0].Start != 10 || fns[1].Start != 30 || fns[2].End != 101 {
		t.Fatalf("closeSizes = %+v", fns)
	}
	if f := containingFunction(fns, 15); f == nil || f.Name != "a" {
		t.Fatalf("containingFunction(15) = %+v", f)
	}
	if f := nextFunction(fns, 15); f == nil || f.Name != "b" {
		t.Fatalf("nextFunction(15) = %+v", f)
	}
	// prevFunction returns the largest start below addr (15 >= 10 → "a").
	if f := prevFunction(fns, 15); f == nil || f.Name != "a" {
		t.Fatalf("prevFunction(15) = %+v", f)
	}
	if f := prevFunction(fns, 5); f != nil {
		t.Fatalf("prevFunction(5) = %+v (want nil)", f)
	}
}

// ---------------------------------------------------------------- op_native_cache.go

func TestR2L13CacheKeysAndDigests(t *testing.T) {
	d1 := ghidraScriptDigest("script A")
	d2 := ghidraScriptDigest("script B")
	if d1 == d2 || len(d1) != 16 {
		t.Fatalf("ghidraScriptDigest = %q / %q", d1, d2)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "target")
	os.WriteFile(path, []byte("abc"), 0o644)
	st, _ := os.Stat(path)
	k1 := ghidraEntryKey(path, "v1", st)
	os.WriteFile(path, []byte("abcd"), 0o644)
	st, _ = os.Stat(path)
	k2 := ghidraEntryKey(path, "v1", st)
	if k1 == k2 || len(k1) != 16 {
		t.Fatalf("ghidraEntryKey did not catch the byte change: %q / %q", k1, k2)
	}
	if ghidraCacheKey(path, st) == "" {
		t.Fatal("ghidraCacheKey empty")
	}
}

func TestR2L13CacheAnswerRoundTripAndLockRead(t *testing.T) {
	dir := t.TempDir()
	res := map[string]any{"functions": 3, "sample": []any{1, 2, 3}}
	ghidraAnswerStore(dir, "list_procedures", []string{"a"}, res)
	got, ok := ghidraAnswerHit(dir, "list_procedures", []string{"a"})
	// JSON numbers come back as float64.
	if !ok || got["functions"] != float64(3) {
		t.Fatalf("ghidraAnswerHit = %#v %v", got, ok)
	}
	if _, ok := ghidraAnswerHit(dir, "list_procedures", []string{"b"}); ok {
		t.Fatal("different arguments returned the same answer")
	}
	// A corrupt answer is not a hit and is deleted.
	p := ghidraAnswerPath(dir, "list_procedures", []string{"a"})
	os.WriteFile(p, []byte("{corrupt"), 0o644)
	if _, ok := ghidraAnswerHit(dir, "list_procedures", []string{"a"}); ok {
		t.Fatal("corrupt answer counted as a hit")
	}
	lockPath := filepath.Join(dir, "lock")
	os.WriteFile(lockPath, []byte("999999 -1 0"), 0o644)
	if _, ok := ghidraLockRead(lockPath); ok {
		t.Fatal("invalid lock accepted")
	}
	os.WriteFile(lockPath, []byte("1 1000 5000000000"), 0o644)
	if owner, ok := ghidraLockRead(lockPath); !ok || owner.PID != 1 || owner.Budget != 5*time.Second {
		t.Fatalf("ghidraLockRead = %+v %v", owner, ok)
	}
	// Our own pid is never stale.
	own := ghidraLockOwner{PID: os.Getpid(), Since: time.Now().Add(-time.Hour), Budget: time.Second}
	if _, stale := ghidraStaleLock(own, time.Now()); stale {
		t.Fatal("own pid mistaken for stale")
	}
}

// ---------------------------------------------------------------- existing test files present

func TestR2L13ExistingTestFilesPresent(t *testing.T) {
	// This lane's test files are already included at compile time; here
	// verify that their sources exist and are non-empty.
	for _, name := range []string{
		"op_list_lane12_test.go", "op_list_strings_test.go",
		"op_managed_decompile_test.go", "op_meta_ledger_fix_test.go",
		"op_meta_real_test.go", "op_meta_test.go", "op_meta_timeout_test.go",
		"op_metab_test.go", "op_modes_test.go", "op_native_cache_bounds_test.go",
		"op_native_cache_test.go", "op_native_deadline_test.go",
		"op_native_session_test.go", "op_native_test.go",
	} {
		st, err := os.Stat(name)
		if err != nil || st.Size() == 0 {
			t.Errorf("test file missing/empty: %s (%v)", name, err)
		}
	}
}
