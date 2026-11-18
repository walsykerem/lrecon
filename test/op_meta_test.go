package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// metaTestArg writes a job object to a temp file and returns its path, which is
// what the CLI hands runOp when the caller passes structured input.
func metaTestArg(t *testing.T, job map[string]any) string {
	t.Helper()
	b, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, "job.json", b)
}

// metaTestState points every state op at a fresh dir for this test.
func metaTestState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("LRECON_STATE", dir)
	return dir
}

// metaTestRun normalizes any op result into a JSON map so tests can assert on
// the same keys the CLI prints.
func metaTestRun(t *testing.T, name, arg string) (map[string]any, error) {
	t.Helper()
	res, err := runOp(name, arg)
	if err != nil {
		return nil, err
	}
	b, err := metaCanonical(res)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: result is not a JSON object: %v (%s)", name, err, b)
	}
	return m, nil
}

func metaMustRun(t *testing.T, name, arg string) map[string]any {
	t.Helper()
	m, err := metaTestRun(t, name, arg)
	if err != nil {
		t.Fatalf("%s %s: %v", name, arg, err)
	}
	return m
}

// metaNum reads a numeric result field regardless of how JSON widened it.
func metaNum(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	t.Fatalf("result has no numeric %q: %#v", key, m)
	return 0
}

func metaStr(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, _ := m[key].(string)
	return s
}

// metaBool reads a boolean result field.
func metaBool(t *testing.T, m map[string]any, key string) bool {
	t.Helper()
	b, _ := m[key].(bool)
	return b
}

// metaManagedPE is the deterministic managed fixture every analysis test uses.
func metaManagedPE(t *testing.T) string {
	t.Helper()
	return buildTablesPE(t, managedTablesFixture(t))
}

func metaReadFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMetaSessionLifecycle(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)

	first := metaMustRun(t, "binary_session", pe)
	if metaStr(t, first, "state") != "opened" {
		t.Fatalf("first open: state = %v, want opened", first["state"])
	}
	file := metaStr(t, first, "session_file")
	if filepath.Dir(file) != state {
		t.Fatalf("session file %s is not in state dir %s", file, state)
	}
	var disk map[string]any
	if err := json.Unmarshal(metaReadFile(t, file), &disk); err != nil {
		t.Fatalf("session.json is not JSON: %v", err)
	}
	if disk["kind"] != "lrecon.session/1" {
		t.Fatalf("session kind = %v", disk["kind"])
	}
	if disk["document"] == "" || disk["project"] == "" {
		t.Fatalf("session.json lost project/document: %v", disk)
	}

	again := metaMustRun(t, "binary_session", pe)
	if metaStr(t, again, "state") != "reopened" {
		t.Fatalf("second open: state = %v, want reopened", again["state"])
	}
	if again["opened"] != first["opened"] {
		t.Fatalf("reopen moved the opened timestamp: %v -> %v", first["opened"], again["opened"])
	}

	// A different artifact must surface the one it replaces instead of silently
	// swapping the session.
	other := writeTemp(t, "other.bin", []byte("second artifact"))
	third := metaMustRun(t, "binary_session", other)
	if metaStr(t, third, "previous_document") != metaStr(t, first, "document") {
		t.Fatalf("previous_document = %v, want %v", third["previous_document"], first["document"])
	}

	closed := metaMustRun(t, "close_binary", state)
	if !metaBool(t, closed, "closed") {
		t.Fatalf("close_binary did not report closed: %v", closed)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatalf("session.json survived close: %v", err)
	}
	if _, err := metaTestRun(t, "close_binary", state); err == nil || !strings.Contains(err.Error(), "no session") {
		t.Fatalf("second close: want a no-session error, got %v", err)
	}
}

func TestMetaUnknownsRoundTrip(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)
	secs, err := metaSectionTable(pe)
	if err != nil || len(secs) == 0 {
		t.Fatalf("section table: %v (%d sections)", err, len(secs))
	}
	var sec metaSection
	for _, s := range secs {
		if s.Size >= 64 && s.Off+64 < uint64(len(metaReadFile(t, pe))) {
			sec = s
			break
		}
	}
	if sec.Name == "" {
		t.Fatal("fixture has no section large enough to sample: the fixture builder changed")
	}
	raw := metaReadFile(t, pe)
	end := min(sec.Off+4+16, uint64(len(raw)))
	want := raw[sec.Off+4 : end]
	addr := fmt.Sprintf("%#x", sec.Addr+4)

	rec := metaMustRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"file":       pe,
		"address":    addr,
		"hypothesis": "checks the cache key before decoding",
	}))
	entry, _ := rec["recorded"].(map[string]any)
	if entry == nil || entry["bytes"] != metaHex(want) {
		t.Fatalf("recorded bytes = %v, want %s (addr %s)", entry["bytes"], metaHex(want), addr)
	}
	if metaNum(t, rec, "count") != 1 || metaNum(t, rec, "unresolved") != 1 {
		t.Fatalf("record counters = %v", rec)
	}
	if _, ok := rec["unknowns_file"]; !ok {
		t.Fatalf("record_unknown did not name the state file: %v", rec)
	}

	if _, err := metaTestRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"address": addr, "bytes": "00",
	})); err == nil || !strings.Contains(err.Error(), "already recorded") {
		t.Fatalf("duplicate address: want already-recorded error, got %v", err)
	}

	upd := metaMustRun(t, "update_unknown", metaTestArg(t, map[string]any{
		"file": pe, "address": addr, "resolution": "the cache key is the plist UUID",
	}))
	if metaNum(t, upd, "unresolved") != 0 {
		t.Fatalf("update did not resolve: %v", upd)
	}

	ver := metaMustRun(t, "verify_unknown_resolution", metaTestArg(t, map[string]any{
		"file": pe, "address": addr,
	}))
	if !metaBool(t, ver, "verified") {
		t.Fatalf("verify against unchanged bytes failed: %v", ver)
	}
	if metaStr(t, ver, "section") != sec.Name {
		t.Fatalf("verify mapped section = %q, want %q", metaStr(t, ver, "section"), sec.Name)
	}

	// A state file written by a different tool must be refused, not overwritten.
	unknowns := filepath.Join(state, "unknowns.json")
	if err := os.WriteFile(unknowns, []byte(`{"kind":"other.tool/9","unknowns":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = metaTestRun(t, "record_unknown", metaTestArg(t, map[string]any{
		"address": "0x1", "bytes": "00",
	}))
	if err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("foreign unknowns.json: want state conflict, got %v", err)
	}
}

func TestMetaBookmarks(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)

	set := metaMustRun(t, "set_bookmark", metaTestArg(t, map[string]any{
		"file": pe, "address": "0x1400", "note": "first note",
	}))
	if metaNum(t, set, "count") != 1 || metaBool(t, set, "updated") {
		t.Fatalf("first set = %v", set)
	}
	set2 := metaMustRun(t, "set_bookmark", metaTestArg(t, map[string]any{
		"file": pe, "address": "0x1400", "note": "second note",
	}))
	if metaNum(t, set2, "count") != 1 || !metaBool(t, set2, "updated") {
		t.Fatalf("upsert = %v", set2)
	}

	list := metaMustRun(t, "list_bookmarks", metaTestArg(t, map[string]any{"file": pe}))
	if metaNum(t, list, "count") != 1 {
		t.Fatalf("list = %v", list)
	}
	marks, _ := list["bookmarks"].([]any)
	if len(marks) != 1 {
		t.Fatalf("bookmarks = %v", list["bookmarks"])
	}
	bm, _ := marks[0].(map[string]any)
	if bm["note"] != "second note" {
		t.Fatalf("list lost the upserted note: %v", bm)
	}

	// The contract is a bare JSON array so other tools can read it.
	bookmarks := filepath.Join(state, "bookmarks.json")
	if b := metaReadFile(t, bookmarks); len(b) == 0 || b[0] != '[' {
		t.Fatalf("bookmarks.json is not a top-level array: %s", b)
	}

	un := metaMustRun(t, "unset_bookmark", metaTestArg(t, map[string]any{"file": pe, "address": "0x1400"}))
	removed, _ := un["removed"].([]any)
	if len(removed) != 1 || metaNum(t, un, "count") != 0 {
		t.Fatalf("unset = %v", un)
	}
	if _, err := metaTestRun(t, "unset_bookmark", metaTestArg(t, map[string]any{"address": "0x1400"})); err == nil {
		t.Fatal("unset of a missing bookmark reported success")
	}
}

func TestMetaAnalysisSettings(t *testing.T) {
	state := metaTestState(t)

	def := metaMustRun(t, "inspect_analysis_settings", state)
	if metaStr(t, def, "source") != "defaults" {
		t.Fatalf("fresh config source = %v", def["source"])
	}
	settings, _ := def["settings"].(map[string]any)
	if metaNum(t, settings, "maxBytes") == 0 {
		t.Fatalf("defaults lost maxBytes: %v", settings)
	}

	upd := metaMustRun(t, "update_analysis_settings", metaTestArg(t, map[string]any{
		"maxBytes": 4096, "minString": 3, "deep": true,
	}))
	after, _ := upd["settings"].(map[string]any)
	if metaNum(t, after, "maxBytes") != 4096 || metaNum(t, after, "minString") != 3 {
		t.Fatalf("update did not persist: %v", after)
	}
	back := metaMustRun(t, "inspect_analysis_settings", state)
	if metaStr(t, back, "source") != "config" {
		t.Fatalf("inspect after update source = %v", back["source"])
	}

	if _, err := metaTestRun(t, "update_analysis_settings", metaTestArg(t, map[string]any{"maxBytes": 0})); err == nil {
		t.Fatal("update accepted maxBytes=0")
	}

	if err := os.WriteFile(filepath.Join(state, "config.json"), []byte(`{"kind":"someone.else/1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := metaTestRun(t, "inspect_analysis_settings", state); err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("foreign config.json: want state conflict, got %v", err)
	}
}

func TestMetaLedgerAndCoverage(t *testing.T) {
	state := metaTestState(t)
	pe := metaManagedPE(t)
	other := writeTemp(t, "padded.dll", append(metaReadFile(t, pe), '\n'))

	first := metaMustRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{"file": pe, "state": state}))
	if metaBool(t, first, "replaced") {
		t.Fatalf("first ledger should not be a replacement: %v", first)
	}
	ledgerFile := metaStr(t, first, "obligations_file")
	var disk map[string]any
	if err := json.Unmarshal(metaReadFile(t, ledgerFile), &disk); err != nil {
		t.Fatalf("obligations.json: %v", err)
	}
	if disk["kind"] != "lrecon.obligations/1" || disk["sha256"] == "" {
		t.Fatalf("ledger envelope = %v", disk)
	}

	again := metaMustRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{"file": pe, "state": state}))
	if !metaBool(t, again, "replaced") {
		t.Fatalf("same artifact should replace in place: %v", again)
	}

	// Different artifact in the same ledger is a conflict, not a silent clobber.
	_, err := metaTestRun(t, "build_reconstruction_obligation_ledger", metaTestArg(t, map[string]any{"file": other, "state": state}))
	if err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("different artifact: want state conflict, got %v", err)
	}

	cov := metaMustRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{
		"resolved":   []string{"main", "init"},
		"unresolved": []map[string]any{{"symbol": "parse", "reason": "cff"}, {"symbol": "emit", "reason": "cff"}},
	}))
	c, _ := cov["coverage"].(map[string]any)
	if metaNum(t, c, "total") != 4 || metaNum(t, c, "resolved") != 2 {
		t.Fatalf("coverage = %v", c)
	}
	if pct, _ := c["percent"].(float64); pct < 49 || pct > 51 {
		t.Fatalf("coverage percent = %v, want 50", c["percent"])
	}
	if _, err := metaTestRun(t, "evaluate_reconstruction_coverage", metaTestArg(t, map[string]any{})); err == nil {
		t.Fatal("coverage with no input reported success")
	}
}

func TestMetaEnvironmentBundle(t *testing.T) {
	metaTestState(t)
	pe := metaManagedPE(t)

	first := metaMustRun(t, "export_environment_bundle", pe)
	if !metaBool(t, first, "deterministic") || metaNum(t, first, "bundle_size") == 0 {
		t.Fatalf("bundle result = %v", first)
	}
	dest := metaStr(t, first, "bundle")
	second := metaMustRun(t, "export_environment_bundle", pe)
	if metaStr(t, second, "bundle_sha256") != metaStr(t, first, "bundle_sha256") {
		t.Fatalf("two exports of the same artifact differ: %v vs %v", first["bundle_sha256"], second["bundle_sha256"])
	}

	f, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	names := map[string]bool{}
	tr := tar.NewReader(f)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		names[h.Name] = true
	}
	if !names["manifest.json"] {
		t.Fatalf("tar has no manifest.json: %v", names)
	}
	if !names["files/"+filepath.Base(pe)] {
		t.Fatalf("tar has no artifact copy: %v", names)
	}
}

func TestMetaEvidenceBundle(t *testing.T) {
	metaTestState(t)
	pe := metaManagedPE(t)

	exp := metaMustRun(t, "export_evidence_bundle", pe)
	file := metaStr(t, exp, "bundle_file")
	bundle, _ := exp["bundle"].(map[string]any)
	if bundle == nil || bundle["sha256"] == "" {
		t.Fatalf("evidence bundle = %v", exp)
	}

	got := metaMustRun(t, "get_evidence_bundle", file)
	if !metaBool(t, got, "verified") {
		t.Fatalf("get did not verify: %v", got)
	}

	imp := metaMustRun(t, "import_evidence_bundle", metaTestArg(t, map[string]any{
		"file": file, "expect": pe,
	}))
	if !metaBool(t, imp, "artifact_match") || !metaBool(t, imp, "size_match") {
		t.Fatalf("import of the same artifact = %v", imp)
	}

	// Drift: the artifact changed after the bundle was taken.
	if err := os.WriteFile(pe, append(metaReadFile(t, pe), 0x00), 0o644); err != nil {
		t.Fatal(err)
	}
	drift := metaMustRun(t, "import_evidence_bundle", metaTestArg(t, map[string]any{"file": file, "expect": pe}))
	if metaBool(t, drift, "artifact_match") {
		t.Fatalf("import missed the drift: %v", drift)
	}
	if s := metaStr(t, drift, "drift"); s == "" {
		t.Fatalf("import reported no drift reason: %v", drift)
	}

	// Tamper: flipping bundle bytes must break the attestation.
	raw := metaReadFile(t, file)
	i := bytes.Index(raw, []byte(`"symbols"`))
	if i < 0 {
		t.Fatal("exported bundle has no symbols field to tamper: the bundle shape changed")
	}
	raw[i+2] = 'X'
	if err := os.WriteFile(file, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := metaTestRun(t, "get_evidence_bundle", file); err == nil || !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("tampered bundle: want attestation error, got %v", err)
	}
}

// TestMetaEvidenceBundleCapSpillsBesideNothing pins the read-only contract of
// get_evidence_bundle: a bundle over the in-line cap is spilled to a temp file,
// so the run still leaves the target's directory untouched (-o is refused for
// this op, so nothing may be written beside the bundle either).
func TestMetaEvidenceBundleCapSpillsBesideNothing(t *testing.T) {
	metaTestState(t)
	pe := metaManagedPE(t)
	exp := metaMustRun(t, "export_evidence_bundle", pe)
	file := metaStr(t, exp, "bundle_file")

	t.Setenv("LRECON_BUNDLE_CAP_BYTES", "64")
	got := metaMustRun(t, "get_evidence_bundle", file)
	if !metaBool(t, got, "verified") || metaBool(t, got, "incomplete") {
		t.Fatalf("over-cap answer must stay verified and complete: %v", got)
	}
	if got["coverage"] != "complete-in-file" {
		t.Fatalf("over-cap coverage = %v", got["coverage"])
	}
	dst := metaStr(t, got, "written_to")
	if dst == "" {
		t.Fatalf("over-cap bundle has no written_to: %v", got)
	}
	defer os.Remove(dst)
	if filepath.Dir(dst) == filepath.Dir(file) {
		t.Fatalf("bundle spilled into the target directory: %s", dst)
	}
	if _, err := os.Stat(file + ".bundle.json"); !os.IsNotExist(err) {
		t.Fatalf("a file appeared beside the bundle: %v", err)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if metaNum(t, got, "bytes") != len(b) {
		t.Fatalf("bytes = %v, spilled file is %d bytes", got["bytes"], len(b))
	}
	var spilled map[string]any
	if err := json.Unmarshal(b, &spilled); err != nil {
		t.Fatalf("spilled bundle is not the answer: %v", err)
	}
	if spilled["bundle_file"] != file || spilled["bundle"] == nil {
		t.Fatalf("spilled bundle lost its content: bundle_file=%v", spilled["bundle_file"])
	}
}

func TestMetaVerifyReconstruction(t *testing.T) {
	raw := []byte("0123456789abcdef")
	path := writeTemp(t, "bytes.bin", raw)

	ok := metaMustRun(t, "verify_reconstruction", metaTestArg(t, map[string]any{
		"file": path,
		"claims": []map[string]any{
			{"offset": 0, "length": 4, "expect": metaHex(raw[:4])},
			{"offset": 12, "length": 4, "expect": metaHex(raw[12:16])},
		},
	}))
	if !metaBool(t, ok, "verified") || metaNum(t, ok, "matched") != 2 {
		t.Fatalf("matching claims = %v", ok)
	}

	bad := metaMustRun(t, "verify_reconstruction", metaTestArg(t, map[string]any{
		"file":   path,
		"claims": []map[string]any{{"offset": 2, "length": 4, "expect": "deadbeef"}},
	}))
	if metaBool(t, bad, "verified") || metaNum(t, bad, "mismatched") != 1 {
		t.Fatalf("mismatching claim = %v", bad)
	}
	if _, err := metaTestRun(t, "verify_reconstruction", metaTestArg(t, map[string]any{"file": path})); err == nil {
		t.Fatal("verify_reconstruction accepted a job with no claims")
	}
}

func TestMetaInspectView(t *testing.T) {
	pe := metaManagedPE(t)
	for view, key := range map[string]string{
		"digest": "text", "json": "json", "symbols": "symbols",
		"notes": "notes", "skipped": "skipped", "raw": "hex",
	} {
		m := metaMustRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": pe, "view": view}))
		if m["kind"] == nil || m["kind"] == "" {
			t.Fatalf("view %s lost the digest kind: %v", view, m)
		}
		if _, ok := m[key]; !ok {
			t.Fatalf("view %s missing %q: %v", view, key, m)
		}
	}
	if _, err := metaTestRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": pe, "view": "nope"})); err == nil || !strings.Contains(err.Error(), "view") {
		t.Fatalf("unknown view: got %v", err)
	}
}

func TestMetaCompareArtifacts(t *testing.T) {
	old := buildTablesPE(t, managedTablesFixture(t))
	if b, err := json.Marshal(probeFixture(t, old)); err == nil {
		saved := writeTemp(t, "old.digest.json", b)
		same := metaMustRun(t, "compare_artifacts", metaTestArg(t, map[string]any{"old": saved, "new": old}))
		if !metaBool(t, same, "identical") || metaNum(t, same, "count") != 0 {
			t.Fatalf("digest vs artifact should be identical: %v", same)
		}
	}

	// A changed artifact must surface as a structured change list.
	different := writeTemp(t, "padded.dll", append(metaReadFile(t, old), '\n'))
	diff := metaMustRun(t, "compare_artifacts", metaTestArg(t, map[string]any{"old": old, "new": different}))
	if metaNum(t, diff, "count") == 0 {
		t.Fatalf("compare found no changes: %v", diff)
	}
	changes, _ := diff["changes"].([]any)
	first, _ := changes[0].(map[string]any)
	if first["path"] == nil || first["path"] == "" {
		t.Fatalf("change has no path: %v", first)
	}
	if _, ok := first["before"]; !ok {
		t.Fatalf("change has no before value: %v", first)
	}

	if _, err := metaTestRun(t, "compare_artifacts", metaTestArg(t, map[string]any{"old": old})); err == nil {
		t.Fatal("compare_artifacts accepted a single side")
	}
}

func TestMetaCompareApplicationVersionsAndBehavior(t *testing.T) {
	old := buildTablesPE(t, managedTablesFixture(t))
	next := writeTemp(t, "next.bin", []byte("not the same application"))

	app := metaMustRun(t, "compare_application_versions", metaTestArg(t, map[string]any{"old": old, "new": next}))
	if metaNum(t, app, "count") == 0 || metaStr(t, app, "verdict") == "" {
		t.Fatalf("application comparison = %v", app)
	}

	beh := metaMustRun(t, "find_changed_behavior", metaTestArg(t, map[string]any{"old": old, "new": next}))
	if metaNum(t, beh, "count") == 0 {
		t.Fatalf("behavior comparison = %v", beh)
	}
	kinds, _ := beh["by_kind"].(map[string]any)
	if len(kinds) == 0 {
		t.Fatalf("behaviors were not classified: %v", beh)
	}
	if _, ok := kinds["other"]; ok {
		t.Fatalf("behavior comparison leaked the catch-all kind: %v", kinds)
	}
	// Every reported behavior is counted exactly once under a real label.
	total := 0
	for kind, raw := range kinds {
		n, ok := raw.(float64)
		if !ok || n <= 0 {
			t.Fatalf("by_kind[%s] = %v, want a positive count", kind, raw)
		}
		total += int(n)
	}
	if total != int(metaNum(t, beh, "count")) {
		t.Fatalf("by_kind total %d != count %v", total, beh["count"])
	}
}

func TestMetaCompareBundles(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	for _, dir := range []string{a, b} {
		if err := os.WriteFile(filepath.Join(dir, "same.txt"), []byte("same"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for dir, body := range map[string]string{a: "one", b: "two"} {
		if err := os.WriteFile(filepath.Join(dir, "changed.txt"), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a, "old-only.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(b, "new-only.txt"), []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := metaMustRun(t, "compare_bundles", metaTestArg(t, map[string]any{"old": a, "new": b}))
	if metaNum(t, m, "added") != 1 || metaNum(t, m, "removed") != 1 || metaNum(t, m, "changed") != 1 {
		t.Fatalf("bundle diff counts = %v", m)
	}
	members, _ := m["changes"].([]any)
	if len(members) != 3 {
		t.Fatalf("changes = %v", m["changes"])
	}
	for _, raw := range members {
		mem, _ := raw.(map[string]any)
		if mem["name"] == "same.txt" {
			t.Fatalf("identical member reported as a change: %v", mem)
		}
	}
}

// metaZip builds a zip fixture from name->bytes pairs.
func metaZip(t *testing.T, name string, files map[string][]byte) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for n, b := range files {
		w, err := zw.Create(n)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return writeTemp(t, name, buf.Bytes())
}

func TestMetaApplicationGraphs(t *testing.T) {
	pe := metaManagedPE(t)
	managed := metaMustRun(t, "project_managed_application_graph", pe)
	nodes, _ := managed["nodes"].([]any)
	var found bool
	for _, raw := range nodes {
		n, _ := raw.(map[string]any)
		if strings.Contains(fmt.Sprint(n["name"]), "Acme.Core.Widget") {
			found = true
		}
	}
	if !found {
		t.Fatalf("managed graph lost the fixture type: %v", nodes)
	}

	hap := metaZip(t, "app.hap", map[string][]byte{
		"module.json":                []byte(`{"app":{"bundleName":"com.acme.demo","versionName":"1.2.3"},"module":{"name":"entry","mainElement":"EntryAbility","abilities":[{"name":"EntryAbility"}]}}`),
		"ets/modules.abc":            []byte("PANDA\x00\x00\x00\x00"),
		"libs/arm64-v8a/libentry.so": []byte("\x7fELF"),
	})
	harmony := metaMustRun(t, "project_harmony_application_graph", hap)
	hnodes, _ := harmony["nodes"].([]any)
	if len(hnodes) == 0 || !strings.Contains(fmt.Sprint(harmony["nodes"]), "entry") {
		t.Fatalf("harmony graph = %v", harmony["nodes"])
	}

	if _, err := metaTestRun(t, "project_android_application_graph", pe); err == nil {
		t.Fatal("android graph accepted a PE with no manifest")
	}
	if _, err := metaTestRun(t, "project_apple_application_graph", pe); err == nil {
		t.Fatal("apple graph accepted a PE with no plist keys")
	}
}

// TestProjectAppleGraphNoDanglingEdges: asar.unpacked is a sibling of app.asar
// and can outlive it (archive deleted, the addon directory left behind). With no
// app.asar node in the graph the edge has to hang off the bundle, otherwise it
// names a node the answer never describes.
func TestProjectAppleGraphNoDanglingEdges(t *testing.T) {
	digest, err := json.Marshal(map[string]any{
		"contract_version":     1,
		"kind":                 "desktop-app",
		"plist_key":            []string{"CFBundleName"},
		"minos":                "14.0",
		"asar_files":           0,
		"asar_unpacked_native": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := metaMustRun(t, "project_apple_application_graph", writeTemp(t, "digest.json", digest))
	nodes, _ := res["nodes"].([]any)
	have := map[string]bool{}
	for _, raw := range nodes {
		n, _ := raw.(map[string]any)
		have[fmt.Sprint(n["name"])] = true
	}
	edges, _ := res["edges"].([]any)
	if len(edges) == 0 {
		t.Fatalf("graph has no edges: %v", res)
	}
	for _, raw := range edges {
		e, _ := raw.(map[string]any)
		for _, end := range []string{fmt.Sprint(e["from"]), fmt.Sprint(e["to"])} {
			if !have[end] {
				t.Fatalf("edge %v -> %v names %q, which is not a node: %v", e["from"], e["to"], end, nodes)
			}
		}
	}
}

func TestMetaImportManagedReconstruction(t *testing.T) {
	state := t.TempDir()
	pe := metaManagedPE(t)

	m := metaMustRun(t, "import_managed_reconstruction", metaTestArg(t, map[string]any{"file": pe, "state": state}))
	typesFile := filepath.Join(state, "types.json")
	var disk map[string]any
	if err := json.Unmarshal(metaReadFile(t, typesFile), &disk); err != nil {
		t.Fatalf("types.json: %v", err)
	}
	if disk["kind"] != "lrecon.managed/1" || disk["sha256"] == "" {
		t.Fatalf("types.json envelope = %v", disk)
	}
	entries, err := os.ReadDir(filepath.Join(state, "methods"))
	if err != nil {
		t.Fatalf("methods dir: %v", err)
	}
	if int(metaNum(t, m, "methods")) != len(entries) || len(entries) == 0 {
		t.Fatalf("methods dir has %d files, op reported %v", len(entries), m["methods"])
	}
	if metaNum(t, m, "types") == 0 {
		t.Fatalf("import reported no types: %v", m)
	}

	// Same artifact again is idempotent, a different one is a conflict.
	metaMustRun(t, "import_managed_reconstruction", metaTestArg(t, map[string]any{"file": pe, "state": state}))
	other := writeTemp(t, "padded2.dll", append(metaReadFile(t, pe), '\n'))
	if _, err := metaTestRun(t, "import_managed_reconstruction", metaTestArg(t, map[string]any{"file": other, "state": state})); err == nil || !strings.Contains(err.Error(), "state conflict") {
		t.Fatalf("different artifact into a populated tree: want state conflict, got %v", err)
	}
}

// metaFakeHeadless writes a stand-in analyzeHeadless that reproduces Meta.java's
// per-mode output keys and refuses a mode Meta.java does not implement. That
// refusal is the point: a Go side passing a mode the script lacks ("PRE" was
// passed for months) fails here instead of in the field.
func metaFakeHeadless(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "analyzeHeadless")
	script := `#!/bin/sh
prev=""; a=""
for x in "$@"; do
  [ "$prev" = "Meta.java" ] && a="$x"
  prev="$x"
done
out=$(sed -n 's/^out=//p' "$a")
mode=$(sed -n 's/^mode=//p' "$a")
addr=$(sed -n 's/^address=//p' "$a")
text=$(sed -n 's/^text=//p' "$a")
name=$(sed -n 's/^name=//p' "$a")
count=$(sed -n 's/^count=//p' "$a")
case "$mode" in
PLATE|PRE|EOL|ANNOTATE)
  printf '{"address":"%s","comment":"%s","stored":"%s"}\n' "$addr" "$text" "$text" > "$out" ;;
LABEL)
  printf '{"address":"%s","name":"%s"}\n' "$addr" "$name" > "$out" ;;
LABELS)
  n=$(sed -n 's/^count=//p' "$a"); json=""; i=0
  while [ "$i" -lt "${n:-0}" ]; do
    la=$(sed -n "s/^label\.$i\.address=//p" "$a")
    ln=$(sed -n "s/^label\.$i\.name=//p" "$a")
    [ -n "$json" ] && json="$json,"
    json="$json{\"address\":\"$la\",\"name\":\"$ln\"}"
    i=$((i+1))
  done
  printf '{"labels":[%s]}\n' "$json" > "$out" ;;
UNKNOWN)
  printf '{"ranges":[],"bytes":0,"count":0}\n' > "$out" ;;
TRACE)
  printf '{"address":"%s","function":"f","callers":[],"count":0}\n' "$addr" > "$out" ;;
*)
  printf '{"error":"java.lang.IllegalStateException: unknown mode %s"}\n' "$mode" > "$out" ;;
esac
`
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestMetaGhidraOps(t *testing.T) {
	t.Setenv("LRECON_ANALYZEHEADLESS", metaFakeHeadless(t))
	// The meta route shares the route-G project cache now, so a fake headless
	// must never pin an entry in the real user cache.
	t.Setenv("LRECON_GHIDRA_CACHE", t.TempDir())
	// The kind gate refuses bytecode before Ghidra, so the plumbing fixture has
	// to be a native image: a managed PE never reaches the fake headless.
	pe := buildTarget(t, "windows", "amd64", "meta.exe")

	cases := []struct {
		name  string
		job   map[string]any
		check func(t *testing.T, m map[string]any)
	}{
		{"annotate_native_function", map[string]any{"address": "0x1400", "text": "decrypts the cache"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "comment"); got != "decrypts the cache" {
				t.Fatalf("comment = %q", got)
			}
			if got := metaStr(t, m, "stored"); got != "decrypts the cache" {
				t.Fatalf("stored = %q", got)
			}
		}},
		{"comment", map[string]any{"address": "0x1400", "text": "plate note"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "stored"); got != "plate note" {
				t.Fatalf("stored = %q", got)
			}
		}},
		{"set_comment", map[string]any{"address": "0x1400", "text": "pre note"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "comment"); got != "pre note" {
				t.Fatalf("comment = %q", got)
			}
		}},
		{"inline_comment", map[string]any{"address": "0x1400", "text": "eol note"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "address"); got != "0x1400" {
				t.Fatalf("address = %q", got)
			}
		}},
		{"set_inline_comment", map[string]any{"address": "0x1400", "text": "inline note"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "stored"); got != "inline note" {
				t.Fatalf("stored = %q", got)
			}
		}},
		{"list_unknowns", map[string]any{}, func(t *testing.T, m map[string]any) {
			if metaNum(t, m, "count") != 0 || metaNum(t, m, "bytes") != 0 {
				t.Fatalf("empty project reported coverage: %v", m)
			}
			if _, ok := m["ranges"].([]any); !ok {
				t.Fatalf("ranges is not a list: %v", m)
			}
		}},
		{"set_address_name", map[string]any{"address": "0x1400", "name": "decrypt_cache"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "name"); got != "decrypt_cache" {
				t.Fatalf("name = %q", got)
			}
		}},
		{"set_addresses_names", map[string]any{"labels": []map[string]any{{"address": "0x1400", "name": "a"}, {"address": "0x1410", "name": "b"}}}, func(t *testing.T, m map[string]any) {
			labels, _ := m["labels"].([]any)
			if len(labels) != 2 {
				t.Fatalf("labels = %v", m["labels"])
			}
			last, _ := labels[1].(map[string]any)
			if got := metaStr(t, last, "name"); got != "b" {
				t.Fatalf("label[1].name = %q", got)
			}
		}},
		{"trace_application_feature", map[string]any{"address": "0x1400"}, func(t *testing.T, m map[string]any) {
			if got := metaStr(t, m, "function"); got == "" {
				t.Fatalf("trace named no function: %v", m)
			}
			if _, ok := m["callers"].([]any); !ok {
				t.Fatalf("callers is not a list: %v", m)
			}
		}},
	}
	for _, tc := range cases {
		job := map[string]any{"file": pe}
		maps.Copy(job, tc.job)
		tc.check(t, metaMustRun(t, tc.name, metaTestArg(t, job)))
	}

	// Ghidra failures must surface as errors, not silent successes.
	if _, err := metaTestRun(t, "comment", metaTestArg(t, map[string]any{"file": pe})); err == nil {
		t.Fatal("comment without an address was accepted")
	}
}

// TestMetaGhidraReusesOneAnalysis: annotate_native_function and
// set_inline_comment used to import the same binary from scratch on every call
// (~50 s each, no cache at all). They now share the route-G project, so the
// second op must reopen the analysed program instead of importing again.
func TestMetaGhidraReusesOneAnalysis(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "argv.log")
	shim := filepath.Join(dir, "analyzeHeadless")
	script := fmt.Sprintf(`case " $* " in
  *" -process "*) echo process >> '%[1]s' ;;
  *" -import "*) echo import >> '%[1]s' ;;
esac
prev=""; args=""
for a in "$@"; do
  [ "$prev" = "Meta.java" ] && args="$a"
  prev="$a"
done
out=$(sed -n 's/^out=//p' "$args")
addr=$(sed -n 's/^address=//p' "$args")
printf '{"address":"%%s","comment":"note","stored":"note"}\n' "$addr" > "$out"
`, logPath)
	if err := os.WriteFile(shim, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_GHIDRA_CACHE", filepath.Join(dir, "cache"))
	target := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(target, []byte("same bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	job := metaJob{File: target}
	extra := map[string]string{"address": "0x1400", "text": "note"}
	for i := range 2 {
		if _, err := metaGhidraRun(shim, job, "ANNOTATE", extra); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(b), "import"); got != 1 {
		t.Fatalf("imports = %d (%q); want exactly one: the analysis belongs to the binary", got, b)
	}
	if got := strings.Count(string(b), "process"); got != 1 {
		t.Fatalf("reopens = %d (%q); want exactly one", got, b)
	}
}

// TestMetaGhidraModesMatchScript keeps the Go side and Meta.java from drifting:
// every mode an op asks for must be a mode the script handles.
func TestMetaGhidraModesMatchScript(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	asked := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range metaModeAsk.FindAllStringSubmatch(string(b), -1) {
			asked[m[1]] = name
		}
	}
	handled := map[string]bool{}
	for _, m := range metaModeHandled.FindAllStringSubmatch(metaGhidraScript, -1) {
		handled[m[1]] = true
	}
	if len(asked) < 8 {
		t.Fatalf("found only %d modes in the Go side: %v", len(asked), asked)
	}
	for mode, file := range asked {
		if !handled[mode] {
			t.Fatalf("%s asks Meta.java for mode %q, which the script does not handle", file, mode)
		}
	}
}

var (
	metaModeAsk     = regexp.MustCompile(`metaGhidraOp\(job, "([A-Z]+)"`)
	metaModeHandled = regexp.MustCompile(`mode\.equals\("([A-Z]+)"\)`)
)

func TestMetaTraceFeature(t *testing.T) {
	pe := metaManagedPE(t)
	secs, err := metaSectionTable(pe)
	if err != nil || len(secs) == 0 {
		t.Fatalf("section table: %v", err)
	}

	byString := map[string]any{"file": pe, "string": "Widget"}
	m := metaMustRun(t, "trace_feature", metaTestArg(t, byString))
	if metaNum(t, m, "count") == 0 {
		t.Fatalf("string search found no Widget reference: %v", m)
	}

	var sec metaSection
	for _, s := range secs {
		if s.Name == ".text" {
			sec = s
			break
		}
	}
	if sec.Name == "" {
		t.Fatal("fixture has no .text section: the fixture builder changed")
	}
	byAddr := metaMustRun(t, "trace_feature", metaTestArg(t, map[string]any{
		"file": pe, "address": fmt.Sprintf("%#x", sec.Addr+8),
	}))
	feature, _ := byAddr["feature"].(map[string]any)
	if metaStr(t, byAddr, "mode") != "address" || metaStr(t, feature, "section") != sec.Name {
		t.Fatalf("address mode = %v", byAddr)
	}
}

func TestMetaCorrelateStaticAndRuntime(t *testing.T) {
	// A PE carries no LC_UUID, so this test used to skip on every run and
	// hide the op's body from coverage. A thin Mach-O is the shape that keeps
	// the uuid at the digest's top level.
	const wantUUID = "D4B9C2DB99983233A2BE5577126F0C8D"
	image := writeTemp(t, "demo", thinUUIDMachO(uuidFromHex(wantUUID)))
	d := probeFixture(t, image)
	if d.UUID != wantUUID {
		t.Fatalf("fixture uuid = %q, want %q (kind %s)", d.UUID, wantUUID, d.Kind)
	}
	ips := writeTemp(t, "crash.ips", fmt.Appendf(nil,
		`{"name":"report","timestamp":"2026-01-01 00:00:00.00 +0000","app_name":"Demo"}`+"\n"+
			`{"procName":"Demo","usedImages":[{"name":"Demo","uuid":"%s","arch":"x86_64"}]}`, d.UUID))

	m := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": image, "crash": ips}))
	runtime, _ := m["runtime"].(map[string]any)
	images, _ := runtime["images"].([]any)
	if len(images) != 1 {
		t.Fatalf("correlation images = %v", runtime["images"])
	}
	img, _ := images[0].(map[string]any)
	if img["match"] != true {
		t.Fatalf("live UUID did not match the digest: %v", img)
	}
	if got := metaStr(t, m, "verdict"); !strings.Contains(got, "static image matches the crashing image uuid") {
		t.Fatalf("verdict = %q", got)
	}

	different := writeTemp(t, "other.ips", fmt.Appendf(nil,
		`{"name":"report","timestamp":"2026-01-01 00:00:00.00 +0000","app_name":"Demo"}`+"\n"+
			`{"procName":"Demo","usedImages":[{"name":"Demo","uuid":"00000000000000000000000000000000","arch":"x86_64"}]}`))
	mm := metaMustRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": image, "crash": different}))
	if got := metaStr(t, mm, "verdict"); !strings.Contains(got, "different build") {
		t.Fatalf("mismatch verdict = %q", got)
	}

	if _, err := metaTestRun(t, "correlate_static_and_runtime", metaTestArg(t, map[string]any{"file": image})); err == nil || !strings.Contains(err.Error(), `needs "crash"`) {
		t.Fatalf("correlation without a crash report: %v", err)
	}
}

func TestMetaRegistry(t *testing.T) {
	want := map[string]string{
		"annotate_native_function": "G", "binary_session": "L", "build_reconstruction_obligation_ledger": "L",
		"close_binary": "L", "comment": "G", "compare_application_versions": "L", "compare_artifacts": "L",
		"compare_bundles": "L", "correlate_static_and_runtime": "L", "evaluate_reconstruction_coverage": "L",
		"export_environment_bundle": "L", "export_evidence_bundle": "L", "find_changed_behavior": "L",
		"get_evidence_bundle": "L", "import_evidence_bundle": "L", "import_managed_reconstruction": "L",
		"inline_comment": "G", "inspect_analysis_settings": "L", "inspect_analysis_view": "L",
		"list_bookmarks": "L", "list_unknowns": "G", "project_android_application_graph": "L",
		"project_apple_application_graph": "L", "project_harmony_application_graph": "L",
		"project_managed_application_graph": "L", "record_unknown": "L", "set_address_name": "G",
		"set_addresses_names": "G", "set_bookmark": "L", "set_comment": "G", "set_inline_comment": "G",
		"trace_application_feature": "G", "trace_feature": "L", "unset_bookmark": "L",
		"update_analysis_settings": "L", "update_unknown": "L", "verify_reconstruction": "L",
		"verify_unknown_resolution": "L",
	}
	if len(want) != 38 {
		t.Fatalf("test table lists %d META items, want 38", len(want))
	}
	for name, route := range want {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("META op %q is not registered", name)
		}
		if o.route != route {
			t.Fatalf("%s: route = %q, want %q", name, o.route, route)
		}
		if o.desc == "" {
			t.Fatalf("%s: empty description", name)
		}
	}
}

func TestMetaDiagPrefersErrors(t *testing.T) {
	log := "INFO progress\nMeta.java:69: error: cannot find symbol\nnoise\nERROR REPORT SCRIPT ERROR\nstack\n"
	if got := metaDiag(log, 6); !strings.Contains(got, "Meta.java:69: error:") || strings.Contains(got, "INFO progress") {
		t.Fatalf("metaDiag = %q, want the error line, not the progress line", got)
	}
	if got := metaDiag("nothing wrong\nlast line\n", 1); got != "last line" {
		t.Fatalf("metaDiag fallback = %q, want the tail when no error line exists", got)
	}
}

// TestMetaEnvironmentBundleRejectsMemberCollision: two inputs with the same base
// name would land on one tar member, so the second would shadow the first on
// extraction while the manifest still listed both. The bundle is refused.
func TestMetaEnvironmentBundleRejectsMemberCollision(t *testing.T) {
	metaTestState(t)
	pe := metaManagedPE(t)
	a := filepath.Join(t.TempDir(), "tool.conf")
	b := filepath.Join(t.TempDir(), "tool.conf")
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, []byte("x="+p), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	job := metaTestArg(t, map[string]any{"file": pe, "include": []string{a, b}})
	_, err := metaTestRun(t, "export_environment_bundle", job)
	if err == nil || !strings.Contains(err.Error(), "both export as files/tool.conf") {
		t.Fatalf("collision error = %v, want files/tool.conf named", err)
	}

	// Distinct base names still bundle.
	c := filepath.Join(t.TempDir(), "other.conf")
	if err := os.WriteFile(c, []byte("y"), 0o644); err != nil {
		t.Fatal(err)
	}
	job = metaTestArg(t, map[string]any{"file": pe, "include": []string{a, c}})
	m := metaMustRun(t, "export_environment_bundle", job)
	if m["deterministic"] != true {
		t.Fatalf("distinct includes = %v", m)
	}
}

// TestCapAnswerSpillsEveryOpAnswer pins item 404: the in-line answer cap guards
// every op answer, not only Ghidra ones, and the pointer keeps the target.
func TestCapAnswerSpillsEveryOpAnswer(t *testing.T) {
	t.Setenv("LRECON_ANSWER_CAP_BYTES", "64")
	big := map[string]any{
		"op":     "binary_overview",
		"target": "/tmp/target.bin",
		"result": map[string]any{"notes": strings.Repeat("a", 200)},
	}
	got := capAnswer(big)
	if got["truncated"] != true {
		t.Fatalf("over-cap answer must be truncated: %v", got)
	}
	dst := metaStr(t, got, "written_to")
	if dst == "" {
		t.Fatalf("over-cap answer has no written_to: %v", got)
	}
	defer os.Remove(dst)
	if got["target"] != "/tmp/target.bin" {
		t.Fatalf("pointer envelope lost the target: %v", got)
	}
	b, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) <= 64 {
		t.Fatalf("spilled answer is %d bytes, want the full over-cap answer", len(b))
	}
}

// TestCapAnswerCountsWrappedMapRecords: the op wrapper keeps the real records
// under "result", so a spilled pointer over a map-shaped answer must not say
// count 0 on a file holding thousands of them.
func TestCapAnswerCountsWrappedMapRecords(t *testing.T) {
	t.Setenv("LRECON_ANSWER_CAP_BYTES", "64")
	refs := make([]any, 0, 20)
	for range 20 {
		refs = append(refs, strings.Repeat("f", 20))
	}
	big := map[string]any{
		"op":     "list_names",
		"target": "/tmp/target.bin",
		"result": map[string]any{"names": refs},
	}
	got := capAnswer(big)
	if got["truncated"] != true {
		t.Fatalf("over-cap answer must be truncated: %v", got)
	}
	if dst, _ := got["written_to"].(string); dst != "" {
		defer os.Remove(dst)
	}
	if n, _ := got["count"].(int); n != len(refs) {
		t.Fatalf("count = %v, want %d records from the wrapped result", got["count"], len(refs))
	}
}

// TestCapAnswerCountsTypedSliceRows: ops answer with their own struct slices,
// which the old record walker ([]any / map[string]any only) could not see, so a
// spill of 15 KB said count 0. The count must read what the file holds.
func TestCapAnswerCountsTypedSliceRows(t *testing.T) {
	t.Setenv("LRECON_ANSWER_CAP_BYTES", "64")
	rows := make([]nativeAPI, 30)
	for i := range rows {
		rows[i] = nativeAPI{Name: strings.Repeat("n", 20), Basis: "test"}
	}
	big := map[string]any{
		"op":     "inspect_native_api",
		"target": "/tmp/target.bin",
		"result": map[string]any{"format": "elf", "imports": len(rows), "rows": rows},
	}
	got := capAnswer(big)
	if got["truncated"] != true {
		t.Fatalf("over-cap answer must be truncated: %v", got)
	}
	if dst, _ := got["written_to"].(string); dst != "" {
		defer os.Remove(dst)
	}
	if n, _ := got["count"].(int); n != len(rows) {
		t.Fatalf("count = %v, want %d typed rows in the spilled file", got["count"], len(rows))
	}
}

// TestScannedAtRecordsExplicitSpan: a read at an explicit offset is its own
// span, so a random-access read is not attributed to the sequential cursor.
func TestScannedAtRecordsExplicitSpan(t *testing.T) {
	var d Digest
	d.FileSize = 4096
	d.scanned(64) // cursor: [0,64)
	d.scannedAt(2048, 32)
	if d.BytesScanned != 96 {
		t.Fatalf("bytes_scanned = %d, want 96", d.BytesScanned)
	}
	d.scannedAt(2050, 10) // overlaps the previous explicit span
	if d.BytesScanned != 96 {
		t.Fatalf("bytes_scanned = %d, want 96 (overlap counted once)", d.BytesScanned)
	}
	d.scannedAt(4096, 16) // entirely past EOF
	if d.BytesScanned != 96 {
		t.Fatalf("bytes_scanned = %d, want 96 (past-EOF read ignored)", d.BytesScanned)
	}
	d.scannedAt(4080, 32) // clamps to the file end
	if d.BytesScanned != 112 {
		t.Fatalf("bytes_scanned = %d, want 112 (clamped span)", d.BytesScanned)
	}
}
