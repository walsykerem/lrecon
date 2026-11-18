package main

// Tur 7, bucket 19: the list_* family answers honestly.
//
// One table drives every list_* op of this bucket through the real built CLI in
// a hermetic environment (empty PATH, temp HOME and LRECON_STATE), so there is
// no adb, no CDP endpoint and no session on the machine under test. The family
// contract checked for every row is the same: exit 0 with rows that can be
// checked against the machine or against the state file that was seeded, or
// exit 2 with the typed refusal envelope (contract_version/op/kind/error and no
// payload key at all). A fabricated device, session, document or unit has no
// shape to hide in: either it is cross-checked against os.Stat/debug/macho/the
// kernel table, or it contradicts the refusal.
//
// The registry set is pinned too: list_* in ops.go must be exactly this
// bucket's eleven plus the ten other buckets' ops, so a new list_* op cannot
// appear without a row here.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
)

// t7b19Needs is the input shape the registry publishes for each op; the table
// below must feed exactly that, or the test is exercising a different call.
var t7b19Needs = map[string][]string{
	"list_adb_services":               {"device"},
	"list_architectures":              {"target"},
	"list_bookmarks":                  {},
	"list_browser_targets":            {"target"},
	"list_cutter_sessions":            {},
	"list_documents":                  {"session"},
	"list_electron_targets":           {"target"},
	"list_frida_devices":              {},
	"list_frida_processes":            {},
	"list_javascript_runtime_targets": {"target"},
	"list_jeb_units":                  {"target"},
}

// t7b19Foreign are the list_* ops that exist in the same registry but belong to
// another bucket; they are named so the set check fails on any drift.
var t7b19Foreign = []string{
	"list_adb_devices", "list_adb_directory", "list_adb_features",
	"list_adb_packages", "list_adb_processes", "list_names", "list_procedures",
	"list_segments", "list_strings", "list_unknowns",
}

type t7b19Env struct {
	home  string
	state string
	port  string // a loopback endpoint that was just closed: no CDP behind it
}

func t7b19NewEnv(t *testing.T) t7b19Env {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for a closed port: %v", err)
	}
	port := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close the loopback listener: %v", err)
	}
	return t7b19Env{home: t.TempDir(), state: t.TempDir(), port: port}
}

func (e t7b19Env) environ() []string {
	return []string{"PATH=", "HOME=" + e.home, "LRECON_STATE=" + e.state}
}

// withState is the same host with another state dir: a second call must not see
// the bookmarks or the session seeded for the first one.
func (e t7b19Env) withState(t *testing.T) t7b19Env {
	t.Helper()
	e.state = t.TempDir()
	return e
}

func t7b19Run(t *testing.T, e t7b19Env, args ...string) (map[string]any, int, string, string) {
	t.Helper()
	if buildErr != nil {
		t.Fatalf("go build failed: %v\n%s", buildErr, buildLog)
	}
	cmd := exec.Command(cliPath, args...)
	cmd.Env = e.environ()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	text := strings.TrimSpace(stdout.String())
	if text == "" {
		return nil, code, stdout.String(), stderr.String()
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(text), &m); err != nil {
		t.Fatalf("%v: stdout is not one JSON object: %v\n%s", args, err, text)
	}
	return m, code, stdout.String(), stderr.String()
}

func t7b19Result(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	r, ok := m["result"].(map[string]any)
	if !ok {
		t.Fatalf("result is %T, want a JSON object: %v", m["result"], m)
	}
	return r
}

func t7b19Arr(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	v, present := m[key]
	if !present {
		t.Fatalf("field %q missing: %v", key, m)
	}
	a, ok := v.([]any)
	if !ok {
		t.Fatalf("field %q is %T, want an array: %v", key, v, m)
	}
	return a
}

func t7b19Write(t *testing.T, path string, b []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

type t7b19Case struct {
	op     string
	target string // the CLI argument; "" when the op takes no target
	exit   int
	kind   errorKind // exit 2 only
	want   string    // exact substring of the refusal message, exit 2 only
	// forbid are payload keys a refusal must not carry: an entry named here
	// would be a row the op never measured.
	forbid []string
	// seed runs in the same env before the op, for the state an op reads.
	seed  func(t *testing.T, e t7b19Env)
	check func(t *testing.T, e t7b19Env, res map[string]any)
}

func TestTur7Bucket19ListFamilyHonesty(t *testing.T) {
	// --- registry set: this bucket's eleven, the others' ten, nothing else ---
	mine := make([]string, 0, len(t7b19Needs))
	for name := range t7b19Needs {
		mine = append(mine, name)
	}
	sort.Strings(mine)
	want := append(append([]string{}, mine...), t7b19Foreign...)
	sort.Strings(want)
	var got []string
	for _, name := range opNames() {
		if strings.HasPrefix(name, "list_") {
			got = append(got, name)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("list_* registry = %v, want %v (a new list_* op needs a row here)", got, want)
	}
	for _, name := range mine {
		if _, ok := ops[name]; !ok {
			t.Fatalf("%s is not registered", name)
		}
		if got := opNeeds(ops[name]); !reflect.DeepEqual(got, t7b19Needs[name]) {
			t.Fatalf("%s declares needs %v, want %v", name, got, t7b19Needs[name])
		}
	}

	fixtures, err := filepath.Abs("testdata/fixtures")
	if err != nil {
		t.Fatal(err)
	}
	text := t7b19Write(t, filepath.Join(t.TempDir(), "plain.txt"), []byte("not a mach-o, not a dex\n"))
	fat := filepath.Join(fixtures, "fatbin", "universal.fat")
	dex := filepath.Join(fixtures, "apk", "classes.dex")

	cases := []t7b19Case{
		{
			// No adb on PATH: the device half of this family must refuse instead
			// of reporting an empty service table the device never answered.
			op: "list_adb_services", exit: 2, kind: kindNoEngine, want: "adb",
			forbid: []string{"services", "count"},
		},
		{
			op: "list_architectures", target: fat, exit: 0,
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckArchitectures(t, res, fat)
				// A format that is not Mach-O is a refusal, not zero slices.
				m, code, _, _ := t7b19Run(t, e, "--op", "list_architectures", text)
				if code != 2 || m["kind"] != string(kindBadArg) {
					t.Fatalf("text target: exit=%d envelope=%v", code, m)
				}
				if _, ok := m["slices"]; ok {
					t.Fatalf("refused Mach-O call still carries slices: %v", m)
				}
			},
		},
		{
			op: "list_bookmarks", exit: 0,
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckBookmarks(t, e, res)
			},
		},
		{
			// Nothing listens on the closed loopback port: no target list may be
			// invented for it.
			op: "list_browser_targets", exit: 2, kind: kindNoEngine, want: "/json/list",
			forbid: []string{"targets", "count", "by_type", "browser_ws"},
		},
		{
			op: "list_cutter_sessions", exit: 0,
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckCutter(t, e, res)
			},
		},
		{
			op: "list_documents", exit: 0,
			seed: func(t *testing.T, e t7b19Env) {
				live := t7b19Write(t, filepath.Join(t.TempDir(), "live.bin"), []byte("four"))
				gone := filepath.Join(e.home, "gone.bin") // never written
				session := `{"kind":"lrecon.session/1","project":"fixtureproj","document":"` + live +
					`","cursor":0,"documents":["` + live + `","` + gone + `"]}`
				t7b19Write(t, filepath.Join(e.state, "session.json"), []byte(session))
			},
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckDocuments(t, e, res)
			},
		},
		{
			op: "list_electron_targets", exit: 2, kind: kindNoEngine, want: "/json/list",
			forbid: []string{"targets", "contexts", "verdict", "electron_isolated_world"},
		},
		{
			op: "list_frida_devices", exit: 2, kind: kindNoEngine, want: "adb",
			forbid: []string{"devices", "count"},
		},
		{
			op: "list_frida_processes", exit: 0,
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckFridaProcesses(t, res)
			},
		},
		{
			op: "list_javascript_runtime_targets", exit: 2, kind: kindNoEngine, want: "/json/list",
			forbid: []string{"targets", "count"},
		},
		{
			op: "list_jeb_units", target: dex, exit: 0,
			check: func(t *testing.T, e t7b19Env, res map[string]any) {
				t7b19CheckJebUnits(t, e, res, dex, text)
			},
		},
	}

	if len(cases) != len(mine) {
		t.Fatalf("%d table rows, %d list_* ops in the slice", len(cases), len(mine))
	}
	seen := map[string]bool{}
	for _, c := range cases {
		if seen[c.op] {
			t.Fatalf("%s has two rows: the family check must run once per op", c.op)
		}
		seen[c.op] = true
	}

	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			e := t7b19NewEnv(t)
			target := c.target
			if c.op == "list_browser_targets" || c.op == "list_electron_targets" || c.op == "list_javascript_runtime_targets" {
				target = e.port // the closed endpoint is only known at run time
			}
			if c.seed != nil {
				c.seed(t, e)
			}
			args := []string{"--op", c.op}
			if target != "" {
				args = append(args, target)
			}
			m, code, stdout, stderr := t7b19Run(t, e, args...)
			if code != c.exit {
				t.Fatalf("exit = %d, want %d; stdout=%s stderr=%s", code, c.exit, stdout, stderr)
			}
			if code != 0 && code != 2 {
				t.Fatalf("exit = %d: 0 and 2 are the only outcomes (1 is reserved for --diff)", code)
			}
			if m["op"] != c.op {
				t.Fatalf("envelope op = %v, want %s", m["op"], c.op)
			}
			if c.exit == 0 {
				if _, ok := m["error"]; ok {
					t.Fatalf("success carries an error key: %v", m)
				}
				if _, ok := m["kind"]; ok {
					t.Fatalf("success carries a refusal kind: %v", m)
				}
				c.check(t, e, t7b19Result(t, m))
				return
			}
			// Refusal shape, identical for every op in the family.
			if m["contract_version"] != float64(contractVersion) {
				t.Fatalf("contract_version = %v, want %d", m["contract_version"], contractVersion)
			}
			kind, _ := m["kind"].(string)
			if kind != string(c.kind) {
				t.Fatalf("kind = %q, want %q; envelope=%v", kind, c.kind, m)
			}
			if !t7b19KindClosed(errorKind(kind)) {
				t.Fatalf("kind %q is not in the closed set", kind)
			}
			msg, _ := m["error"].(string)
			if msg == "" || !strings.Contains(msg, c.want) {
				t.Fatalf("error = %q, want it to contain %q", msg, c.want)
			}
			if _, ok := m["result"]; ok {
				t.Fatalf("refusal carries a result payload: %v", m)
			}
			for _, key := range c.forbid {
				if _, ok := m[key]; ok {
					t.Fatalf("refusal fabricates %q: %v", key, m)
				}
			}
			if !strings.HasPrefix(stderr, "lrecon: ") {
				t.Fatalf("stderr = %q, want the lrecon: prefix", stderr)
			}
			// The same unanswerable call must answer with the same bytes.
			_, code2, stdout2, _ := t7b19Run(t, e, args...)
			if code2 != code || stdout2 != stdout {
				t.Fatalf("refusal is not deterministic: exit %d/%d\n%s\n---\n%s", code, code2, stdout, stdout2)
			}
		})
	}
}

func t7b19KindClosed(k errorKind) bool {
	return slices.Contains(kindList, k)
}

func t7b19CheckArchitectures(t *testing.T, res map[string]any, fat string) {
	t.Helper()
	if res["format"] != "fat" || res["slices"] != float64(2) {
		t.Fatalf("format/slices = %v/%v, want fat/2", res["format"], res["slices"])
	}
	rows := t7b19Arr(t, res, "architectures")
	if len(rows) != 2 {
		t.Fatalf("%d architecture rows, want 2", len(rows))
	}
	st, err := os.Stat(fat)
	if err != nil {
		t.Fatal(err)
	}
	whole, err := os.ReadFile(fat)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		arch    string
		subtype float64
		offset  float64
		size    float64
		align   float64
	}{
		{"arm64", 0, 4096, 1641330, 12},
		{"x86-64", 3, 1646592, 1698176, 12},
	}
	var covered int64
	for i, w := range want {
		r := rows[i].(map[string]any)
		if r["arch"] != w.arch || r["cpu_subtype"] != w.subtype || r["offset"] != w.offset ||
			r["size"] != w.size || r["align"] != w.align {
			t.Fatalf("slice %d = %v, want %v", i, r, w)
		}
		off := int64(w.offset)
		// The reported slice must really be a Mach-O image at that offset in the
		// file: the row is measured, not repeated from a table.
		if off < 0 || off+4 > int64(len(whole)) {
			t.Fatalf("slice %d offset %d is outside the %d-byte file", i, off, len(whole))
		}
		magic := binary.LittleEndian.Uint32(whole[off : off+4])
		if magic != 0xfeedfacf {
			t.Fatalf("slice %d at offset %d starts with %#x, not a MH_MAGIC_64 image", i, off, magic)
		}
		covered += int64(w.size)
	}
	if covered > st.Size() {
		t.Fatalf("slices cover %d bytes of a %d-byte file", covered, st.Size())
	}
}

func t7b19CheckBookmarks(t *testing.T, e t7b19Env, res map[string]any) {
	t.Helper()
	if res["exists"] != false || res["count"] != float64(0) || res["total"] != float64(0) {
		t.Fatalf("empty state: exists/count/total = %v/%v/%v, want false/0/0", res["exists"], res["count"], res["total"])
	}
	t7b19Arr(t, res, "bookmarks") // empty, but a list, not null
	if res["bookmarks_file"] != filepath.Join(e.state, "bookmarks.json") {
		t.Fatalf("bookmarks_file = %v, want the seeded state file", res["bookmarks_file"])
	}
	if _, err := os.Stat(filepath.Join(e.state, "bookmarks.json")); !os.IsNotExist(err) {
		t.Fatalf("list_bookmarks created a bookmark file it did not have: %v", err)
	}

	// A seeded file with two real rows: the answer has to be those rows and the
	// filter has to drop the one it does not match.
	seeded := `[{"file":"/a.bin","address":"0x10","note":"n1","created":"2026-01-01T00:00:00Z"},` +
		`{"file":"/b.bin","address":"0x20","note":"n2","created":"2026-01-02T00:00:00Z"}]`
	t7b19Write(t, filepath.Join(e.state, "bookmarks.json"), []byte(seeded))
	m, code, _, stderr := t7b19Run(t, e, "--op", "list_bookmarks")
	if code != 0 {
		t.Fatalf("seeded exit = %d, stderr=%s", code, stderr)
	}
	res = t7b19Result(t, m)
	if res["exists"] != true || res["count"] != float64(2) || res["total"] != float64(2) {
		t.Fatalf("seeded state: exists/count/total = %v/%v/%v, want true/2/2", res["exists"], res["count"], res["total"])
	}
	rows := t7b19Arr(t, res, "bookmarks")
	for i, want := range []map[string]string{
		{"file": "/a.bin", "address": "0x10", "note": "n1", "created": "2026-01-01T00:00:00Z"},
		{"file": "/b.bin", "address": "0x20", "note": "n2", "created": "2026-01-02T00:00:00Z"},
	} {
		r := rows[i].(map[string]any)
		for k, v := range want {
			if r[k] != v {
				t.Fatalf("bookmark %d field %s = %v, want %q", i, k, r[k], v)
			}
		}
	}
	job := t7b19Write(t, filepath.Join(t.TempDir(), "job.json"), []byte(`{"file":"/a.bin"}`))
	m, code, _, _ = t7b19Run(t, e, "--op", "list_bookmarks", job)
	if code != 0 {
		t.Fatalf("filtered exit = %d", code)
	}
	res = t7b19Result(t, m)
	if res["count"] != float64(1) || res["total"] != float64(2) {
		t.Fatalf("filtered count/total = %v/%v, want 1/2", res["count"], res["total"])
	}
	if filtered := t7b19Arr(t, res, "bookmarks"); filtered[0].(map[string]any)["file"] != "/a.bin" {
		t.Fatalf("filter returned %v", filtered)
	}
}

func t7b19CheckCutter(t *testing.T, e t7b19Env, res map[string]any) {
	t.Helper()
	searched := t7b19Arr(t, res, "searched")
	wantDirs := []string{
		filepath.Join(e.home, "Library", "Application Support", "Cutter"),
		filepath.Join(e.home, "Library", "Application Support", "rizin", "projects"),
		filepath.Join(e.home, ".local", "share", "rizin", "projects"),
	}
	gotDirs := make([]string, len(searched))
	for i := range searched {
		gotDirs[i], _ = searched[i].(string)
	}
	if !reflect.DeepEqual(gotDirs, wantDirs) {
		t.Fatalf("searched = %v, want %v", gotDirs, wantDirs)
	}
	if projects := t7b19Arr(t, res, "projects"); len(projects) != 0 {
		t.Fatalf("empty home reported %v", projects)
	}
	if ps := t7b19Arr(t, res, "cutter_processes"); len(ps) != 0 {
		t.Fatalf("empty process table reported %v", ps)
	}
	if src, _ := res["process_source"].(string); !strings.Contains(src, "kernel process table") || !strings.Contains(src, "no pgrep") {
		t.Fatalf("process_source = %q", res["process_source"])
	}
	if note, _ := res["rizin"].(string); !strings.Contains(note, "never probes or runs rizin") {
		t.Fatalf("rizin note = %q", res["rizin"])
	}

	// Two real project files in the searched dirs, one decoy outside them.
	a := t7b19Write(t, filepath.Join(e.home, "Library", "Application Support", "rizin", "projects", "a.rzdb"), []byte("a"))
	b := t7b19Write(t, filepath.Join(e.home, ".local", "share", "rizin", "projects", "b.rzdb"), []byte("b"))
	decoy := t7b19Write(t, filepath.Join(e.home, "decoy.rzdb"), []byte("d"))
	m, code, _, _ := t7b19Run(t, e, "--op", "list_cutter_sessions")
	if code != 0 {
		t.Fatalf("seeded exit = %d", code)
	}
	res = t7b19Result(t, m)
	rows := t7b19Arr(t, res, "projects")
	got := make([]string, len(rows))
	for i := range rows {
		got[i], _ = rows[i].(string)
	}
	sort.Strings(got)
	want := []string{a, b}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projects = %v, want exactly %v (decoy %s is not in a project dir)", got, want, decoy)
	}
	for _, p := range got {
		if !strings.HasSuffix(p, ".rzdb") {
			t.Fatalf("project %q is not an .rzdb file", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("project %q does not exist: %v", p, err)
		}
	}
}

func t7b19CheckDocuments(t *testing.T, e t7b19Env, res map[string]any) {
	t.Helper()
	// No session yet is a refusal with a remedy, not an empty document list.
	empty := e.withState(t)
	m, code, _, _ := t7b19Run(t, empty, "--op", "list_documents")
	if code != 2 || m["kind"] != string(kindNoEngine) || !strings.Contains(m["error"].(string), "no session") {
		t.Fatalf("no session: exit=%d envelope=%v", code, m)
	}
	if _, ok := m["documents"]; ok {
		t.Fatalf("no-session refusal carries documents: %v", m)
	}

	if res["project"] != "fixtureproj" {
		t.Fatalf("project = %v, want the session's fixtureproj", res["project"])
	}
	if res["session"] != filepath.Join(e.state, "session.json") {
		t.Fatalf("session = %v, want the state file", res["session"])
	}
	rows := t7b19Arr(t, res, "documents")
	if len(rows) != 2 {
		t.Fatalf("%d document rows, want the 2 the session recorded: %v", len(rows), rows)
	}
	selected := 0
	for _, r := range rows {
		row := r.(map[string]any)
		path, _ := row["path"].(string)
		st, statErr := os.Stat(path)
		if row["selected"] == true {
			selected++
			if path != res["document"] {
				t.Fatalf("selected row %q is not the session document %v", path, res["document"])
			}
			// The one seeded document is on disk: report its real size.
			if statErr != nil || row["exists"] != true || st == nil || row["size"] != float64(st.Size()) || row["size"] != float64(4) {
				t.Fatalf("document row = %v (stat err %v), want exists/size 4", row, statErr)
			}
			continue
		}
		// The other one was recorded and then deleted: it cannot claim to exist.
		if statErr == nil || !os.IsNotExist(statErr) {
			t.Fatalf("%s: %q claims a stat result %v", path, "exists", statErr)
		}
		if row["exists"] != false {
			t.Fatalf("deleted document claimed to exist: %v", row)
		}
		if msg, _ := row["error"].(string); !strings.Contains(msg, "no such file") {
			t.Fatalf("deleted document error = %v", row["error"])
		}
		if _, ok := row["size"]; ok {
			t.Fatalf("deleted document carries a size it cannot measure: %v", row)
		}
	}
	if selected != 1 {
		t.Fatalf("%d rows marked selected, want exactly 1", selected)
	}
}

func t7b19CheckFridaProcesses(t *testing.T, res map[string]any) {
	t.Helper()
	if res["device"] != "local" || res["device_type"] != "local" {
		t.Fatalf("device/device_type = %v/%v, want the host table", res["device"], res["device_type"])
	}
	note, _ := res["note"].(string)
	if !strings.Contains(note, "adb is not installed") {
		t.Fatalf("note = %q, want it to name the missing adb", note)
	}
	rows := t7b19Arr(t, res, "processes")
	if len(rows) == 0 || res["count"] != float64(len(rows)) {
		t.Fatalf("count = %v for %d rows", res["count"], len(rows))
	}
	// Every reported pid must be in this machine's kernel table, or be the CLI
	// itself: it was alive while printing and is gone by the cross-check. Any
	// other row was invented.
	alive := t7b19Pids(t)
	self := filepath.Base(cliPath)
	prev := -1
	for _, r := range rows {
		row := r.(map[string]any)
		pid, _ := row["pid"].(float64)
		name, _ := row["name"].(string)
		if pid <= 0 || name == "" {
			t.Fatalf("incomplete process row: %v", row)
		}
		if int(pid) <= prev {
			t.Fatalf("process rows are not sorted by pid at %v (prev %d)", pid, prev)
		}
		prev = int(pid)
		if !alive[int(pid)] && name != self {
			t.Fatalf("pid %d (%s) is not in the kernel process table", int(pid), name)
		}
	}
}

func t7b19Pids(t *testing.T) map[int]bool {
	t.Helper()
	kernel, err := listProcesses()
	if err != nil {
		t.Fatalf("kernel process table: %v", err)
	}
	pids := make(map[int]bool, len(kernel))
	for _, p := range kernel {
		pids[p.PID] = true
	}
	return pids
}

func t7b19CheckJebUnits(t *testing.T, e t7b19Env, res map[string]any, dex, text string) {
	t.Helper()
	if res["target"] != dex {
		t.Fatalf("target = %v, want %s", res["target"], dex)
	}
	dexes := t7b19Arr(t, res, "dex")
	if len(dexes) != 1 || dexes[0] != dex {
		t.Fatalf("dex = %v, want [%s]", dexes, dex)
	}
	rows := t7b19Arr(t, res, "units")
	wantClasses := []string{"Lcom/example/fix/Helper;", "Lcom/example/fix/Main;", "Lcom/example/fix/Util;"}
	if len(rows) != len(wantClasses) {
		t.Fatalf("%d units, want %d: %v", len(rows), len(wantClasses), rows)
	}
	for i, want := range wantClasses {
		row := rows[i].(map[string]any)
		if row["class"] != want {
			t.Fatalf("unit %d class = %v, want %s", i, row["class"], want)
		}
		if !strings.HasPrefix(want, "L") || !strings.HasSuffix(want, ";") {
			t.Fatalf("class descriptor %q is not a dex type descriptor", want)
		}
		methods := t7b19Arr(t, row, "methods")
		if len(methods) == 0 {
			t.Fatalf("%s carries no methods", want)
		}
		for _, mv := range methods {
			if name, _ := mv.(string); name == "" {
				t.Fatalf("%s has an empty method name: %v", want, methods)
			}
		}
	}
	if got := t7b19Arr(t, rows[1].(map[string]any), "methods"); !reflect.DeepEqual(got, []any{"<init>", "main"}) {
		t.Fatalf("Main methods = %v, want [<init> main]", got)
	}

	// Neither of these is a DEX image: both refuse and neither lists units.
	for _, bad := range []string{text, t.TempDir()} {
		m, code, _, _ := t7b19Run(t, e, "--op", "list_jeb_units", bad)
		if code != 2 || m["kind"] != string(kindBadArg) {
			t.Fatalf("%s: exit=%d envelope=%v", bad, code, m)
		}
		if _, ok := m["units"]; ok {
			t.Fatalf("%s refusal carries units: %v", bad, m)
		}
	}
}
