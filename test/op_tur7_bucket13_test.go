package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTur7Bucket13Settings proves config.json is real state, not a canned
// answer: the default read is read-only, one mutated knob survives the process
// boundary, the next op's answer carries it, and a refused knob is refused by
// name, inside its documented bound, without touching the file.
func TestTur7Bucket13Settings(t *testing.T) {
	state := t.TempDir()
	t.Setenv("LRECON_STATE", state)
	cfg := filepath.Join(state, "config.json")

	// Defaults: stated, not invented -- and reading them must not create state.
	first := metaMustRun(t, "inspect_analysis_settings", state)
	if metaStr(t, first, "source") != "defaults" {
		t.Fatalf("fresh source = %q, want defaults", first["source"])
	}
	if metaStr(t, first, "config_file") != cfg {
		t.Fatalf("config_file = %q, want %q", metaStr(t, first, "config_file"), cfg)
	}
	ds, _ := first["settings"].(map[string]any)
	if metaStr(t, ds, "kind") != metaSettingsKind || metaNum(t, ds, "maxBytes") != 8<<20 ||
		metaNum(t, ds, "minString") != 4 || metaBool(t, ds, "deep") || metaStr(t, ds, "updated") != "" {
		t.Fatalf("defaults = %v, want kind=%s maxBytes=%d minString=4 deep=false updated empty",
			ds, metaSettingsKind, 8<<20)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatalf("inspect created %s (err=%v); the read must not write state", cfg, err)
	}

	// Mutate exactly one knob. The others must survive untouched, and the
	// answer must name the value it replaced.
	upd := metaMustRun(t, "update_analysis_settings", metaTestArg(t, map[string]any{"minString": 9}))
	before, _ := upd["before"].(map[string]any)
	if metaNum(t, before, "minString") != 4 || metaNum(t, before, "maxBytes") != 8<<20 {
		t.Fatalf("before = %v, want the defaults 4/%d", before, 8<<20)
	}
	us, _ := upd["settings"].(map[string]any)
	if metaNum(t, us, "minString") != 9 || metaNum(t, us, "maxBytes") != 8<<20 || metaBool(t, us, "deep") {
		t.Fatalf("after update = %v, want minString=9 and the other knobs unchanged", us)
	}
	if _, err := time.Parse(time.RFC3339, metaStr(t, us, "updated")); err != nil {
		t.Fatalf("updated = %q is not RFC3339: %v", metaStr(t, us, "updated"), err)
	}

	// The write reached disk: the file itself, not just the reply, holds 9.
	raw, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("update did not write %s: %v", cfg, err)
	}
	var onDisk metaSettings
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatalf("config.json is not settings JSON: %v\n%s", err, raw)
	}
	if onDisk.MinString != 9 || onDisk.MaxBytes != 8<<20 || onDisk.Kind != metaSettingsKind {
		t.Fatalf("on-disk settings = %+v, want minString=9 maxBytes=%d kind=%s", onDisk, 8<<20, metaSettingsKind)
	}

	// A separate process sees the mutation: a canned in-memory answer cannot.
	stdout, stderr, code := runCLIAll(t, "--json", "--op", "inspect_analysis_settings", state)
	if code != 0 {
		t.Fatalf("cli exit %d, want 0; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	var env struct {
		Op     string `json:"op"`
		Result struct {
			Settings map[string]any `json:"settings"`
			Source   string         `json:"source"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(stdout), &env); err != nil {
		t.Fatalf("cli stdout is not one JSON object: %v\n%s", err, stdout)
	}
	if env.Op != "inspect_analysis_settings" {
		t.Fatalf("cli op = %q", env.Op)
	}
	if got := metaNum(t, env.Result.Settings, "minString"); got != 9 {
		t.Fatalf("minString in a new process = %d, want the mutated 9", got)
	}
	if env.Result.Source != "config" {
		t.Fatalf("source in a new process = %q, want config", env.Result.Source)
	}

	// The mutation changed a later answer: same op, same explicit target, now 9
	// where the first answer said 4; and the next op's "before" carries it.
	back := metaMustRun(t, "inspect_analysis_settings", state)
	bs, _ := back["settings"].(map[string]any)
	if metaNum(t, bs, "minString") != 9 {
		t.Fatalf("minString after mutation = %d, want 9 (the first answer said %d)",
			metaNum(t, bs, "minString"), metaNum(t, ds, "minString"))
	}
	upd2 := metaMustRun(t, "update_analysis_settings", metaTestArg(t, map[string]any{"maxBytes": 4096}))
	b2, _ := upd2["before"].(map[string]any)
	if metaNum(t, b2, "minString") != 9 || metaNum(t, b2, "maxBytes") != 8<<20 {
		t.Fatalf("second update before = %v, want the first mutation (minString 9, maxBytes %d)", b2, 8<<20)
	}
	s2, _ := upd2["settings"].(map[string]any)
	if metaNum(t, s2, "minString") != 9 || metaNum(t, s2, "maxBytes") != 4096 {
		t.Fatalf("second update = %v, want minString kept at 9 and maxBytes 4096", s2)
	}

	// Bounds are refused by name, with the documented range, and nothing is
	// written: the file keeps both mutated values.
	settled, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		field, want string
		job         map[string]any
	}{
		{"minString", fmt.Sprintf("update_analysis_settings: minString 65 is not inside 1..%d", 64), map[string]any{"minString": 65}},
		{"minString", "update_analysis_settings: minString 0 is not inside 1..64", map[string]any{"minString": 0}},
		{"maxBytes", fmt.Sprintf("update_analysis_settings: maxBytes 0 is not inside 1..%d", 1<<30), map[string]any{"maxBytes": 0}},
		{"maxBytes", fmt.Sprintf("update_analysis_settings: maxBytes %d is not inside 1..%d", 1<<30+1, 1<<30), map[string]any{"maxBytes": 1<<30 + 1}},
	} {
		_, err := metaTestRun(t, "update_analysis_settings", metaTestArg(t, tc.job))
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%s %v: err = %v, want %q", tc.field, tc.job, err, tc.want)
		}
		if !strings.Contains(err.Error(), "1..") {
			t.Fatalf("%s refusal hides its bound: %q", tc.field, err.Error())
		}
	}
	still, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if string(still) != string(settled) {
		t.Fatalf("a refused update rewrote config.json:\nbefore: %s\nafter:  %s", settled, still)
	}

	// The view op honours its own default rather than an unstated one: a job
	// with no "view" answers digest for the target's real bytes.
	txt := writeTemp(t, "tur7b13.txt", []byte("hello bucket thirteen\n"))
	v := metaMustRun(t, "inspect_analysis_view", metaTestArg(t, map[string]any{"file": txt}))
	if metaStr(t, v, "view") != "digest" || metaStr(t, v, "kind") != "text" || metaNum(t, v, "contract_version") != contractVersion {
		t.Fatalf("default view = %v, want digest of the text target", v)
	}
	if metaStr(t, v, "file") != txt {
		t.Fatalf("view file = %q, want %q", metaStr(t, v, "file"), txt)
	}
}
