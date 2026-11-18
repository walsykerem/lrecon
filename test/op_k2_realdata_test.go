package main

// The K2 rows in the domination report were argument-free smoke calls: these
// ops need a real target shape. This test locks one real call per op so a
// future "no data" regression is a test failure instead of a report footnote.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func k2Fixture(t *testing.T, parts ...string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join(append([]string{"..", "env", "probe20", "fixtures"}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func k2Run(t *testing.T, name, target string) map[string]any {
	t.Helper()
	res, err := runOp(name, target)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, target, err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: decode: %v", name, err)
	}
	return m
}

func k2Num(t *testing.T, m map[string]any, key string) float64 {
	t.Helper()
	v, ok := m[key].(float64)
	if !ok || v <= 0 {
		t.Fatalf("field %q = %v, want positive number (%v)", key, m[key], m)
	}
	return v
}

func k2Len(t *testing.T, m map[string]any, key string) {
	t.Helper()
	v, ok := m[key].([]any)
	if !ok || len(v) == 0 {
		t.Fatalf("field %q = %v, want non-empty array (%v)", key, m[key], m)
	}
}

func k2Job(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestK2OpsProduceRealData(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	evidence := filepath.Join("..", "evidence", "c6-bundle", "probe.evidence.json")
	v1 := k2Fixture(t, "managed", "dotnet", "Acme.Managed.v1.dll")
	v2 := k2Fixture(t, "managed", "dotnet", "Acme.Managed.v2.dll")
	oldZip := k2Fixture(t, "bundles", "old.zip")
	newZip := k2Fixture(t, "bundles", "new.zip")

	t.Run("get_evidence_bundle", func(t *testing.T) {
		m := k2Run(t, "get_evidence_bundle", k2Job(t, map[string]any{"file": evidence}))
		if m["verified"] != true || m["bundle_sha256"] == nil {
			t.Fatalf("no verified bundle: %v", m)
		}
	})

	t.Run("import_evidence_bundle", func(t *testing.T) {
		m := k2Run(t, "import_evidence_bundle", k2Job(t, map[string]any{"file": evidence, "expect": "/bin/ls"}))
		if m["verified"] != true || m["artifact_match"] != true || m["artifact_checked"] != true {
			t.Fatalf("artifact not checked: %v", m)
		}
	})

	t.Run("inspect_apple_ips", func(t *testing.T) {
		m := k2Run(t, "inspect_apple_ips", k2Fixture(t, "native", "probe.ips"))
		if m["bug_type"] == nil || m["body_parsed"] != true {
			t.Fatalf("no parsed .ips body: %v", m)
		}
	})

	t.Run("inspect_recorded_crash", func(t *testing.T) {
		m := k2Run(t, "inspect_recorded_crash", k2Fixture(t, "firmware", "probe.ips"))
		k2Len(t, m, "images")
		k2Len(t, m, "threads")
		if m["exception"] == nil || m["incident_id"] == nil {
			t.Fatalf("no crash facts: %v", m)
		}
	})

	t.Run("inspect_web_network_capture", func(t *testing.T) {
		m := k2Run(t, "inspect_web_network_capture", k2Fixture(t, "web", "real-capture.har"))
		k2Num(t, m, "entries")
		if m["version"] != "1.2" || m["creator"] == nil {
			t.Fatalf("no HAR facts: %v", m)
		}
	})

	t.Run("analyze_javascript_application", func(t *testing.T) {
		m := k2Run(t, "analyze_javascript_application", k2Fixture(t, "web", "flat", "bundle.js"))
		k2Num(t, m, "tokens")
		if _, ok := m["strings"].([]any); !ok {
			t.Fatalf("no strings: %v", m)
		}
	})

	t.Run("build_reconstruction_obligation_ledger", func(t *testing.T) {
		job := k2Job(t, map[string]any{
			"file":  v1,
			"state": t.TempDir(),
			"rows":  []any{map[string]any{"symbol": "main", "reason": "wave4 probe"}},
		})
		m := k2Run(t, "build_reconstruction_obligation_ledger", job)
		k2Num(t, m, "count")
		if m["ledger"] == nil || m["obligations_file"] == nil {
			t.Fatalf("no ledger: %v", m)
		}
	})

	t.Run("compare_application_versions", func(t *testing.T) {
		m := k2Run(t, "compare_application_versions", k2Job(t, map[string]any{"old": v1, "new": v2}))
		k2Num(t, m, "count")
		if m["verdict"] == nil {
			t.Fatalf("no verdict: %v", m)
		}
	})

	t.Run("compare_artifacts", func(t *testing.T) {
		m := k2Run(t, "compare_artifacts", k2Job(t, map[string]any{"old": oldZip, "new": newZip}))
		k2Num(t, m, "count")
		if m["old"] == nil || m["new"] == nil {
			t.Fatalf("no sides: %v", m)
		}
	})

	t.Run("compare_bundles", func(t *testing.T) {
		m := k2Run(t, "compare_bundles", k2Job(t, map[string]any{"old": oldZip, "new": newZip}))
		k2Num(t, m, "changed")
		if m["new"] == nil || m["old"] == nil {
			t.Fatalf("no sides: %v", m)
		}
	})

	t.Run("compare_javascript_export_shapes", func(t *testing.T) {
		dir := t.TempDir()
		write := func(name, body string) {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		write("old.js", "exports.alpha = function (x, y) {};\nexports.gamma = function (q) {};\n")
		write("new.js", "exports.alpha = function (x, y, z) {};\nexports.delta = function () {};\n")
		m := k2Run(t, "compare_javascript_export_shapes", dir)
		if len(m["added"].([]any)) != 1 || len(m["removed"].([]any)) != 1 || len(m["changed"].([]any)) != 1 {
			t.Fatalf("wrong export diff: %v", m)
		}
	})

	t.Run("compare_managed_members", func(t *testing.T) {
		m := k2Run(t, "compare_managed_members", v1+","+v2)
		k2Num(t, m, "left_types")
		k2Num(t, m, "right_methods")
		if len(m["types_only_right"].([]any)) == 0 {
			t.Fatalf("no type diff: %v", m)
		}
	})
}
