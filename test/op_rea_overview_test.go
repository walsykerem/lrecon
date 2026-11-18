package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// The REA-overview entry points answer from the digest lrecon already builds,
// so on a real Mach-O every one of them owes JSON with its named keys.
func TestReaOverviewOps(t *testing.T) {
	const target = "/bin/ls"
	cases := []struct {
		name string
		keys []string
	}{
		{"binary_overview", []string{"summary", "kind", "format", "slices", "exports", "hardening"}},
		{"inspect_binary_layout", []string{"format", "sections"}},
		{"inspect_artifact", []string{"document", "kind", "format", "size", "sha256", "exports"}},
		{"open_binary", []string{"document", "handle", "kind", "format", "size", "sha256"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res, err := runOp(c.name, target)
			if err != nil {
				t.Fatalf("%s %s: %v", c.name, target, err)
			}
			if s, ok := res.(*skip); ok {
				t.Fatalf("%s skipped on %s: %s", c.name, target, s.Reason)
			}
			b, err := json.Marshal(res)
			if err != nil {
				t.Fatalf("%s result does not marshal: %v", c.name, err)
			}
			var m map[string]any
			if err := json.Unmarshal(b, &m); err != nil {
				t.Fatalf("%s is not a JSON object: %v\n%s", c.name, err, b)
			}
			for _, k := range c.keys {
				if _, ok := m[k]; !ok {
					t.Fatalf("%s result has no %q key: %s", c.name, k, b)
				}
			}
		})
	}
}

// objdump is external: absent means a skip that names it, present means the
// section table comes back non-empty.
func TestReaOverviewObjdump(t *testing.T) {
	const target = "/bin/ls"
	res, err := runOp("inspect_with_objdump", target)
	if err != nil {
		t.Fatalf("inspect_with_objdump %s: %v", target, err)
	}
	if s, ok := res.(*skip); ok {
		if !strings.Contains(s.Reason, "objdump") {
			t.Fatalf("skip reason does not name objdump: %q", s.Reason)
		}
		t.Logf("objdump absent, skip reason: %s", s.Reason)
		return
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("inspect_with_objdump result does not marshal: %v", err)
	}
	var m struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("inspect_with_objdump is not a JSON object: %v\n%s", err, b)
	}
	if strings.TrimSpace(m.Output) == "" {
		t.Fatalf("inspect_with_objdump produced empty output on %s", target)
	}
}
