package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// keySet returns the top-level keys of a digest as JSON emits them.
func keySet(t *testing.T, d Digest) []string {
	t.Helper()
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A consumer switches on keys, so every digest must carry the same ones: no
// omitempty, no key that appears only for some kinds.
func TestJSONKeySetStable(t *testing.T) {
	text, err := Probe(writeTemp(t, "keys.txt", []byte("key set\n")))
	if err != nil {
		t.Fatalf("Probe(text): %v", err)
	}
	bin, err := Probe(cliPath)
	if err != nil {
		t.Fatalf("Probe(%s): %v", cliPath, err)
	}
	want := keySet(t, text)
	got := keySet(t, bin)
	if strings.Join(want, ",") != strings.Join(got, ",") {
		t.Fatalf("key set moves with the target:\ntext: %v\nbin:  %v", want, got)
	}

	var m map[string]json.RawMessage
	b, err := json.Marshal(text)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["path"]; ok {
		t.Fatal("path is still in the contract: it makes the digest depend on where the file lives")
	}
	var version int
	if err := json.Unmarshal(m["contract_version"], &version); err != nil || version != contractVersion {
		t.Fatalf("contract_version = %s, want %d", m["contract_version"], contractVersion)
	}
	var target map[string]json.RawMessage
	if err := json.Unmarshal(m["target"], &target); err != nil {
		t.Fatalf("target missing or not an object: %s", m["target"])
	}
	for _, k := range []string{"size", "file_sha256", "hash_scope", "hash_bytes", "gitoid"} {
		if _, ok := target[k]; !ok {
			t.Fatalf("target.%s missing from %s", k, m["target"])
		}
	}
}

// A saved digest from another contract version cannot be compared field by
// field: the refusal happens after both sides are read. In text mode stdout
// stays empty; under --json it is one envelope (A1), never a half-answer.
func TestLateRefusalWritesNoJSON(t *testing.T) {
	forged := writeTemp(t, "forged.json", []byte(`{"contract_version":9,"kind":"elf","mod":"old/thing"}`))
	target := writeTemp(t, "late.txt", []byte("late\n"))
	out, errOut, code := runCLIAll(t, "--diff", forged, target)
	if code != 2 {
		t.Fatalf("text: exit %d, want 2; stdout:\n%s", code, out)
	}
	if out != "" {
		t.Fatalf("text: refused but wrote stdout:\n%s", out)
	}
	if !strings.Contains(errOut, "contract_version") {
		t.Fatalf("refusal does not name the contract version: %q", errOut)
	}
	out, errOut, code = runCLIAll(t, "--json", "--diff", forged, target)
	if code != 2 {
		t.Fatalf("json: exit %d, want 2; stdout:\n%s", code, out)
	}
	var env struct {
		Error string `json:"error"`
		Kind  string `json:"kind"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatalf("json: stdout is not one envelope: %v\n%s", err, out)
	}
	// --json plus --diff is itself a mode conflict, so the envelope names that,
	// not the contract version; the point is that it is one complete object.
	if env.Kind == "" || env.Error == "" {
		t.Fatalf("json: envelope = %s", out)
	}
	if !strings.HasPrefix(errOut, "lrecon: ") {
		t.Fatalf("json: stderr = %q, want the prefixed refusal line", errOut)
	}
}
