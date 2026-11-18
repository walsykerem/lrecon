package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The pinned skill docs describe the answer a consumer gets, so the CLI's JSON
// is checked against the prose, not against types.go: a key the docs do not
// name is a shape a reader was never warned about, and a documented key that
// the CLI drops is a field the reader was promised.
func docSection(t *testing.T, file, heading string) string {
	t.Helper()
	path := filepath.Join("..", "skill", "references", file)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	lines := strings.Split(string(b), "\n")
	start := -1
	for i, l := range lines {
		if l == "## "+heading {
			start = i + 1
			continue
		}
		if start >= 0 && strings.HasPrefix(l, "## ") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	if start < 0 {
		t.Fatalf("%s has no %q section", path, heading)
	}
	return strings.Join(lines[start:], "\n")
}

// backticks returns the `name` tokens of one line. A token the doc marks as a
// text-digest alias ("(text `mobile_permission`)") is not a JSON key, so the
// word right before it decides.
func backticks(line string) []string {
	var out []string
	for {
		i := strings.IndexByte(line, '`')
		if i < 0 {
			return out
		}
		rest := line[i+1:]
		j := strings.IndexByte(rest, '`')
		if j < 0 {
			return out
		}
		before := strings.TrimRight(line[:i], " ")
		if !strings.HasSuffix(before, "text") {
			out = append(out, rest[:j])
		}
		line = rest[j+1:]
	}
}

// docDigestKeys is the digest key set the skill promises: router.md enumerates
// the 63 keys with a route row or a value row, contract_min.md#Digest names the
// 8 an agent reads first, and the two together are the "64 top-level keys".
func docDigestKeys(t *testing.T) []string {
	t.Helper()
	seen := map[string]bool{}
	add := func(keys ...string) {
		for _, k := range keys {
			seen[k] = true
		}
	}
	for _, line := range strings.Split(docSection(t, "router.md", "read-digest"), "\n") {
		if strings.HasPrefix(line, "| `") && !strings.Contains(line, "text digest only") {
			cell := strings.SplitN(line, "|", 3)[1]
			add(backticks(cell)...)
		}
		if !strings.Contains(line, "keys, no own action:") {
			continue
		}
		add(backticks(line)...)
	}
	// The continuation lines of that paragraph are a plain `a`, `b`, `c` list.
	other := false
	for _, line := range strings.Split(docSection(t, "router.md", "read-digest"), "\n") {
		switch {
		case strings.Contains(line, "keys, no own action:"):
			other = true
		case other && strings.HasPrefix(line, "`"):
			add(backticks(line)...)
		default:
			other = false
		}
	}
	// contract_min.md opens its Digest paragraph with the first-read keys and
	// closes the list with a full stop.
	for _, line := range strings.Split(docSection(t, "contract_min.md", "Digest"), "\n") {
		toks := backticks(line)
		if len(toks) == 0 || toks[0] != "kind" {
			continue
		}
		for _, tok := range toks {
			add(tok)
			after := strings.SplitN(line, "`"+tok+"`", 2)[1]
			if !strings.HasPrefix(after, ",") {
				break // "." closes the list: the prose that follows names more fields
			}
			line = after
		}
		break
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// docErrorKinds is the closed kind list ops.md prints for the refusal envelope.
func docErrorKinds(t *testing.T) []string {
	t.Helper()
	lines := strings.Split(docSection(t, "ops.md", "Failure"), "\n")
	for i, line := range lines {
		if !strings.Contains(line, "`kind` is closed") {
			continue
		}
		kinds := backticks(strings.SplitN(line, "`kind` is closed", 2)[1])
		for _, cont := range lines[i+1:] {
			if !strings.HasPrefix(cont, "`") {
				break
			}
			body, _, closed := strings.Cut(cont, ". ")
			kinds = append(kinds, backticks(body)...)
			if closed {
				break // the sentence ended: the tokens from here on are prose
			}
		}
		return kinds
	}
	t.Fatal("ops.md#Failure no longer prints a closed kind list")
	return nil
}

func digestKeys(t *testing.T, stdout string) (map[string]json.RawMessage, []string) {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &m); err != nil {
		t.Fatalf("digest is not one JSON object: %v\n%s", err, stdout)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return m, keys
}

// TestTur7Bucket30ContractDocs: one sample per kind, every success envelope
// compared to the documented key set in both directions.
func TestTur7Bucket30ContractDocs(t *testing.T) {
	docKeys := docDigestKeys(t)
	if len(docKeys) != 64 {
		t.Fatalf("parsed %d documented digest keys, docs claim 64: %v", len(docKeys), docKeys)
	}
	doc := map[string]bool{}
	for _, k := range docKeys {
		doc[k] = true
	}

	sqliteHdr := make([]byte, 100)
	copy(sqliteHdr, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(sqliteHdr[16:18], 4096)
	pcapHdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcapHdr[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(pcapHdr[20:], 1)

	sample := []struct{ kind, path string }{
		{"text", writeTemp(t, "contract.txt", []byte("contract\n"))},
		{"wasm", writeTemp(t, "contract.wasm", []byte("\x00asm\x01\x00\x00\x00"))},
		{"sqlite", writeTemp(t, "contract.db", sqliteHdr)},
		{"pcap", writeTemp(t, "contract.pcap", pcapHdr)},
		{"elf", constELF(t, nil)},
		{"pe", constPE(t)},
	}

	seen := map[string]bool{}
	for _, s := range sample {
		out, code := runCLI(t, "--json", s.path)
		if code != 0 {
			t.Fatalf("%s: exit %d, want 0; output:\n%s", s.kind, code, out)
		}
		m, keys := digestKeys(t, out)
		var kind string
		if err := json.Unmarshal(m["kind"], &kind); err != nil || kind != s.kind {
			t.Fatalf("%s: kind = %s, want %q: a canned answer would collapse the sample", s.path, m["kind"], s.kind)
		}
		seen[kind] = true

		var version int
		if err := json.Unmarshal(m["contract_version"], &version); err != nil || version != 1 {
			t.Fatalf("%s: contract_version = %s, docs promise 1", s.kind, m["contract_version"])
		}
		for _, k := range keys {
			if !doc[k] {
				t.Fatalf("%s: key %q is emitted but no skill reference documents it", s.kind, k)
			}
		}
		for _, k := range docKeys {
			if _, ok := m[k]; !ok {
				t.Fatalf("%s: documented key %q is missing from the digest", s.kind, k)
			}
		}
	}
	if len(seen) < 5 {
		t.Fatalf("sample covered %d kinds, want at least 5: %v", len(seen), seen)
	}

	// The refusal envelope: docs promise contract_version 1, a non-empty error
	// and a kind from the closed list, and the same refusal twice must not move
	// that kind.
	kinds := docErrorKinds(t)
	if len(kinds) != 9 {
		t.Fatalf("parsed %d documented error kinds, ops.md prints 9: %v", len(kinds), kinds)
	}
	closed := map[string]bool{}
	for _, k := range kinds {
		closed[k] = true
	}
	missing := writeTemp(t, "absent.txt", nil)
	os.Remove(missing)
	for _, args := range [][]string{{"--json", missing}, {"--json", "--max-bytes", "0", sample[0].path}} {
		var first string
		for run := 0; run < 2; run++ {
			out, _, code := runCLIAll(t, args...)
			if code != 2 {
				t.Fatalf("%v: exit %d, want 2; stdout:\n%s", args, code, out)
			}
			m, _ := digestKeys(t, out)
			var kind, detail string
			if err := json.Unmarshal(m["kind"], &kind); err != nil {
				t.Fatalf("%v: kind = %s", args, m["kind"])
			}
			if !closed[kind] {
				t.Fatalf("%v: kind %q is not in the documented refusal list %v", args, kind, kinds)
			}
			if err := json.Unmarshal(m["error"], &detail); err != nil || strings.TrimSpace(detail) == "" {
				t.Fatalf("%v: envelope error = %s, want a reason", args, m["error"])
			}
			if run == 0 {
				first = kind
			} else if kind != first {
				t.Fatalf("%v: kind moved between runs: %q then %q", args, first, kind)
			}
		}
	}
}
