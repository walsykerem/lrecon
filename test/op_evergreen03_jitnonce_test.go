package main

// Evergreen 03: the token a canned fixture cannot have. K nonces are minted
// from crypto/rand at run time, injected into copies of a real .go file, and
// the tool must hand each one back from its own artifact and no other. A
// recorded-output replay fails on the first nonce because the value did not
// exist when the recording was made.
//
// lrecon never extracts text from a .go source file (text targets are digested,
// not scanned), so the injected copy is embedded verbatim into a built Go
// binary; the binary is the artifact whose strings are searched. The copy is
// still read byte-for-byte by the text digest first, so the binding between the
// temp .go file and the searched bytes is checked, not assumed.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const ev03NoncePrefix = "EVERGREEN03_"

func ev03Nonce(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return ev03NoncePrefix + hex.EncodeToString(b[:])
}

// ev03Run shells out to the built tool and returns stdout.
func ev03Run(t *testing.T, bin string, env []string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %v: %v (stderr: %s)", bin, args, err, strings.TrimSpace(stderr.String()))
	}
	return out
}

type ev03Digest struct {
	Kind   string `json:"kind"`
	Target struct {
		Size       int    `json:"size"`
		FileSHA256 string `json:"file_sha256"`
	} `json:"target"`
}

type ev03Search struct {
	Op     string `json:"op"`
	Result struct {
		Matched int `json:"matched"`
		Matches []struct {
			Value string `json:"value"`
		} `json:"matches"`
	} `json:"result"`
}

func TestEvergreen03JITNonce(t *testing.T) {
	const k = 3

	// K fresh nonces, structurally checked: format, mutual distinctness, and no
	// collision with an independently drawn second batch (run-to-run
	// independence). No exact value is ever asserted.
	nonces := make([]string, 0, k)
	seen := map[string]bool{}
	for i := 0; i < k; i++ {
		n := ev03Nonce(t)
		if want := ev03NoncePrefix + "0123456789abcdef"; len(n) != len(want) {
			t.Fatalf("nonce %q is not %d chars", n, len(want))
		}
		if strings.TrimPrefix(n, ev03NoncePrefix) == n {
			t.Fatalf("nonce %q lacks the %q prefix", n, ev03NoncePrefix)
		}
		if seen[n] {
			t.Fatalf("crypto/rand produced the same nonce twice: %q", n)
		}
		seen[n] = true
		nonces = append(nonces, n)
	}
	for i := 0; i < k; i++ {
		if n := ev03Nonce(t); seen[n] {
			t.Fatalf("second batch repeated a first-batch nonce: %q", n)
		}
	}

	realSrc := "op_scrub_output.go"
	orig, err := os.ReadFile(realSrc)
	if err != nil {
		t.Fatalf("read real corpus file %s: %v", realSrc, err)
	}

	tool, err := filepath.Abs("./lrecon")
	if err != nil {
		t.Fatalf("abs tool path: %v", err)
	}
	if st, err := os.Stat(tool); err != nil || st.Mode()&0111 == 0 {
		t.Fatalf("%s is not an executable file: %v", tool, err)
	}

	type ev03Case struct {
		nonce string
		bin   string
	}
	cases := make([]ev03Case, 0, k)

	for i, nonce := range nonces {
		dir := t.TempDir()
		srcDir := filepath.Join(dir, "src")
		if err := os.MkdirAll(srcDir, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		src := filepath.Join(srcDir, "corpus.go")
		content := string(orig) + "\nvar Evergreen03JITNonce = \"" + nonce + "\"\n"
		if strings.Contains(string(orig), nonce) {
			t.Fatalf("nonce %q already present in %s", nonce, realSrc)
		}
		if err := os.WriteFile(src, []byte(content), 0o644); err != nil {
			t.Fatalf("write temp copy: %v", err)
		}

		// The tool must digest the exact temp bytes, not a remembered fixture.
		var d ev03Digest
		if err := json.Unmarshal(ev03Run(t, tool, nil, src, "--json"), &d); err != nil {
			t.Fatalf("case %d: digest json: %v", i, err)
		}
		sum := sha256.Sum256([]byte(content))
		wantSHA := hex.EncodeToString(sum[:])
		if d.Kind != "text" {
			t.Fatalf("case %d: kind = %q, want text", i, d.Kind)
		}
		if d.Target.Size != len(content) {
			t.Fatalf("case %d: size = %d, want %d", i, d.Target.Size, len(content))
		}
		if d.Target.FileSHA256 != wantSHA {
			t.Fatalf("case %d: file_sha256 = %q, want %q", i, d.Target.FileSHA256, wantSHA)
		}

		main := "package main\n\nimport (\n\t_ \"embed\"\n\t\"fmt\"\n)\n\n" +
			"//go:embed src/corpus.go\nvar corpus string\n\nfunc main() { fmt.Print(corpus) }\n"
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(main), 0o644); err != nil {
			t.Fatalf("write wrapper: %v", err)
		}
		bin := filepath.Join(dir, "probe.bin")
		build := exec.Command("go", "build", "-o", bin, "main.go")
		build.Dir = dir
		build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("go build case %d: %v (%s)", i, err, strings.TrimSpace(string(out)))
		}
		cases = append(cases, ev03Case{nonce: nonce, bin: bin})
	}

	// Diagonal: nonce i must be found in binary i and in none of the others.
	for i, own := range cases {
		for j, probe := range cases {
			var s ev03Search
			raw := ev03Run(t, tool, []string{"LRECON_QUERY=" + probe.nonce},
				own.bin, "--op", "search_strings", "--json")
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("case %d/%d: search json: %v", i, j, err)
			}
			if s.Op != "search_strings" {
				t.Fatalf("case %d/%d: op = %q", i, j, s.Op)
			}
			if i == j {
				if s.Result.Matched < 1 {
					t.Fatalf("nonce %q not returned by its own artifact (matched=%d)", probe.nonce, s.Result.Matched)
				}
				found := false
				for _, m := range s.Result.Matches {
					if strings.Contains(m.Value, probe.nonce) {
						found = true
					}
				}
				if !found {
					t.Fatalf("nonce %q absent from every returned record", probe.nonce)
				}
				continue
			}
			if s.Result.Matched != 0 {
				t.Fatalf("nonce %q leaked into artifact of case %d (matched=%d, want 0)", probe.nonce, i, s.Result.Matched)
			}
		}
	}

	// Every nonce resolved in exactly one artifact.
	for _, probe := range cases {
		hits := 0
		for _, own := range cases {
			var s ev03Search
			raw := ev03Run(t, tool, []string{"LRECON_QUERY=" + probe.nonce},
				own.bin, "--op", "search_strings", "--json")
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatalf("recount json: %v", err)
			}
			if s.Result.Matched > 0 {
				hits++
			}
		}
		if hits != 1 {
			t.Fatalf("nonce %q appeared in %d artifacts, want 1", probe.nonce, hits)
		}
	}

	t.Logf("FIELD=jit_nonce_differential STATUS=PASS nonces=%d artifacts=%d", k, len(cases))
}
