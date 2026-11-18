package main

// ROUND 2 AUDIT — LANE 16 independent simulation test.
// Each TestR2L16* subtest calls the relevant production function with real
// input and verifies its observable behavior. Production code is not relaxed.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func r2l16Write(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func r2l16Map(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// --- Group 1: rt2 helpers ---

func TestR2L16RT2CausePairsStableMsgSHAStatus(t *testing.T) {
	t.Run("cause", func(t *testing.T) {
		got := rt2Cause("Banner line\n  Failure [INSTALL_FAILED_TEST]\nrest")
		if got != "Failure [INSTALL_FAILED_TEST]" {
			t.Fatalf("rt2Cause = %q", got)
		}
		if got := rt2Cause("no reason here"); got != "" {
			t.Fatalf("rt2Cause(no prefix) = %q, want empty", got)
		}
	})
	t.Run("pair", func(t *testing.T) {
		a, b, err := rt2Pair(" com.example/.MainActivity ", "/")
		if err != nil || a != "com.example" || b != ".MainActivity" {
			t.Fatalf("rt2Pair = %q,%q,%v", a, b, err)
		}
		if _, _, err := rt2Pair("noslash", "/"); err == nil {
			t.Fatal("rt2Pair accepted a target with no separator")
		}
		if _, _, err := rt2Pair("pkg/", "/"); err == nil {
			t.Fatal("rt2Pair accepted an empty second half")
		}
	})
	t.Run("stable", func(t *testing.T) {
		msg := "11-02 03:44:25.944 98321 4724641 F adb : Error: boom 1 file pushed. 9.3 MB/s (8192 bytes in 0.001s)"
		got := rt2StableMsg(msg)
		if !strings.Contains(got, "Error: boom") || strings.Contains(got, "MB/s") || strings.Contains(got, "98321") {
			t.Fatalf("rt2StableMsg did not strip clock/rate: %q", got)
		}
	})
	t.Run("sha256", func(t *testing.T) {
		p := r2l16Write(t, "abc.bin", []byte("abc"))
		got, err := rt2SHA256(p)
		if err != nil {
			t.Fatal(err)
		}
		want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
		if got != want {
			t.Fatalf("rt2SHA256 = %s, want %s", got, want)
		}
	})
	t.Run("amstatus", func(t *testing.T) {
		got, err := rt2AMStatus("Starting: Intent\nStatus: ok\n")
		if err != nil || got != "ok" {
			t.Fatalf("rt2AMStatus = %q,%v", got, err)
		}
		if _, err := rt2AMStatus("no status line"); err == nil {
			t.Fatal("rt2AMStatus accepted output with no Status: line")
		}
	})
}

// --- Group 1: scrub_output ---

func TestR2L16ScrubBytesAndRun(t *testing.T) {
	t.Run("runbyte", func(t *testing.T) {
		if !scrubRunByte('A') || scrubRunByte(' ') || scrubRunByte('\n') || scrubRunByte(0x7f) {
			t.Fatal("scrubRunByte alphabet is wrong")
		}
	})
	t.Run("regex", func(t *testing.T) {
		r := scrubBytes([]byte("key=AKIA" + "ABCDEFGHIJKLMNOP end"))
		if r.Clean || r.Scrubbed != 1 || len(r.Findings) != 1 || r.Findings[0].Pattern != "aws-akia" || r.Findings[0].Length != 20 {
			t.Fatalf("aws finding = %+v", r)
		}
		r = scrubBytes([]byte("pem -----BEGIN RSA PRIVATE KEY----- tail"))
		if len(r.Findings) != 1 || r.Findings[0].Pattern != "pem-private-key" {
			t.Fatalf("pem finding = %+v", r)
		}
	})
	t.Run("entropy", func(t *testing.T) {
		token := "Zx9Qw2Lm7Vb4Nt8Kp3Rc6Yd1Hf5Jg0SaEwUoPiTl"
		r := scrubBytes([]byte(token))
		if r.Clean || len(r.Findings) != 1 || r.Findings[0].Pattern != "entropy-40" {
			t.Fatalf("high-entropy run not flagged: %+v", r)
		}
		r = scrubBytes([]byte(strings.Repeat("a", 64)))
		if !r.Clean {
			t.Fatalf("low-entropy run false positive: %+v", r)
		}
	})
	t.Run("run-file", func(t *testing.T) {
		secret := "AKIA" + "ABCDEFGHIJKLMNOP"
		p := r2l16Write(t, "out.log", []byte("before "+secret+" after"))
		v, err := runScrubOutput(p)
		if err != nil {
			t.Fatal(err)
		}
		m := r2l16Map(t, v)
		if int(m["scrubbed"].(float64)) != 1 || m["clean"].(bool) {
			t.Fatalf("runScrubOutput = %v", m)
		}
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), secret) {
			t.Fatalf("scrub report leaked the matched bytes: %s", raw)
		}
		if _, err := runScrubOutput(""); err == nil {
			t.Fatal("runScrubOutput accepted an empty path")
		}
	})
}

// --- Group 2: search_bytes / search_strings / android classes ---

func TestR2L16BytePatternAndSearch(t *testing.T) {
	t.Run("parse-roundtrip", func(t *testing.T) {
		pat, mask, err := parseBytePattern("48 8b ?? c3")
		if err != nil || len(pat) != 4 || len(mask) != 4 {
			t.Fatalf("parseBytePattern = %x,%v,%v", pat, mask, err)
		}
		if mask[0] != true || mask[2] != false {
			t.Fatalf("mask = %v", mask)
		}
		if s := nativePatternString(pat, mask); s != "48 8b ?? c3" {
			t.Fatalf("nativePatternString = %q", s)
		}
		if _, _, err := parseBytePattern("4g"); err == nil {
			t.Fatal("parseBytePattern accepted a non-hex byte")
		}
	})
	t.Run("search-elf", func(t *testing.T) {
		// "runtime.main" is a real string in the ELF fixture's non-exec sections.
		pat, mask, err := parseBytePattern("72 75 ?? 74 69 6d 65 2e 6d 61 69 6e")
		if err != nil {
			t.Fatal(err)
		}
		hits, total, scanned, err := searchPattern("testdata/fixtures/elf", pat, mask, 10)
		if err != nil {
			t.Fatal(err)
		}
		if total < 1 || len(hits) == 0 || scanned == 0 {
			t.Fatalf("searchPattern: total=%d hits=%d scanned=%d", total, len(hits), scanned)
		}
		if hits[0].At == "" {
			t.Fatalf("hit has no section: %+v", hits[0])
		}
	})
	t.Run("strings-honesty", func(t *testing.T) {
		v, err := searchStringsAnswer("testdata/fixtures/elf", "runtime.main", 50, 100, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		m := r2l16Map(t, v)
		matched := int(m["matched"].(float64))
		if matched < 1 {
			t.Fatalf("no match for runtime.main: %v", m)
		}
		if int(m["shown"].(float64)) != matched || int(m["listed"].(float64)) != matched {
			t.Fatalf("shown/listed disagree with matched: %v", m)
		}
		if m["scanned_whole"].(bool) != true || m["strings_truncated"].(bool) != true {
			t.Fatalf("scan cap accounting wrong: %v", m)
		}
	})
	t.Run("metaBQuery", func(t *testing.T) {
		if !metaBQuery("Lcom/example/Alpha;", "com.example") || !metaBQuery("Lcom/example/Beta;", "example.beta") {
			t.Fatal("metaBQuery missed a normalized match")
		}
		if metaBQuery("Lcom/example/Alpha;", "retrofit2") {
			t.Fatal("metaBQuery matched an unrelated query")
		}
	})
}

func TestR2L16DexAndAndroidClassSearch(t *testing.T) {
	dex := jebdDex(t)
	t.Run("dexClassData", func(t *testing.T) {
		r, err := dexOpen(dex, &Digest{})
		if err != nil {
			t.Fatal(err)
		}
		if r.strSize != 5 || r.typSize != 2 {
			t.Fatalf("dexOpen sizes = %d/%d", r.strSize, r.typSize)
		}
		off := int(u32le(dex, 0x64)) + 2*32 // Alpha is the first class_def
		fields, methods, err := dexClassData(r, off)
		if err != nil {
			t.Fatal(err)
		}
		if len(fields) != 0 || len(methods) != 2 {
			t.Fatalf("dexClassData(Alpha) = %d fields, %d methods", len(fields), len(methods))
		}
	})
	t.Run("android-class-search", func(t *testing.T) {
		p := r2l16Write(t, "classes.dex", dex)
		t.Setenv("LRECON_QUERY", "com.example")
		v, err := runOp("search_android_classes", p)
		if err != nil {
			t.Fatal(err)
		}
		m := r2l16Map(t, v)
		if int(m["class_matches_total"].(float64)) < 2 || int(m["string_ids"].(float64)) != 5 {
			t.Fatalf("search_android_classes = %v", m)
		}
		classes, ok := m["classes"].([]any)
		if !ok || len(classes) < 2 {
			t.Fatalf("classes list = %v", m["classes"])
		}
		withDef := 0
		for _, c := range classes {
			cm := c.(map[string]any)
			if int(cm["class_defs"].(float64)) == 1 {
				withDef++
				wantMethods := 2
				if strings.Contains(cm["descriptor"].(string), "Beta") {
					wantMethods = 1
				}
				if int(cm["methods"].(float64)) != wantMethods || int(cm["fields"].(float64)) != 0 {
					t.Fatalf("class join counts wrong: %v", cm)
				}
			}
		}
		if withDef != 2 {
			t.Fatalf("expected 2 class_defs joined, got %d: %v", withDef, classes)
		}
	})
}

// --- Group 3: set ops ---

func TestR2L16SetBookmarkCreateUpdate(t *testing.T) {
	state := t.TempDir()
	jobFile := r2l16Write(t, "job.json", []byte(`{"file":"/bin/ls","address":"0x1400","state":"`+state+`","note":"first"}`))
	v, err := runSetBookmark(jobFile)
	if err != nil {
		t.Fatal(err)
	}
	m := r2l16Map(t, v)
	if m["updated"].(bool) || int(m["count"].(float64)) != 1 {
		t.Fatalf("first set_bookmark = %v", m)
	}

	// Seed a backdated bookmark so "Created preserved" is not a same-second accident.
	bf := filepath.Join(state, "bookmarks.json")
	if err := os.WriteFile(bf, []byte(`[{"file":"/bin/ls","address":"0x1400","note":"old","created":"2020-01-01T00:00:00Z"}]`), 0o644); err != nil {
		t.Fatal(err)
	}
	jobFile2 := r2l16Write(t, "job2.json", []byte(`{"file":"/bin/ls","address":"0x1400","state":"`+state+`","note":"second"}`))
	v2, err := runSetBookmark(jobFile2)
	if err != nil {
		t.Fatal(err)
	}
	m2 := r2l16Map(t, v2)
	bm := m2["bookmark"].(map[string]any)
	if !m2["updated"].(bool) || int(m2["count"].(float64)) != 1 {
		t.Fatalf("update = %v", m2)
	}
	if bm["note"] != "second" || bm["created"] != "2020-01-01T00:00:00Z" {
		t.Fatalf("bookmark note/created wrong: %v", bm)
	}
}

func TestR2L16SetAddressNamesValidation(t *testing.T) {
	old := ghidraFinder
	t.Cleanup(func() { ghidraFinder = old })
	ghidraFinder = func() (string, string, error) { return "/fake/analyzeHeadless", "/fake/project", nil }
	p := r2l16Write(t, "job.json", []byte(`{"file":"/bin/ls"}`))
	_, err := runOp("set_addresses_names", p)
	if err == nil || !strings.Contains(err.Error(), `job needs "labels"`) {
		t.Fatalf("set_addresses_names on empty labels = %v", err)
	}
	p2 := r2l16Write(t, "job2.json", []byte(`{"file":"/bin/ls","labels":[{"address":"0x1"}]}`))
	_, err = runOp("set_addresses_names", p2)
	if err == nil || !strings.Contains(err.Error(), "labels[0] is not a pair") || classify(err.Error()) != kindBadArg {
		t.Fatalf("set_addresses_names on partial label = %v", err)
	}
}

// --- Group 4: start ops ---

func TestR2L16StartOpsArgAndRefusal(t *testing.T) {
	t.Run("adb-bad-arg", func(t *testing.T) {
		if _, err := opStartAdbActivity("bad-target"); err == nil || !strings.Contains(err.Error(), "not <pkg>/<activity>") {
			t.Fatalf("opStartAdbActivity bad target = %v", err)
		}
		if _, err := opStartAdbApp("  "); err == nil || !strings.Contains(err.Error(), "needs a package name") {
			t.Fatalf("opStartAdbApp empty package = %v", err)
		}
	})
	for _, c := range []struct {
		name, target string
	}{
		{"start_gdb_session", "/bin/ls"},
		{"start_frida_session", ""},
		{"start_rizin_debug_session", "/bin/ls"},
	} {
		t.Run(c.name, func(t *testing.T) {
			args := []string{"--op", c.name, "--json"}
			if c.target != "" {
				args = append(args, c.target)
			}
			stdout, _, code := runCLIAll(t, args...)
			if code != 2 {
				t.Fatalf("%s exit = %d, want 2; stdout=%s", c.name, code, stdout)
			}
			var e struct {
				Kind  string `json:"kind"`
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &e); err != nil {
				t.Fatalf("%s refusal is not JSON: %v (%s)", c.name, err, stdout)
			}
			if e.Kind != string(kindOutOfScope) || !strings.Contains(strings.ToLower(e.Error), "out of scope") {
				t.Fatalf("%s refusal = %+v", c.name, e)
			}
		})
	}
}

// --- Group 5: sqlite / static util / PE ---

func TestR2L16SQLiteVarintRecord(t *testing.T) {
	if n, size := sqliteVarint([]byte{0x80, 0x01}); n != 1 || size != 2 {
		t.Fatalf("sqliteVarint(2-byte non-minimal) = %d,%d", n, size)
	}
	if n, size := sqliteVarint([]byte{0x87, 0xff, 0xff, 0xff, 0x7f}); n != 0x7fffffff || size != 5 {
		t.Fatalf("sqliteVarint(5-byte) = %d,%d", n, size)
	}
	vals, err := sqliteRecord([]byte{0x02, 0x01, 0x2a}) // header=2, serial=1 (1-byte int), body=42
	if err != nil || len(vals) != 1 || vals[0] != int64(42) {
		t.Fatalf("sqliteRecord = %v, %v", vals, err)
	}
	if _, err := sqliteRecord([]byte{0x09, 0x01}); err == nil {
		t.Fatal("sqliteRecord accepted a header past the payload")
	}
}

func TestR2L16ReadExactlyCapEntropyPE(t *testing.T) {
	t.Run("read-exactly", func(t *testing.T) {
		if _, err := readExactly(strings.NewReader("abc"), 5); err == nil || !strings.Contains(err.Error(), "short read") {
			t.Fatalf("readExactly on short reader = %v", err)
		}
	})
	t.Run("op-read-cap", func(t *testing.T) {
		p := r2l16Write(t, "eight.bin", []byte("12345678"))
		if _, err := opRead(p, 4); err == nil || !strings.Contains(err.Error(), "over the 4-byte cap") {
			t.Fatalf("opRead over cap = %v", err)
		}
		if b, err := opRead(p, 8); err != nil || string(b) != "12345678" {
			t.Fatalf("opRead at cap = %q,%v", b, err)
		}
	})
	t.Run("entropy", func(t *testing.T) {
		zero := blockEntropy(make([]byte, 64), 64)
		if len(zero) != 1 || zero[0] != 0 {
			t.Fatalf("blockEntropy(zeros) = %v", zero)
		}
		distinct := make([]byte, 64)
		for i := range distinct {
			distinct[i] = byte(i)
		}
		h := blockEntropy(distinct, 64)
		if len(h) != 1 || math.Abs(h[0]-6) > 0.01 {
			t.Fatalf("blockEntropy(64 distinct) = %v, want ~6", h)
		}
	})
	t.Run("pe", func(t *testing.T) {
		if _, err := openPEBytes([]byte("not a PE at all, long enough to parse")); err == nil {
			t.Fatal("openPEBytes accepted a non-MZ blob")
		}
		p, err := openPEBytes(sfPE(t, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if !p.pe32plus || p.nDirs < uint32(peDirSecurity+1) {
			t.Fatalf("openPEBytes: pe32plus=%v nDirs=%d", p.pe32plus, p.nDirs)
		}
		off, size, err := p.dir(peDirSecurity)
		if err != nil || (off != 0 && size != 0) {
			t.Fatalf("dir(security) = %d,%d,%v", off, size, err)
		}
		if _, _, err := p.dir(99); err == nil {
			t.Fatal("dir accepted an out-of-range index")
		}
		if b, err := p.at(0x100, 4); err != nil || len(b) != 4 {
			t.Fatalf("at(header rva) = %v,%v", b, err)
		}
	})
	t.Run("sha-self-check", func(t *testing.T) {
		// rt2SHA256 above pins the known digest; here round-trip the stdlib
		// primitive to ensure the fixture bytes were not the only thing tested.
		sum := sha256.Sum256([]byte("abc"))
		if hex.EncodeToString(sum[:]) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
			t.Fatal("sha256 primitive check failed")
		}
	})
}
