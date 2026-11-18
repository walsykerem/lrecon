package main

// ROUND 3 audit lane07 — behavior simulation with the real lrecon binary.
// cliPath (cli_test.go TestMain) is built from the source tree; no fake/mock results.

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	r3l07Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l07Test2 = "/Users/keremurhan/kalitetest/test2"
	r3l07Self  = "/Users/keremurhan/walsyrea/lrecon/lrecon"
	r3l07Dex   = "testdata/fixtures/apk/classes.dex"
)

func r3l07JSON(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, s)
	}
	return m
}

func r3l07Result(t *testing.T, s string) map[string]any {
	t.Helper()
	r, ok := r3l07JSON(t, s)["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result object: %s", s)
	}
	return r
}

func r3l07Op(t *testing.T, name, target string, extra ...string) (string, int) {
	t.Helper()
	args := []string{"--op", name, "--json", target}
	args = append(args, extra...)
	return runCLI(t, args...)
}

// Real identity: version and inventory counts match the skill contract exactly.
func TestR3L07BinaryIdentity(t *testing.T) {
	out, code := runCLI(t, "--version")
	if code != 0 || !strings.Contains(out, "lrecon 1.0.0") {
		t.Fatalf("--version = %q rc=%d", out, code)
	}
	out, code = runCLI(t, "--list-ops")
	if code != 0 || len(strings.Split(strings.TrimSpace(out), "\n")) != 235 {
		t.Fatalf("--list-ops count != 235 rc=%d", code)
	}
	out, code = runCLI(t, "--list-ext-ops")
	if code != 0 || len(strings.Split(strings.TrimSpace(out), "\n")) != 80 {
		t.Fatalf("--list-ext-ops count != 80 rc=%d", code)
	}
}

// op_static_util.go opRead path: three real Mach-O digests, real size/sha.
func TestR3L07DigestRealTargets(t *testing.T) {
	for _, target := range []string{r3l07Test1, r3l07Test2, r3l07Self} {
		out, code := runCLI(t, "--json", target)
		if code != 0 {
			t.Fatalf("digest %s rc=%d: %s", target, code, out)
		}
		d := r3l07JSON(t, out)
		if d["kind"] != "macho" || d["format"] != "thin" {
			t.Errorf("%s kind/format = %v/%v", target, d["kind"], d["format"])
		}
		tg := d["target"].(map[string]any)
		st, err := os.Stat(target)
		if err != nil {
			t.Fatal(err)
		}
		if int64(tg["size"].(float64)) != st.Size() {
			t.Errorf("%s size = %v, want %d", target, tg["size"], st.Size())
		}
		b, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		if tg["file_sha256"] != hex.EncodeToString(sum[:]) {
			t.Errorf("%s sha256 mismatch", target)
		}
	}
}

// Y ops: live session/device/endpoint requests are refused on a real target.
func TestR3L07LiveOpsRefuseOnRealArtifact(t *testing.T) {
	cases := map[string]string{
		"close_frida_session":         "out_of_scope",
		"inspect_adb_device":          "no_engine",
		"inspect_web_event_listeners": "bad_arg",
		"read_adb_setting":            "no_engine",
	}
	for op, wantKind := range cases {
		t.Run(op, func(t *testing.T) {
			out, code := r3l07Op(t, op, r3l07Test1)
			if code != 2 {
				t.Fatalf("%s rc=%d, want 2: %s", op, code, out)
			}
			env := r3l07JSON(t, out)
			if env["op"] != op || env["kind"] != wantKind {
				t.Fatalf("%s envelope = op=%v kind=%v, want %s", op, env["op"], env["kind"], wantKind)
			}
			if env["error"] == nil || env["error"] == "" {
				t.Fatalf("%s envelope has no reason: %s", op, out)
			}
		})
	}
}

// inspect_jeb_client: counts classes in a real DEX, refuses a real Mach-O.
func TestR3L07InspectJebClientRealDex(t *testing.T) {
	out, code := r3l07Op(t, "inspect_jeb_client", r3l07Dex)
	if code != 0 {
		t.Fatalf("DEX rc=%d: %s", code, out)
	}
	r := r3l07Result(t, out)
	if r["dex_files"] != float64(1) || r["classes"].(float64) < 1 {
		t.Fatalf("DEX result = %v", r)
	}
	if !strings.Contains(r["reason"].(string), "no static marker") {
		t.Errorf("JEB reason = %v", r["reason"])
	}
	out, code = r3l07Op(t, "inspect_jeb_client", r3l07Test1)
	if code != 2 || r3l07JSON(t, out)["kind"] != "bad_arg" {
		t.Fatalf("Mach-O as DEX rc=%d: %s", code, out)
	}
}

// export_environment_bundle: deterministic tar from a real file, does not write beside the target.
func TestR3L07ExportEnvironmentBundleRealFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "env.tar")
	out, code := r3l07Op(t, "export_environment_bundle", r3l07Test1, "-o", dest)
	if code != 0 {
		t.Fatalf("bundle rc=%d: %s", code, out)
	}
	r := r3l07Result(t, out)
	if r["deterministic"] != true || r["bundle"] != dest {
		t.Fatalf("bundle result = %v", r)
	}
	b, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	if r["bundle_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("bundle sha = %v, disk = %x", r["bundle_sha256"], sum)
	}
	tr := tar.NewReader(bytes.NewReader(b))
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	if len(names) != 2 || names[0] != "manifest.json" || names[1] != "files/test1" {
		t.Fatalf("tar members = %v", names)
	}
	// Same input -> same bytes; the second write is not a conflict, it is idempotent.
	again, code := r3l07Op(t, "export_environment_bundle", r3l07Test1, "-o", dest)
	if code != 0 || r3l07Result(t, again)["bundle_sha256"] != r["bundle_sha256"] {
		t.Fatalf("re-export rc=%d: %s", code, again)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(r3l07Test1), "test1.env.tar")); !os.IsNotExist(err) {
		t.Fatalf("bundle written beside the artifact: %v", err)
	}
	// The write op is refused without -o (needs_arg).
	out, code = r3l07Op(t, "export_environment_bundle", r3l07Test1)
	if code != 2 || r3l07JSON(t, out)["kind"] != "needs_arg" {
		t.Fatalf("bundle without -o rc=%d: %s", code, out)
	}
}

// compress.go post reader: the Mach-O inside a real gzip wrapper is digested.
func TestR3L07CompressReaderRealGzip(t *testing.T) {
	dir := t.TempDir()
	gz := filepath.Join(dir, "test1.gz")
	cmd := exec.Command("gzip", "-c", r3l07Test1)
	f, err := os.Create(gz)
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout = f
	if err := cmd.Run(); err != nil {
		f.Close()
		t.Fatalf("gzip: %v", err)
	}
	f.Close()

	out, code := runCLI(t, "--json", gz)
	if code != 0 {
		t.Fatalf("gzip digest rc=%d: %s", code, out)
	}
	d := r3l07JSON(t, out)
	if d["kind"] != "firmware" || d["format"] != "gzip" || d["firmware_kind"] != "gzip" {
		t.Fatalf("gzip digest = kind=%v format=%v firmware_kind=%v", d["kind"], d["format"], d["firmware_kind"])
	}
	out, code = r3l07Op(t, "inspect_firmware_regions", gz)
	if code != 0 {
		t.Fatalf("firmware regions rc=%d: %s", code, out)
	}
	notes, _ := r3l07Result(t, out)["notes"].([]any)
	joined := ""
	for _, n := range notes {
		joined += n.(string) + "\n"
	}
	if !strings.Contains(joined, "compress: inner=macho") {
		t.Fatalf("no inner-kind note from compress.go: %s", joined)
	}
}
