package main

import (
	"archive/zip"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const reaMobileManifest = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.rea">` +
	`<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34"/>` +
	`<uses-permission android:name="android.permission.INTERNET"/>` +
	`</manifest>`

func reaMobileRun(t *testing.T, name, path string) any {
	t.Helper()
	o, ok := ops[name]
	if !ok {
		t.Fatalf("op %q is not registered", name)
	}
	v, err := o.run(path)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func reaMobileMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("result is not JSON-marshalable: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("result is not a JSON object: %v", err)
	}
	return m
}

func reaMobileSkip(t *testing.T, name, path string) string {
	t.Helper()
	v := reaMobileRun(t, name, path)
	s, ok := v.(*skip)
	if !ok {
		t.Fatalf("%s: expected skip for %s, got %T", name, path, v)
	}
	return s.Reason
}

func reaMobileZip(t *testing.T, path string, files map[string]string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip entry %q: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("zip write %q: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}

func reaMobileText(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("plain text, no container"), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// reaMobileAsar writes a one-file asar: 16-byte frame, a header JSON whose file
// table points at a body right after the padded header.
func reaMobileAsar(t *testing.T, path string) {
	t.Helper()
	body := "hi"
	hdrJSON := `{"files":{"index.js":{"size":2,"offset":"0"}}}`
	jsonLen := len(hdrJSON)
	base := (16 + jsonLen + 3) &^ 3
	hdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(hdr[0:], 4)
	binary.LittleEndian.PutUint32(hdr[4:], uint32(base-8))
	binary.LittleEndian.PutUint32(hdr[8:], uint32(jsonLen+len(body)))
	binary.LittleEndian.PutUint32(hdr[12:], uint32(jsonLen))
	raw := append(hdr, []byte(hdrJSON)...)
	for len(raw) < base {
		raw = append(raw, 0)
	}
	raw = append(raw, []byte(body)...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReaMobileRegistered(t *testing.T) {
	for _, name := range []string{
		"inspect_android_package",
		"identify_flutter_build",
		"inspect_desktop_application",
		"inspect_asset_catalog",
		"extract_artifact",
	} {
		o, ok := ops[name]
		if !ok {
			t.Fatalf("%s is not registered", name)
		}
		if o.route != "L" || !o.needs || o.desc == "" {
			t.Fatalf("%s: route=%q needs=%v desc=%q", name, o.route, o.needs, o.desc)
		}
	}
}

func TestReaMobileAndroidPackage(t *testing.T) {
	dir := t.TempDir()
	apk := filepath.Join(dir, "app.apk")
	reaMobileZip(t, apk, map[string]string{"AndroidManifest.xml": reaMobileManifest})

	m := reaMobileMap(t, reaMobileRun(t, "inspect_android_package", apk))
	if m["kind"] != "apk" {
		t.Fatalf("kind = %v, want apk", m["kind"])
	}
	if m["package"] != "com.example.rea" {
		t.Fatalf("package = %v", m["package"])
	}
	if sdk, _ := m["sdk"].(string); !strings.Contains(sdk, "min 24") || !strings.Contains(sdk, "target 34") {
		t.Fatalf("sdk = %q", sdk)
	}
	perms, _ := m["permissions"].([]any)
	if len(perms) != 1 || perms[0] != "android.permission.INTERNET" {
		t.Fatalf("permissions = %v", m["permissions"])
	}

	reason := reaMobileSkip(t, "inspect_android_package", reaMobileText(t, dir, "note.txt"))
	if !strings.Contains(reason, "not an Android package") || !strings.Contains(reason, "text") {
		t.Fatalf("wrong-kind skip does not name the kind: %q", reason)
	}
}

func TestReaMobileFlutterBuild(t *testing.T) {
	dir := t.TempDir()
	const hash = "3f0a1b2c3d4e5f60718293a4b5c6d7e8"
	snap := make([]byte, 52)
	binary.LittleEndian.PutUint32(snap[0:], 0xdcdcf5f5)
	binary.LittleEndian.PutUint64(snap[4:], uint64(len(snap)-4))
	binary.LittleEndian.PutUint64(snap[12:], 2) // kFullAOT
	copy(snap[20:], hash)
	snapshot := filepath.Join(dir, "snapshot.bin")
	if err := os.WriteFile(snapshot, snap, 0o644); err != nil {
		t.Fatal(err)
	}

	m := reaMobileMap(t, reaMobileRun(t, "identify_flutter_build", snapshot))
	if m["kind"] != "flutter" || m["flutter_hash"] != hash || m["dart_snapshot_kind"] != "full-aot" {
		t.Fatalf("snapshot identity = %v", m)
	}

	apk := filepath.Join(dir, "flutter.apk")
	reaMobileZip(t, apk, map[string]string{
		"AndroidManifest.xml":         reaMobileManifest,
		"lib/arm64-v8a/libflutter.so": "not a real library",
	})
	m = reaMobileMap(t, reaMobileRun(t, "identify_flutter_build", apk))
	caps, _ := m["capabilities"].([]any)
	found := false
	for _, c := range caps {
		if c == "flutter" {
			found = true
		}
	}
	if !found {
		t.Fatalf("package capabilities = %v", m["capabilities"])
	}

	reason := reaMobileSkip(t, "identify_flutter_build", reaMobileText(t, dir, "note.txt"))
	if !strings.Contains(reason, "no Flutter marker") {
		t.Fatalf("wrong-kind skip: %q", reason)
	}
}

func TestReaMobileDesktopApplication(t *testing.T) {
	dir := t.TempDir()
	asar := filepath.Join(dir, "app.asar")
	reaMobileAsar(t, asar)

	m := reaMobileMap(t, reaMobileRun(t, "inspect_desktop_application", asar))
	if m["kind"] != "asar" || m["asar_files"] != float64(1) {
		t.Fatalf("desktop identity = %v", m)
	}

	reason := reaMobileSkip(t, "inspect_desktop_application", reaMobileText(t, dir, "note.txt"))
	if !strings.Contains(reason, "not a desktop app bundle") || !strings.Contains(reason, "text") {
		t.Fatalf("wrong-kind skip does not name the kind: %q", reason)
	}
}

func TestReaMobileAssetCatalog(t *testing.T) {
	dir := t.TempDir()
	car := filepath.Join(dir, "Assets.car")
	if err := os.WriteFile(car, append([]byte("CARV"), make([]byte, 8)...), 0o644); err != nil {
		t.Fatal(err)
	}

	reason := reaMobileSkip(t, "inspect_asset_catalog", car)
	if !strings.Contains(reason, "asset catalog parsing not implemented") || !strings.Contains(reason, "CARV") {
		t.Fatalf("car skip: %q", reason)
	}

	reason = reaMobileSkip(t, "inspect_asset_catalog", reaMobileText(t, dir, "note.txt"))
	if !strings.Contains(reason, "not an asset catalog") || !strings.Contains(reason, "text") {
		t.Fatalf("wrong-kind skip does not name the kind: %q", reason)
	}
}

func TestReaMobileExtractArtifact(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	reaMobileZip(t, "app.apk", map[string]string{"AndroidManifest.xml": reaMobileManifest})

	m := reaMobileMap(t, reaMobileRun(t, "extract_artifact", "app.apk"))
	out, _ := m["output"].(string)
	if out == "" {
		t.Fatalf("no output dir: %v", m)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		t.Fatal(err)
	}
	// With no -o the destination is fresh under the system temp dir, never in
	// the caller's working directory: a library call must not leave a tree
	// beside the caller.
	tmp, err := filepath.Abs(os.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(tmp, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("output %q is not under the temp dir %q (rel %q, %v)", abs, tmp, rel, err)
	}
	if rel, err := filepath.Rel(cwd, abs); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("output %q landed inside the working directory %q", abs, cwd)
	}
	t.Cleanup(func() { os.RemoveAll(out) })
	body, err := os.ReadFile(filepath.Join(out, "AndroidManifest.xml"))
	if err != nil || string(body) != reaMobileManifest {
		t.Fatalf("extracted manifest = %q, %v", body, err)
	}

	reason := reaMobileSkip(t, "extract_artifact", reaMobileText(t, dir, "note.txt"))
	if !strings.Contains(reason, "not an archive") || !strings.Contains(reason, "text") {
		t.Fatalf("wrong-kind skip does not name the kind: %q", reason)
	}

	// A member that climbs must fail the extraction, not land beside the
	// destination tree.
	reaMobileZip(t, "slip.apk", map[string]string{"../escape.txt": "x"})
	o := ops["extract_artifact"]
	if _, err := o.run("slip.apk"); err == nil {
		t.Fatal("extraction of a .. member succeeded")
	}
	escape := filepath.Join(filepath.Dir(abs), "escape.txt")
	if _, err := os.Stat(escape); !os.IsNotExist(err) {
		t.Fatalf("zip-slip wrote outside the destination tree: %s", escape)
	}
}

// TestReaMobileGraphRefusalKinds pins the four project_* graphs on the same
// three answers, then proves the happy path on a real .hap zip: a module.json
// becomes a module node with its abilities, and a broken module.json is a
// bad_arg rather than an empty graph.
func TestReaMobileGraphRefusalKinds(t *testing.T) {
	text := writeTemp(t, "note.txt", []byte("plain text, no container"))
	for _, name := range []string{
		"project_android_application_graph", "project_apple_application_graph",
		"project_harmony_application_graph", "project_managed_application_graph",
	} {
		a21WantKind(t, name, "", kindNeedsArg)
		a21WantKind(t, name, "/nonexistent-xyz", kindIO)
		a21WantKind(t, name, text, kindBadArg)
	}

	hap := a21Zip(t, "hap.zip", map[string]string{
		"module.json":     `{"app":{"bundleName":"com.example.hap","versionName":"1.0.0"},"module":{"name":"entry","mainElement":"EntryAbility","abilities":[{"name":"EntryAbility"}]}}`,
		"ets/modules.abc": "abc",
	})
	got, err := runOp("project_harmony_application_graph", hap)
	if err != nil {
		t.Fatalf("harmony graph on a .hap zip: %v", err)
	}
	out := reaObject(t, got)
	if out["format"] != "zip" || out["node_count"] != float64(4) {
		t.Fatalf("harmony graph = %v, want 4 nodes in a zip", out)
	}
	if edges, _ := out["edges"].([]any); len(edges) != 3 {
		t.Fatalf("harmony edges = %v, want 3", out["edges"])
	}

	a21WantKind(t, "project_harmony_application_graph",
		a21Zip(t, "bad.zip", map[string]string{"module.json": "{not json"}), kindBadArg)
}
