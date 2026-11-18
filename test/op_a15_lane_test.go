package main

// Lane A15 pins. The six ops below report argument and "nothing to do" failures
// as text, and main re-classifies that text (refuse -> classify), so the wording
// is the contract: each of these tests fails if a message stops carrying a
// bad_arg/needs_arg phrase and the CLI quietly reports kind "internal" instead.

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func a15SetOutput(t *testing.T, out string) {
	t.Helper()
	old := opOutput
	opOutput = out
	t.Cleanup(func() { opOutput = old })
}

func a15Artifact(t *testing.T) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	return p
}

func a15Write(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func a15Result(t *testing.T, res any) map[string]any {
	t.Helper()
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return m
}

func a15WantKind(t *testing.T, msg string, want errorKind) {
	t.Helper()
	if got := classify(msg); got != want {
		t.Fatalf("%q classified %q, want %q", msg, got, want)
	}
}

func TestA15DestRefusalsKeepBadArg(t *testing.T) {
	art := a15Artifact(t)
	a15SetOutput(t, art)
	if _, err := exportDest("export_evidence_bundle", art, "", false); err == nil {
		t.Fatal("file destination over the artifact was accepted")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
	if _, err := exportDest("export_web_scripts", art, "", true); err == nil {
		t.Fatal("file destination for a tree op was accepted")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
	// The same refusal reached through the op itself: main only keeps the kind
	// from checkOpOutput, so the run text has to classify on its own.
	if _, err := runOp("export_evidence_bundle", art); err == nil {
		t.Fatal("op wrote over the artifact it reads")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
}

func TestA15OutputPolicyKinds(t *testing.T) {
	art := a15Artifact(t)
	if err := checkOpOutput("export_web_scripts", ""); err == nil {
		t.Fatal("writing op accepted a call with no -o")
	} else {
		a15WantKind(t, err.Error(), kindNeedsArg)
	}
	if err := checkOpOutput("get_call_graph", art); err == nil {
		t.Fatal("-o accepted on an op that writes nothing")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
	a15WantKind(t, (&metaAttestationError{File: "x.json", Claimed: "sha256:aa", Actual: "sha256:bb"}).Error(), kindBadArg)
}

func TestA15EvidenceRoundTripAndTamper(t *testing.T) {
	art := a15Artifact(t)
	out := filepath.Join(t.TempDir(), "a.evidence.json")
	a15SetOutput(t, out)
	res, err := runOp("export_evidence_bundle", art)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if att, _ := a15Result(t, res)["attestation"].(string); att == "" {
		t.Fatalf("no attestation in %v", res)
	}
	if _, _, err := metaReadEvidenceFile(out); err != nil {
		t.Fatalf("read back: %v", err)
	}
	g, err := runOp("get_evidence_bundle", out)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if v, _ := a15Result(t, g)["verified"].(bool); !v {
		t.Fatalf("bundle not verified: %v", g)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read %s: %v", out, err)
	}
	var w metaEvidenceWrapper
	if err := json.Unmarshal(b, &w); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	w.Bundle.Size++
	tampered, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if err := os.WriteFile(out, tampered, 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", out, err)
	}
	_, _, err = metaReadEvidenceFile(out)
	if err == nil {
		t.Fatal("tampered bundle was accepted")
	}
	if _, ok := errors.AsType[*metaAttestationError](err); !ok {
		t.Fatalf("want *metaAttestationError, got %T: %v", err, err)
	}
	a15WantKind(t, err.Error(), kindBadArg)
}

func TestA15WebScriptsZip(t *testing.T) {
	zp := writeZip(t, "a.zip", []zipEntry{
		{"app.js", []byte("console.log(1)")},
		{"index.html", []byte("<p>")},
		{"assets/logo.png", []byte("\x89PNG")},
	})
	out := filepath.Join(t.TempDir(), "scripts")
	a15SetOutput(t, out)
	res, err := runOp("export_web_scripts", zp)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	scripts, _ := a15Result(t, res)["scripts"].([]any)
	if len(scripts) != 1 || scripts[0] != "app.js" {
		t.Fatalf("scripts = %v, want [app.js]", a15Result(t, res)["scripts"])
	}
	if _, err := os.Stat(filepath.Join(out, "app.js")); err != nil {
		t.Fatalf("app.js not written: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, "assets", "logo.png")); err == nil {
		t.Fatal("non-script member was exported")
	}
}

func TestA15WebScriptsRefusesEscape(t *testing.T) {
	zp := writeZip(t, "slip.zip", []zipEntry{
		{"../evil.js", []byte("x")},
		{"ok.js", []byte("y")},
	})
	base := t.TempDir()
	out := filepath.Join(base, "scripts")
	a15SetOutput(t, out)
	if _, err := runOp("export_web_scripts", zp); err == nil {
		t.Fatal("archive member escaping the tree was accepted")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
	if _, err := os.Stat(filepath.Join(base, "evil.js")); err == nil {
		t.Fatal("member escaped the export directory")
	}
}

func TestA15WebScriptsNothingToDoIsBadArg(t *testing.T) {
	zp := writeZip(t, "noscript.zip", []zipEntry{{"assets/logo.png", []byte("\x89PNG")}})
	out := filepath.Join(t.TempDir(), "scripts")
	a15SetOutput(t, out)
	if _, err := runOp("export_web_scripts", zp); err == nil {
		t.Fatal("archive without script members was exported")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
	// The failed export must not leave the directory it created behind.
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("failed export left %s behind", out)
	}
}

func TestA15FirmwareParts(t *testing.T) {
	body := append([]byte("hsqs"), make([]byte, 64)...)
	body = append(body, []byte("UBI#")...)
	body = append(body, make([]byte, 32)...)
	p := a15Write(t, t.TempDir(), "fw.bin", body)
	out := filepath.Join(t.TempDir(), "fw")
	a15SetOutput(t, out)
	res, err := runOp("extract_firmware", p)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	parts, _ := a15Result(t, res)["parts"].([]any)
	if len(parts) != 2 {
		t.Fatalf("parts = %v, want 2", a15Result(t, res)["parts"])
	}
	first, _ := parts[0].(map[string]any)
	if first["file"] != "00-squashfs.bin" || first["name"] != "squashfs" {
		t.Fatalf("first part = %v", first)
	}
	if _, err := os.Stat(filepath.Join(out, "01-ubi.bin")); err != nil {
		t.Fatalf("second part not written: %v", err)
	}
}

func TestA15FirmwareSkipIsBadArg(t *testing.T) {
	p := a15Write(t, t.TempDir(), "junk.bin", []byte("garbage"))
	a15SetOutput(t, filepath.Join(t.TempDir(), "fw"))
	res, err := runOp("extract_firmware", p)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	s, ok := res.(*skip)
	if !ok {
		t.Fatalf("want *skip, got %T: %v", res, res)
	}
	a15WantKind(t, s.Reason, kindBadArg)
}

func TestA15ObjcSkipsAreBadArg(t *testing.T) {
	p := a15Write(t, t.TempDir(), "plain.bin", []byte("not a mach-o file"))
	for _, name := range []string{"get_objc_classes", "get_objc_protocols"} {
		res, err := runOp(name, p)
		msg := ""
		switch v := res.(type) {
		case *skip:
			msg = v.Reason
		}
		if err != nil {
			msg = err.Error()
		}
		if msg == "" {
			t.Fatalf("%s: no refusal for a non-Mach-O target", name)
		}
		a15WantKind(t, msg, kindBadArg)
	}
}

func TestA15EnvironmentBundleDeterministic(t *testing.T) {
	art := a15Artifact(t)
	dir := t.TempDir()
	a15SetOutput(t, filepath.Join(dir, "a.tar"))
	r1, err := runOp("export_environment_bundle", art)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	a15SetOutput(t, filepath.Join(dir, "b.tar"))
	r2, err := runOp("export_environment_bundle", art)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	s1, _ := a15Result(t, r1)["bundle_sha256"].(string)
	s2, _ := a15Result(t, r2)["bundle_sha256"].(string)
	if s1 == "" || s1 != s2 {
		t.Fatalf("bundle digests differ: %q vs %q", s1, s2)
	}
	if kind, _ := a15Result(t, r1)["manifest"].(map[string]any)["kind"].(string); kind != "lrecon.env/1" {
		t.Fatalf("manifest kind = %q", kind)
	}
}

func TestA15EnvironmentDuplicateBaseIsBadArg(t *testing.T) {
	art := a15Artifact(t)
	job := a15Write(t, t.TempDir(), "job.json", []byte(`{"file":"`+art+`","include":["`+art+`"]}`))
	a15SetOutput(t, filepath.Join(t.TempDir(), "a.tar"))
	if _, err := runOp("export_environment_bundle", job); err == nil {
		t.Fatal("two inputs sharing one base name were accepted")
	} else {
		a15WantKind(t, err.Error(), kindBadArg)
	}
}

func TestA15NavigationContextNeedsSession(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	if _, err := runOp("get_navigation_context", ""); err == nil {
		t.Fatal("navigation context served without a session")
	} else {
		a15WantKind(t, err.Error(), kindNoEngine)
	}
}

func TestA15ImportEvidenceMatchesArtifact(t *testing.T) {
	art := a15Artifact(t)
	out := filepath.Join(t.TempDir(), "a.evidence.json")
	a15SetOutput(t, out)
	if _, err := runOp("export_evidence_bundle", art); err != nil {
		t.Fatalf("export: %v", err)
	}
	res, err := runOp("import_evidence_bundle", out)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	m := a15Result(t, res)
	if m["artifact_match"] != true || m["artifact_checked"] != true {
		t.Fatalf("artifact_match=%v artifact_checked=%v, want true/true", m["artifact_match"], m["artifact_checked"])
	}
}

// The zip header states each member's size, so the read can be sized once.
// These two benchmarks are the same read with and without that hint: the op
// output is byte-identical either way.
func BenchmarkA15ScriptBodyPrealloc(b *testing.B) { a15BenchScriptBody(b, true) }
func BenchmarkA15ScriptBodyReadAll(b *testing.B)  { a15BenchScriptBody(b, false) }

func a15BenchScriptBody(b *testing.B, prealloc bool) {
	b.Helper()
	p := filepath.Join(b.TempDir(), "big.zip")
	f, err := os.Create(p)
	if err != nil {
		b.Fatalf("create %s: %v", p, err)
	}
	zw := zip.NewWriter(f)
	w, err := zw.Create("big.js")
	if err != nil {
		b.Fatalf("zip entry: %v", err)
	}
	body := bytes.Repeat([]byte("a"), 4<<20)
	if _, err := w.Write(body); err != nil {
		b.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		b.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		b.Fatalf("close %s: %v", p, err)
	}
	zr, err := zip.OpenReader(p)
	if err != nil {
		b.Fatalf("open %s: %v", p, err)
	}
	defer zr.Close()
	zf := zr.File[0]
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rc, err := zf.Open()
		if err != nil {
			b.Fatalf("member open: %v", err)
		}
		var got []byte
		if prealloc {
			got, err = readScriptBody(rc, zf.UncompressedSize64)
		} else {
			got, err = io.ReadAll(io.LimitReader(rc, maxExportScript))
		}
		rc.Close()
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if len(got) != len(body) {
			b.Fatalf("read %d bytes, want %d", len(got), len(body))
		}
	}
}
