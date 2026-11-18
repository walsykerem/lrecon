package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The op declares needs=true, so a target that does not exist is io. Reporting
// rc=0 with a note made a typo'd path look like a decoded dir without apktool.yml.
func TestInspectApktoolClientMissingTargetIsIO(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "apktool", "echo 2.9.3")
	t.Setenv("PATH", dir)

	_, err := ops["inspect_apktool_client"].run("/nonexistent-xyz")
	if err == nil {
		t.Fatal("a missing target must refuse, not report a client")
	}
	if got := classify(err.Error()); got != kindIO {
		t.Fatalf("kind = %s, want %s: %v", got, kindIO, err)
	}
}

func TestInspectApktoolClientReadsDecodedDirVersion(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "apktool", "echo 2.9.3")
	t.Setenv("PATH", dir)

	proj := t.TempDir()
	yml := filepath.Join(proj, "apktool.yml")
	if err := os.WriteFile(yml, []byte("!!brut.androlib.meta.MetaInfo\napkFileName: app.apk\nversion: 9.9.9\n"), 0o644); err != nil {
		t.Fatalf("write apktool.yml: %v", err)
	}
	m := reaMobileMap(t, reaMobileRun(t, "inspect_apktool_client", proj))
	if m["decompiled_by"] != "9.9.9" || m["apktool_yml"] != yml {
		t.Fatalf("client = %v, want decompiled_by 9.9.9 from %s", m, yml)
	}
	if m["apktool"] != "2.9.3" {
		t.Fatalf("apktool = %v, want 2.9.3", m["apktool"])
	}
}

// The entry stat is what lets a missing target skip the tool spawns. This
// benchmark measures both paths so the saving is a number, not a claim.
func BenchmarkInspectApktoolClientMissingVsExisting(b *testing.B) {
	bin := b.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "apktool"), []byte("#!/bin/sh\necho 2.9.3\n"), 0o755); err != nil {
		b.Fatalf("write fake apktool: %v", err)
	}
	b.Setenv("PATH", bin)
	proj := b.TempDir()
	if err := os.WriteFile(filepath.Join(proj, "apktool.yml"), []byte("version: 9.9.9\n"), 0o644); err != nil {
		b.Fatalf("write apktool.yml: %v", err)
	}
	b.Run("missing-target", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			opInspectApktoolClient("/nonexistent-xyz")
		}
	})
	b.Run("existing-dir", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			opInspectApktoolClient(proj)
		}
	})
}

// A directory that exists but was not decoded keeps the honest note and rc=0:
// the dir is a valid target, only the file-side trace is missing.
func TestInspectApktoolClientDirWithoutYMLNotes(t *testing.T) {
	dir := t.TempDir()
	a07FakeTool(t, dir, "apktool", "echo 2.9.3")
	t.Setenv("PATH", dir)

	m := reaMobileMap(t, reaMobileRun(t, "inspect_apktool_client", t.TempDir()))
	notes, _ := m["notes"].([]any)
	found := false
	for _, n := range notes {
		if s, _ := n.(string); strings.Contains(s, "no apktool.yml at ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notes = %v, want the no-apktool.yml note", m["notes"])
	}
}
