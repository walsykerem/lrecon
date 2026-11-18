package main

// Tur 3 audit, lane 23: each test runs a real op path on a real artifact.
// Production code is not loosened; existing test files are not touched.

import (
	"os"
	"strings"
	"testing"
)

const (
	r3l23Test1 = "/Users/keremurhan/kalitetest/test1"
	r3l23Test2 = "/Users/keremurhan/kalitetest/test2"
	r3l23Self  = "/Users/keremurhan/walsyrea/lrecon/lrecon"
)

func r3l23Real(t *testing.T, path string) string {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("real artifact missing %q: %v", path, err)
	}
	return path
}

func TestR3L23ByteEntropyReal(t *testing.T) {
	m := opStatic(t, "inspect_byte_entropy", r3l23Real(t, r3l23Test1))
	if got := opStaticNum(t, m, "block_bytes"); got != 4096 {
		t.Fatalf("block_bytes = %d", got)
	}
	if got := opStaticNum(t, m, "blocks"); got < 2 {
		t.Fatalf("blocks = %d", got)
	}
}

func TestR3L23ListDocumentsReal(t *testing.T) {
	t.Setenv("LRECON_STATE", t.TempDir())
	real := r3l23Real(t, r3l23Test1)
	t.Setenv("LRECON_AT", "0x1000004e8")
	if _, err := runOp("goto_address", real); err != nil {
		t.Fatalf("goto_address(%s): %v", real, err)
	}
	m := opStatic(t, "list_documents", real)
	docs, ok := m["documents"].([]any)
	if !ok || len(docs) == 0 {
		t.Fatalf("documents = %v", m["documents"])
	}
	first, _ := docs[0].(map[string]any)
	if first["exists"] != true || opStaticNum(t, first, "size") <= 0 {
		t.Fatalf("first document = %v", first)
	}
}

func TestR3L23PacketCaptureRefusesMacho(t *testing.T) {
	m := opStatic(t, "inspect_pcap_capture", r3l23Real(t, r3l23Test1))
	if !strings.Contains(opStaticStr(t, m, "skipped"), "is not a packet capture") {
		t.Fatalf("pcap refusal = %v", m)
	}
}

func TestR3L23SearchAndroidClassesHonestNoDex(t *testing.T) {
	t.Setenv("LRECON_QUERY", "_main")
	m := opStatic(t, "search_android_classes", r3l23Real(t, r3l23Test1))
	if !strings.Contains(opStaticStr(t, m, "note"), "is not a DEX image") {
		t.Fatalf("no-dex note = %v", m)
	}
}

func TestR3L23BatchDecompileRealFunctions(t *testing.T) {
	t.Setenv("LRECON_ARGS", "entry,FUN_1000006cc")
	m := opStatic(t, "batch_decompile", r3l23Real(t, r3l23Test1))
	if got := opStaticNum(t, m, "decompiled"); got < 2 {
		t.Fatalf("decompiled = %d, result = %v", got, m)
	}
	if opStaticStr(t, m, "ghidra_version") == "" {
		t.Fatalf("ghidra_version missing: %v", m)
	}
}

func TestR3L23ProcedureAssemblyReal(t *testing.T) {
	t.Setenv("LRECON_NAME", "entry")
	m := opStatic(t, "procedure_assembly", r3l23Real(t, r3l23Test1))
	if got := opStaticNum(t, m, "instructions"); got <= 0 {
		t.Fatalf("instructions = %d", got)
	}
}

func TestR3L23FirmwareMagicKinds(t *testing.T) {
	cases := []struct {
		head []byte
		want string
	}{
		{[]byte("hsqs"), "squashfs"},
		{[]byte("UBI#"), "ubi"},
		{[]byte("\x1f\x8b\x08"), "gzip"},
		{[]byte("\xd0\x0d\xfe\xed"), "dtb"},
	}
	for _, c := range cases {
		if got := firmwareKind(c.head); got != c.want {
			t.Fatalf("firmwareKind(%x) = %q, want %q", c.head, got, c.want)
		}
	}
}
