package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	elfbin "debug/elf"
)

// TestReaData pins the five data-format inventory items against real fixtures,
// and pins the refusal path: a wrong-kind or empty file must answer with the
// kind it actually is, never with an empty success.
func TestReaData(t *testing.T) {
	pcapPath := writeTemp(t, "dns.pcap",
		pcapLE(1, frameIPv4(17, udpSegment(53, dnsQuery("example.test")))))
	for _, name := range []string{"inspect_packet_capture", "inspect_pcap_capture"} {
		out := reaDataJSON(t, name, pcapPath)
		if out["packets"] != float64(1) || out["link_type"] != "ethernet" || out["span"] == "" {
			t.Fatalf("%s: packets/link_type/span = %v/%v/%v", name, out["packets"], out["link_type"], out["span"])
		}
		if dns := reaDataStrings(out["dns"]); len(dns) != 1 || dns[0] != "example.test" {
			t.Fatalf("%s: dns = %v, want [example.test]", name, out["dns"])
		}
	}

	fwPath := writeTemp(t, "image.bin", append([]byte("hsqs"), make([]byte, 60)...))
	fw := reaDataJSON(t, "inspect_firmware_regions", fwPath)
	if fw["kind"] != "squashfs" || fw["regions"] != float64(1) {
		t.Fatalf("firmware kind/regions = %v/%v, want squashfs/1", fw["kind"], fw["regions"])
	}
	if detail := reaDataStrings(fw["region_detail"]); len(detail) != 1 || detail[0] != "0x00000000 squashfs" {
		t.Fatalf("firmware detail = %v, want [0x00000000 squashfs]", fw["region_detail"])
	}

	db := make([]byte, 100)
	copy(db, "SQLite format 3\x00")
	binary.BigEndian.PutUint16(db[16:18], 4096)
	db[18], db[19] = 1, 1
	binary.BigEndian.PutUint32(db[96:100], 3045000)
	sq := reaDataJSON(t, "inspect_sqlite_database", writeTemp(t, "app.db", db))
	if sq["page_size"] != float64(4096) {
		t.Fatalf("sqlite page_size = %v, want 4096", sq["page_size"])
	}
	if v, _ := sq["version"].(string); !strings.Contains(v, "3.45.0") {
		t.Fatalf("sqlite version = %q, want a 3.45.0 library version", v)
	}
	if sq["wal"] != false {
		t.Fatalf("sqlite wal = %v, want false", sq["wal"])
	}

	plist := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>com.example.demo</string></dict></plist>`
	pl := reaDataJSON(t, "inspect_plist", writeTemp(t, "Info.plist", []byte(plist)))
	if keys := reaDataStrings(pl["keys"]); len(keys) != 1 || keys[0] != "CFBundleIdentifier = com.example.demo" {
		t.Fatalf("plist keys = %v, want the bundle identifier with its value", pl["keys"])
	}

	names := []string{
		"inspect_packet_capture", "inspect_pcap_capture", "inspect_firmware_regions",
		"inspect_sqlite_database", "inspect_plist",
	}
	textPath := writeTemp(t, "note.txt", []byte("plain text, no container here\n"))
	emptyPath := writeTemp(t, "empty.bin", nil)
	for _, name := range names {
		for _, wrong := range []string{textPath, emptyPath} {
			got, err := runOp(name, wrong)
			if err != nil {
				if !strings.Contains(err.Error(), base(wrong)) {
					t.Fatalf("%s rejected %s with an error that does not name it: %v", name, base(wrong), err)
				}
				continue
			}
			s, ok := got.(*skip)
			if !ok || !strings.Contains(s.Reason, base(wrong)) {
				t.Fatalf("%s accepted %s as a success: %#v", name, base(wrong), got)
			}
		}
	}
}

// reaDataJSON runs one op and decodes its JSON shape, so the assertions read the
// same contract a consumer sees.
func reaDataJSON(t *testing.T, name, path string) map[string]any {
	t.Helper()
	got, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("%s: marshal: %v", name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s: unmarshal: %v", name, err)
	}
	return out
}

func reaDataStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// TestReaDataRefusalKinds pins the byte-level ops: a missing target is
// needs_arg, a target not on disk is io, and a non-native file is bad_arg --
// never an empty success. The positive pair reads and then finds the same four
// bytes at the ELF entry, so the two ops agree with each other.
func TestReaDataRefusalKinds(t *testing.T) {
	t.Setenv("LRECON_AT", "0x0")
	t.Setenv("LRECON_LEN", "4")
	t.Setenv("LRECON_PATTERN", "7f454c46")
	t.Setenv("LRECON_QUERY", "ELF")
	text := writeTemp(t, "bytes.txt", []byte("hi there"))
	for _, name := range []string{"read_bytes", "search_bytes", "search_strings"} {
		a21WantKind(t, name, "", kindNeedsArg)
		a21WantKind(t, name, "/nonexistent-xyz", kindIO)
		a21WantKind(t, name, text, kindBadArg)
	}
	// A3: a target with no DEX has no matching classes, so the search answers
	// rc=0 with an empty result instead of bad_arg that ends a sweep.
	a21WantKind(t, "search_android_classes", "", kindNeedsArg)
	a21WantKind(t, "search_android_classes", "/nonexistent-xyz", kindIO)
	if res, err := ops["search_android_classes"].run(text); err != nil {
		t.Fatalf("search_android_classes on a non-DEX file = %v, want an empty result", err)
	} else if b, _ := json.Marshal(res); !strings.Contains(string(b), `"class_matches":0`) {
		t.Fatalf("search_android_classes on a non-DEX file = %s, want class_matches 0", b)
	}

	elfPath := buildTarget(t, "linux", "amd64", "hello.elf")
	ef, err := elfbin.Open(elfPath)
	if err != nil {
		t.Fatalf("open fixture ELF: %v", err)
	}
	defer ef.Close()
	sec := ef.Section(".text")
	if sec == nil {
		t.Fatal("fixture ELF has no .text section")
	}
	data, err := sec.Data()
	if err != nil || ef.Entry < sec.Addr || ef.Entry+4 > sec.Addr+uint64(len(data)) {
		t.Fatalf(".text data = %d bytes err %v, entry %#x outside it", len(data), err, ef.Entry)
	}
	head := data[ef.Entry-sec.Addr:][:4]

	t.Setenv("LRECON_AT", fmt.Sprintf("%#x", ef.Entry))
	rb := reaDataJSON(t, "read_bytes", elfPath)
	if rb["section"] != ".text" || rb["length"] != float64(4) || rb["basis"] != "virtual_address" {
		t.Fatalf("read_bytes at the entry = %v", rb)
	}

	t.Setenv("LRECON_PATTERN", hex.EncodeToString(head))
	sb := reaDataJSON(t, "search_bytes", elfPath)
	if n, _ := sb["hits"].(float64); n < 1 {
		t.Fatalf("search_bytes for the entry bytes = %v, want at least one hit", sb)
	}
}
