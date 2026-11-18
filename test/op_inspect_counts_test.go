package main

// Regression tests for the two audit fixes that only had a probe run: the
// P/Invoke listing cap must keep its counts honest past the cut, and the JEB
// client op must not dress a constant "jeb" label as evidence.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// An image with 101 ImplMap rows must report all 101 while listing 100, so a
// reader can tell "the image has 101" from "the listing stopped at 100".
func TestInspectManagedNativeBoundariesCountsPastCap(t *testing.T) {
	if testing.Short() {
		t.Skip("fixture assembly")
	}
	path := metaBBuildPInvokePE(t, metaBPInvokeMetaN(t, 101))
	m := opStatic(t, "inspect_managed_native_boundaries", path)
	if got := opStaticNum(t, m, "pinvokes"); got != 101 {
		t.Fatalf("pinvokes = %d, want 101 (shown %v)", got, m["shown"])
	}
	if got := opStaticNum(t, m, "shown"); got != 100 {
		t.Fatalf("shown = %d, want the 100-row cap", got)
	}
	entries, ok := m["entries"].([]any)
	if !ok || len(entries) != 100 {
		t.Fatalf("entries = %v, want 100 rows", m["entries"])
	}
	first, ok := entries[0].(map[string]any)
	if !ok || first["managed"] != "Say0" || first["native"] != "MessageBoxW" ||
		first["module"] != "KERNEL32.dll" {
		t.Fatalf("first entry = %v", entries[0])
	}
}

// inspect_jeb_client must answer with the observed DEX class count and a reason
// that says why no client is named; a constant client:"jeb" field is a guess.
// The verify op's 100-row listing cap must report the true total, so 101
// boundaries do not read as exactly 100.
func TestVerifyManagedNativeBoundariesCountsPastCap(t *testing.T) {
	path := metaBBuildPInvokePE(t, metaBPInvokeMetaN(t, 101))
	m := opStatic(t, "verify_managed_native_boundaries", path)
	if n := opStaticNum(t, m, "boundaries"); n != 100 {
		t.Fatalf("boundaries = %d, want 100 listed", n)
	}
	if n := opStaticNum(t, m, "boundaries_total"); n != 101 {
		t.Fatalf("boundaries_total = %d, want 101", n)
	}
	if m["truncated"] != true {
		t.Fatalf("truncated = %v, want true", m["truncated"])
	}
	rows, _ := m["rows"].([]any)
	if len(rows) != 100 {
		t.Fatalf("len(rows) = %d, want 100 (the cap must still hold)", len(rows))
	}
}

// The search cap must keep both match counts: class_matches stays "listed",
// the *_total keys carry how many matched, and truncated says a cut happened.
func TestSearchAndroidClassesCountsPastCap(t *testing.T) {
	t.Setenv("LRECON_QUERY", "com/example")
	strs := make([]string, 60)
	types := make([]uint32, 60)
	for i := range strs {
		strs[i] = fmt.Sprintf("Lcom/example/C%02d;", i)
		types[i] = uint32(i)
	}
	path := writeTemp(t, "classes.dex", dexFixture{version: "035", strs: strs, types: types}.build())
	m := opStatic(t, "search_android_classes", path)
	if n := opStaticNum(t, m, "class_matches"); n != 50 {
		t.Fatalf("class_matches = %d, want 50 listed", n)
	}
	if n := opStaticNum(t, m, "class_matches_total"); n != 60 {
		t.Fatalf("class_matches_total = %d, want 60", n)
	}
	if n := opStaticNum(t, m, "string_matches_total"); n != 60 {
		t.Fatalf("string_matches_total = %d, want 60", n)
	}
	if m["truncated"] != true {
		t.Fatalf("truncated = %v, want true", m["truncated"])
	}
	if hits, _ := m["string_hits"].([]any); len(hits) != 50 {
		t.Fatalf("len(string_hits) = %d, want 50 (the cap must still hold)", len(hits))
	}
	if cls, _ := m["classes"].([]any); len(cls) != 50 {
		t.Fatalf("len(classes) = %d, want 50 (the cap must still hold)", len(cls))
	}
}

func TestInspectJebClientNamesNoClient(t *testing.T) {
	apk := jebdApk(t, jebdDex(t))
	m := opStatic(t, "inspect_jeb_client", apk)
	if _, ok := m["client"]; ok {
		t.Fatalf("fabricated client label survived: %v", m)
	}
	if got := opStaticNum(t, m, "classes"); got != 2 {
		t.Fatalf("classes = %d, want 2", got)
	}
	reason := opStaticStr(t, m, "reason")
	if !strings.Contains(reason, "no static marker") || !strings.Contains(reason, "2 DEX classes") {
		t.Fatalf("reason = %q, want the evidence boundary and the count", reason)
	}
}

// A refusal or an error must still name why, and must never fall back to a
// client label.
func TestInspectJebClientRefusalKeepsReason(t *testing.T) {
	dex := jebdDex(t)
	binary.LittleEndian.PutUint32(dex[0x60:], 0) // class_defs_size = 0
	m := opStatic(t, "inspect_jeb_client", jebdApk(t, dex))
	if _, ok := m["client"]; ok {
		t.Fatalf("refusal fabricated a client label: %v", m)
	}
	if msg := opStaticStr(t, m, "skipped"); !strings.Contains(msg, "no DEX classes") {
		t.Fatalf("refusal = %q, want the missing-class reason", msg)
	}

	_, err := runOp("inspect_jeb_client", writeTemp(t, "plain.bin", []byte("not a dex image")))
	if err == nil || !strings.Contains(err.Error(), "is not a DEX image") {
		t.Fatalf("non-DEX error = %v, want the not-a-DEX reason", err)
	}
}

// Every refusal in this lane must land on a kind a caller can switch on. These
// are the malformed targets that used to answer kind=internal (lrecon's own
// fault) because the wording missed every classifier pattern; the target was
// given and wrong, so bad_arg is the answer. Both negative paths per op.
func TestInspectRefusalKinds(t *testing.T) {
	fdt := func(structBlock []byte) []byte {
		hdr := make([]byte, 40)
		be := binary.BigEndian
		be.PutUint32(hdr, 0xd00dfeed)
		be.PutUint32(hdr[4:], uint32(40+len(structBlock)))
		be.PutUint32(hdr[8:], 40)
		be.PutUint32(hdr[12:], uint32(40+len(structBlock)))
		be.PutUint32(hdr[16:], 40)
		be.PutUint32(hdr[20:], 17)
		be.PutUint32(hdr[24:], 16)
		be.PutUint32(hdr[32:], 0)
		be.PutUint32(hdr[36:], uint32(len(structBlock)))
		return append(hdr, structBlock...)
	}
	be := binary.BigEndian
	openNode := func() []byte { // BEGIN_NODE "root", then FDT_END: no END_NODE
		b := be.AppendUint32(nil, 1)
		b = append(b, "root\x00\x00\x00\x00"...)
		return be.AppendUint32(b, 9)
	}
	unbalanced := append(be.AppendUint32(nil, 2), be.AppendUint32(nil, 9)...)

	fuse := func(count byte, body ...byte) []byte {
		return append(append(make([]byte, 8), append([]byte(fuseSentinel), 1, count)...), body...)
	}
	// fatbin: the declared header size pads the 16-byte wrapper, so the TLV
	// body starts at headerSize, not at 16.
	fatbin := func(headerSize uint16, body []byte) []byte {
		b := make([]byte, 16)
		le := binary.LittleEndian
		le.PutUint32(b, gpuFatbinMagic)
		le.PutUint16(b[4:], 1)
		le.PutUint16(b[6:], headerSize)
		le.PutUint64(b[8:], uint64(int(headerSize)+len(body)))
		b = append(b, make([]byte, int(headerSize)-16)...)
		return append(b, body...)
	}
	bean := func(body ...string) []byte {
		b := append([]byte("FOR1"), make([]byte, 4)...)
		b = append(b, "BEAM"...)
		for _, s := range body {
			b = append(b, s...)
		}
		be.PutUint32(b[4:], uint32(len(b)-8))
		return b
	}
	truncELF := make([]byte, 128)
	copy(truncELF, "\x7fELF\x02\x01\x01")
	binary.LittleEndian.PutUint16(truncELF[52:], 0xffff) // e_shstrndx past the table

	cases := []struct {
		op     string
		body   []byte
		kind   errorKind
		substr string
	}{
		{"inspect_dart_aot", []byte("tiny"), kindBadArg, "must be at least 20 bytes for the Dart header"},
		{"inspect_dart_aot", func() []byte {
			b := make([]byte, 20)
			binary.LittleEndian.PutUint32(b, 0xdcdcf5f5)
			binary.LittleEndian.PutUint64(b[4:], 1000)
			return b
		}(), kindBadArg, "is not the size its header declares"},
		{"inspect_electron_fuses", fuse(40), kindBadArg, "count must be 1..32"},
		{"inspect_electron_fuses", fuse(8), kindBadArg, "is not as long as its count declares"},
		{"inspect_electron_fuses", []byte(fuseSentinel), kindBadArg, "carries no fuse version byte"},
		{"inspect_devicetree", fdt(openNode()), kindBadArg, "nodes left open at FDT_END"},
		{"inspect_devicetree", fdt(be.AppendUint32(nil, 4)), kindBadArg, "never reaches FDT_END"},
		{"inspect_devicetree", fdt(unbalanced), kindBadArg, "closes no node"},
		{"inspect_devicetree", fdt(be.AppendUint32(nil, 9)), kindBadArg, "struct block holds none"},
		{"inspect_devicetree", []byte("not a dtb at all"), kindBadArg, "is not a flattened device tree"},
		{"inspect_gpu_code_objects", func() []byte { // header larger than the blob
			b := make([]byte, 48)
			binary.LittleEndian.PutUint32(b, gpuFatbinMagic)
			binary.LittleEndian.PutUint16(b[4:], 1)
			binary.LittleEndian.PutUint16(b[6:], 64)
			binary.LittleEndian.PutUint64(b[8:], 48)
			return b
		}(), kindBadArg, "is not a complete fatbin"},
		{"inspect_gpu_code_objects", fatbin(32, func() []byte {
			tlv := make([]byte, 16)
			binary.LittleEndian.PutUint32(tlv, 1) // PTX
			binary.LittleEndian.PutUint16(tlv[6:], 16)
			binary.LittleEndian.PutUint64(tlv[8:], 99)
			return tlv
		}()), kindBadArg, "declares 99 bytes past the blob"},
		{"inspect_erlang_beam", bean("Atom\x00\x00\x00\x63"), kindBadArg, "past the end"},
		{"inspect_erlang_beam", bean(), kindBadArg, "no chunks follow the header"},
		{"inspect_evm_interface", []byte("0x60"), kindBadArg, "not long enough for a dispatcher"},
		{"inspect_kernel_module", truncELF, kindBadArg, "is not ELF"},
		{"inspect_kernel_module", []byte("plain text"), kindBadArg, "is neither ELF nor Mach-O"},
		{"inspect_jeb_client", []byte("not a dex image"), kindBadArg, "is not a DEX image"},
		{"inspect_elf_notes", []byte("plain text"), kindBadArg, "is not ELF"},
		{"inspect_binary_layout", []byte("plain text"), kindBadArg, "not computed"},
		{"inspect_firmware_regions", []byte("plain text"), kindBadArg, "not a firmware image"},
		{"inspect_il2cpp_metadata", []byte("plain text"), kindBadArg, "carries no IL2CPP"},
		{"inspect_go_binary", []byte("plain text"), kindBadArg, "is not a native image"},
		{"inspect_desktop_application", []byte("plain text"), kindBadArg, "not a desktop app bundle"},
		{"inspect_electron_page", []byte("unused"), kindBadArg, "is not a DevTools endpoint"},
	}
	for _, c := range cases {
		t.Run(c.op+"/"+c.substr, func(t *testing.T) {
			// A refusal can arrive as an error or as a skip; both reach the
			// same classify(), so both must land on the same kind.
			m, err := runOp(c.op, opStaticFile(t, "bad", c.body))
			msg := ""
			if err != nil {
				msg = err.Error()
			} else {
				// A skip marshals to {"skipped": "..."}, same shape a
				// caller sees on stdout.
				raw, mErr := json.Marshal(m)
				if mErr != nil {
					t.Fatalf("%s result is not JSON: %v", c.op, mErr)
				}
				var r map[string]any
				if uErr := json.Unmarshal(raw, &r); uErr != nil {
					t.Fatalf("%s result is not an object: %v", c.op, uErr)
				}
				msg, _ = r["skipped"].(string)
			}
			if msg == "" {
				t.Fatalf("%s accepted the malformed target", c.op)
			}
			if !strings.Contains(msg, c.substr) {
				t.Fatalf("%s refusal = %q, want %q", c.op, msg, c.substr)
			}
			if got := classify(msg); got != c.kind {
				t.Fatalf("%s kind = %s, want %s (message %q)", c.op, got, c.kind, msg)
			}
		})
	}
}

// A malformed target that is still recognisable enough to read has no numbers
// to report: it must refuse with the reason, not answer with a zero.
func TestInspectRefusalSkips(t *testing.T) {
	// fatbin: the declared header size pads the 16-byte wrapper, so the TLV
	// body starts at headerSize, not at 16.
	fatbin := func(headerSize uint16, body []byte) []byte {
		b := make([]byte, 16)
		le := binary.LittleEndian
		le.PutUint32(b, gpuFatbinMagic)
		le.PutUint16(b[4:], 1)
		le.PutUint16(b[6:], headerSize)
		le.PutUint64(b[8:], uint64(int(headerSize)+len(body)))
		b = append(b, make([]byte, int(headerSize)-16)...)
		return append(b, body...)
	}
	bean := func(body ...string) []byte {
		b := append([]byte("FOR1"), make([]byte, 4)...)
		b = append(b, "BEAM"...)
		for _, s := range body {
			b = append(b, s...)
		}
		binary.BigEndian.PutUint32(b[4:], uint32(len(b)-8))
		return b
	}
	for _, c := range []struct {
		op, name, substr string
		body             []byte
	}{
		{"inspect_gpu_code_objects", "fatbin.bin", "carries no PTX or CUBIN entry", fatbin(32, make([]byte, 16))},
		{"inspect_erlang_beam", "atoms.beam", "carries no readable atom", bean("Atom\x00\x00\x00\x04\x00\x00\x00\x00")},
	} {
		m := opStatic(t, c.op, opStaticFile(t, c.name, c.body))
		if !strings.Contains(opStaticStr(t, m, "skipped"), c.substr) {
			t.Fatalf("%s refusal = %v", c.op, m)
		}
	}
}

// The three ops whose malformed targets are refusals rather than errors still
// have to be refusals with a reason, not a zero.
func TestInspectRefusalsKeepReason(t *testing.T) {
	if m := opStatic(t, "inspect_go_binary", opStaticFile(t, "plain", []byte("plain text"))); !strings.Contains(
		opStaticStr(t, m, "skipped"), "is not a native image") {
		t.Fatalf("go_binary refusal = %v", m)
	}
	if m := opStatic(t, "inspect_il2cpp_metadata", opStaticFile(t, "plain", []byte("plain text"))); !strings.Contains(
		opStaticStr(t, m, "skipped"), "carries no IL2CPP") {
		t.Fatalf("il2cpp refusal = %v", m)
	}
	if m := opStatic(t, "inspect_desktop_application", opStaticFile(t, "plain", []byte("plain text"))); !strings.Contains(
		opStaticStr(t, m, "skipped"), "not a desktop app bundle") {
		t.Fatalf("desktop refusal = %v", m)
	}
	for _, c := range []struct{ op, substr string }{
		{"inspect_binary_layout", `layout not computed for kind "text"`},
		{"inspect_byte_entropy", "must be at least one 4096-byte block"},
		{"inspect_firmware_regions", "is not a firmware image"},
	} {
		m := opStatic(t, c.op, opStaticFile(t, "fixture", []byte("plain text")))
		if !strings.Contains(opStaticStr(t, m, "skipped"), c.substr) {
			t.Fatalf("%s refusal = %v", c.op, m)
		}
	}
}

// inspect_elf_notes had no test at all: the note decoder, the GNU build-id hex
// and the owner list must all come from the PT_NOTE segment.
func TestInspectElfNotesPositive(t *testing.T) {
	m := opStatic(t, "inspect_elf_notes", opStaticFile(t, "elfnote", sfELFNote()))
	if got := opStaticStr(t, m, "machine"); got != "EM_X86_64" {
		t.Fatalf("machine = %q", got)
	}
	if got := opStaticStr(t, m, "build_id"); got != "deadbeef0102030405060708090a0b0c0d0e0f10" {
		t.Fatalf("build_id = %q", got)
	}
	owners, ok := m["owners"].([]any)
	if !ok || len(owners) != 1 || owners[0] != "GNU" {
		t.Fatalf("owners = %v", m["owners"])
	}
	notes, ok := m["notes"].([]any)
	if !ok || len(notes) != 1 {
		t.Fatalf("notes = %v", m["notes"])
	}
	first, _ := notes[0].(map[string]any)
	if first["type"] != float64(3) || first["bytes"] != float64(20) {
		t.Fatalf("note = %v", notes[0])
	}
}

// inspect_kernel_module reads .modinfo key=value rows and counts every row, not
// just the ones it lists; the module name comes from the "name" key.
func TestInspectKernelModuleModinfoFieldCount(t *testing.T) {
	body := []byte("name=acme_net\x00vermagic=5.10.0 SMP\x00license=GPL\x00depends=\x00")
	m := opStatic(t, "inspect_kernel_module", writeTemp(t, "acme.ko", modinfoELF(body)))
	if got := opStaticStr(t, m, "module"); got != "acme_net" {
		t.Fatalf("module = %q", got)
	}
	if got := opStaticNum(t, m, "fields_total"); got != 4 {
		t.Fatalf("fields_total = %d, want 4", got)
	}
	if got := opStaticStr(t, m, "os"); got != "linux" {
		t.Fatalf("os = %q", got)
	}
}

// A v16 FDT stops its header at 36 bytes and has no sizeStruct field, so its
// struct block starts where a v17 header would still be running.
func TestInspectDeviceTreeV16(t *testing.T) {
	be := binary.BigEndian
	strs := []byte("\x00model\x00compatible\x00")
	var sb []byte
	sb = be.AppendUint32(sb, 1) // BEGIN_NODE "root"
	sb = append(sb, "root\x00"...)
	sb = append(sb, 0, 0, 0)
	sb = be.AppendUint32(sb, 3) // PROP model
	sb = be.AppendUint32(sb, 8)
	sb = be.AppendUint32(sb, 1)
	sb = append(sb, "acme v16"...)
	sb = be.AppendUint32(sb, 3) // PROP compatible
	sb = be.AppendUint32(sb, 8)
	sb = be.AppendUint32(sb, 7)
	sb = append(sb, "acme,v16"...)
	sb = be.AppendUint32(sb, 2) // END_NODE
	sb = be.AppendUint32(sb, 9) // END
	const hdr = 36
	var b []byte
	b = be.AppendUint32(b, 0xd00dfeed)
	b = be.AppendUint32(b, uint32(hdr+len(sb)+len(strs)))
	b = be.AppendUint32(b, hdr)
	b = be.AppendUint32(b, uint32(hdr+len(sb)))
	b = be.AppendUint32(b, 0)  // offMemReserve
	b = be.AppendUint32(b, 16) // version
	b = be.AppendUint32(b, 0)  // lastCompVersion
	b = be.AppendUint32(b, 0)  // offBootCPUID
	b = be.AppendUint32(b, uint32(len(strs)))
	b = append(b, sb...)
	b = append(b, strs...)
	m := opStatic(t, "inspect_devicetree", opStaticFile(t, "board16.dtb", b))
	if got := opStaticNum(t, m, "version"); got != 16 {
		t.Fatalf("version = %d", got)
	}
	if got := opStaticStr(t, m, "model"); got != "acme v16" {
		t.Fatalf("model = %q", got)
	}
	if got := opStaticStr(t, m, "compatible"); got != "acme,v16" {
		t.Fatalf("compatible = %q", got)
	}
}

// A list-valued key is never null: an Electron app with no recorded
// capabilities must answer [], so a consumer can range over it.
func TestInspectDesktopCapabilitiesIsList(t *testing.T) {
	dir := t.TempDir()
	res := filepath.Join(dir, "Acme.app", "Contents", "Resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatal(err)
	}
	writeAsarArchive(t, res, "app.asar", map[string][]byte{"main.js": []byte("console.log(1)\n")})
	m := opStatic(t, "inspect_desktop_application", filepath.Join(dir, "Acme.app"))
	caps, ok := m["capabilities"].([]any)
	if !ok || len(caps) != 0 {
		t.Fatalf("capabilities = %v (%T), want an empty list", m["capabilities"], m["capabilities"])
	}
}

// The four ops whose source files needed no fix still owe the same proof:
// a positive answer on a real target, from a test, not only from a CLI run.
func TestInspectLayoutFirmwareIL2CPPPositive(t *testing.T) {
	elfPath := constELF(t, nil)
	lay := opStatic(t, "inspect_binary_layout", elfPath)
	if got := opStaticStr(t, lay, "format"); got != "elf" {
		t.Fatalf("layout format = %q, want elf", got)
	}
	if n, _ := lay["sections"].([]any); len(n) == 0 {
		t.Fatalf("layout reported no sections for %s: %v", elfPath, lay)
	}

	fw := append([]byte("hsqs"), make([]byte, 2044)...)
	fw = append(fw, make([]byte, 4096)...)
	fwm := opStatic(t, "inspect_firmware_regions", opStaticFile(t, "firmware", fw))
	if got := opStaticNum(t, fwm, "regions"); got < 1 {
		t.Fatalf("firmware regions = %d, want at least 1: %v", got, fwm)
	}
	if got := opStaticStr(t, fwm, "kind"); got == "" {
		t.Fatalf("firmware kind is empty: %v", fwm)
	}

	il := opStatic(t, "inspect_il2cpp_metadata", constELF(t, []byte("global-metadata.dat\x00Unity 2021.3.15f1\x00")))
	caps, _ := il["capabilities"].([]any)
	found := false
	for _, c := range caps {
		if s, _ := c.(string); s == "il2cpp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("il2cpp capabilities = %v, want one named il2cpp", caps)
	}
}

// The positive path of the CDP op without a socket: the transport is the seam,
// so a stubbed driver answers the fixed three-step spec and the UA is read.
func TestInspectElectronPageFromUA(t *testing.T) {
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", nil),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "string", "value": "no-process"}}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{
			"type":  "string",
			"value": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/130.0.0.0 Electron/33.2.1 Safari/537.36",
		}}),
	}})
	m := opStatic(t, "inspect_electron_page", "127.0.0.1:9333")
	if got := opStaticStr(t, m, "electron_version"); got != "33.2.1" {
		t.Fatalf("electron_version = %q, want 33.2.1 (%v)", got, m)
	}
	if got := opStaticStr(t, m, "chrome_version"); got != "130.0.0.0" {
		t.Fatalf("chrome_version = %q, want 130.0.0.0 (%v)", got, m)
	}
	if got := opStaticStr(t, m, "value"); got != "no-process" {
		t.Fatalf("value = %q, want no-process (%v)", got, m)
	}
}

// The other negative path of the CDP op: a real endpoint nobody listens on is
// a missing engine, not a bad argument.
func TestInspectElectronPageClosedPort(t *testing.T) {
	_, err := runOp("inspect_electron_page", "127.0.0.1:9")
	if err == nil {
		t.Fatal("a closed CDP port was accepted")
	}
	if got := classify(err.Error()); got != kindNoEngine {
		t.Fatalf("kind = %s, want %s (message %q)", got, kindNoEngine, err)
	}
}

// The streaming read must not change a single number: same blocks, same
// rounding, as one whole-file blockEntropy pass over the same bytes.
func TestInspectByteEntropyStreamsLikeWholeRead(t *testing.T) {
	var b []byte
	b = append(b, make([]byte, 4096)...)               // plain
	b = append(b, bytes.Repeat([]byte{0x5a}, 4096)...) // plain
	for i := range 4096 {                              // packed
		b = append(b, byte(i*37), byte(i*91), byte(i>>3), byte(i*173))
	}
	b = append(b, []byte("tail shorter than one block")...)

	m := opStatic(t, "inspect_byte_entropy", opStaticFile(t, "entropy", b))
	want := blockEntropy(b, 4096)
	sort.Float64s(want)
	if got := opStaticNum(t, m, "blocks"); got != len(want) {
		t.Fatalf("blocks = %d, want %d", got, len(want))
	}
	if got := opStaticNum(t, m, "min"); float64(got) != want[0] {
		t.Fatalf("min = %d, want %v", got, want[0])
	}
	mx := m["max"].(float64)
	if mx != want[len(want)-1] {
		t.Fatalf("max = %v, want %v", mx, want[len(want)-1])
	}
}

func BenchmarkInspectByteEntropy(b *testing.B) {
	body := make([]byte, 16<<20)
	for i := range body {
		body[i] = byte(i * 31)
	}
	path := filepath.Join(b.TempDir(), "entropy.bin")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := ops["inspect_byte_entropy"].run(path); err != nil {
			b.Fatal(err)
		}
	}
}

// hasMarker must answer exactly what bytes.Contains(head(path, max), marker)
// answers, including a marker that straddles the streaming window boundary.
func TestHasMarkerStraddlesWindow(t *testing.T) {
	marker := []byte("\xff Go build ID:")
	body := make([]byte, 200<<10)
	copy(body[64<<10-5:], marker) // starts 5 bytes before the first window ends
	p := writeTemp(t, "straddle.bin", body)
	if !hasMarker(p, marker, maxGoInfoScan) {
		t.Fatal("marker across the 64 KiB boundary was missed")
	}
	body[64<<10-5] = 0
	if hasMarker(writeTemp(t, "absent.bin", body), marker, maxGoInfoScan) {
		t.Fatal("absent marker reported present")
	}
	if hasMarker(p, marker, 100) {
		t.Fatal("marker past maxScan reported present")
	}
}

// The scan reads a 64 KiB window instead of copying the whole prefix.
func BenchmarkMarkerScan(b *testing.B) {
	body := make([]byte, 8<<20)
	body[7<<20] = 0xff
	p := filepath.Join(b.TempDir(), "big.bin")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		hasMarker(p, goBuildIDMarker, maxGoInfoScan)
	}
}

// TestFirmwareRegionsRefusesVerifiedFormat pins F2: the fallback carve used to
// read container magics inside any file, so a Mach-O holding "hsqs" answered
// kind:squashfs regions:1. The fixture is a real Mach-O with that magic
// appended, the shape the pinned Go binary itself tripped (regions:8).
func TestFirmwareRegionsRefusesVerifiedFormat(t *testing.T) {
	body, err := os.ReadFile("testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, []byte("hsqs")...)
	m := opStatic(t, "inspect_firmware_regions", opStaticFile(t, "macho-squashfs", body))
	reason := opStaticStr(t, m, "skipped")
	if !strings.Contains(reason, "macho") || classify(reason) != kindBadArg {
		t.Fatalf("refusal = %q (%s), want bad_arg naming the detected Mach-O", reason, classify(reason))
	}
	if _, ok := m["regions"]; ok {
		t.Fatalf("carved regions out of a Mach-O: %v", m)
	}
}

// TestEVMRefusesVerifiedFormat pins F3: the dispatcher scan used to run over
// any bytes, so a Mach-O with PUSH4/EQ-shaped payload answered code_bytes and
// selectors. The fixture is a real Mach-O with that byte pair appended.
func TestEVMRefusesVerifiedFormat(t *testing.T) {
	body, err := os.ReadFile("testdata/fixtures/macho")
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, 0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14) // PUSH4 0xaabbccdd EQ
	m := opStatic(t, "inspect_evm_interface", opStaticFile(t, "macho-evm", body))
	reason := opStaticStr(t, m, "skipped")
	if !strings.Contains(reason, "macho") || classify(reason) != kindBadArg {
		t.Fatalf("refusal = %q (%s), want bad_arg naming the detected Mach-O", reason, classify(reason))
	}
	if _, ok := m["selectors"]; ok {
		t.Fatalf("fabricated selectors over a Mach-O: %v", m)
	}
}
