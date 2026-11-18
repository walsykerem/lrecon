package main

// Round-2 independent audit, LANE 10. Every TestR2L10* case feeds a real
// byte-level fixture through the production op (or its pure helper) and
// asserts the documented behaviour. Production code is never relaxed here.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func r2num(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	return opStaticNum(t, m, key)
}

func r2str(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	return opStaticStr(t, m, key)
}

func r2arr(t *testing.T, m map[string]any, key string) []any {
	t.Helper()
	a, ok := m[key].([]any)
	if !ok {
		t.Fatalf("%s = %v (%T), want array", key, m[key], m[key])
	}
	return a
}

func r2decode(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// r2mustErr asserts an op refuses an invalid input rather than answering it.
func r2mustErr(t *testing.T, name, path string) {
	t.Helper()
	if _, err := runOp(name, path); err == nil {
		t.Fatalf("%s(%s): expected refusal, got none", name, path)
	}
}

// r2optStr reads an optional JSON string key without failing when it is absent.
func r2optStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// --- g1: native image layout / sections / kernel modules -------------------

func TestR2L10BinaryLayoutElfSections(t *testing.T) {
	m := opStatic(t, "inspect_binary_layout", constELF(t, nil))
	rows := r2arr(t, m, "sections")
	if len(rows) == 0 {
		t.Fatalf("sections empty: %v", m)
	}
	first, _ := rows[0].(map[string]any)
	if r2optStr(first, "name") == "" {
		t.Fatalf("section row lacks name: %v", first)
	}
}

func TestR2L10BinaryLayoutRefusesText(t *testing.T) {
	m := opStatic(t, "inspect_binary_layout", opStaticFile(t, "plain", []byte("plain text")))
	if !strings.Contains(r2str(t, m, "skipped"), "layout not computed for kind") {
		t.Fatalf("layout refusal = %v", m)
	}
}

func TestR2L10MachoThinSlices(t *testing.T) {
	path := opStaticFile(t, "thin.macho", objcMachO([]objcSect{{name: "__text", data: []byte{0xc3}}}))
	m := opStatic(t, "inspect_macho", path)
	if got := r2num(t, m, "slices"); got < 1 {
		t.Fatalf("slices = %d", got)
	}
}

func TestR2L10KernelModuleELFAndRefusal(t *testing.T) {
	m := opStatic(t, "inspect_kernel_module", writeTemp(t, "acme.ko", modinfoELF([]byte("name=acme\x00license=GPL\x00\x00"))))
	if r2str(t, m, "module") != "acme" || r2str(t, m, "os") != "linux" {
		t.Fatalf("module = %v", m)
	}
	r2mustErr(t, "inspect_kernel_module", opStaticFile(t, "plain", []byte("not an object")))
}

// --- g2: byte entropy / format coverage ------------------------------------

func TestR2L10EntropyFixture(t *testing.T) {
	m := opStatic(t, "inspect_byte_entropy", opStaticFile(t, "entropy", sfEntropyFixture()))
	if r2num(t, m, "block_bytes") != 4096 || r2num(t, m, "blocks") < 2 {
		t.Fatalf("entropy shape = %v", m)
	}
	if r2num(t, m, "plain_blocks") < 1 || r2num(t, m, "packed_blocks") < 1 {
		t.Fatalf("expected both plain and packed blocks, got %v", m)
	}
}

func TestR2L10EntropyRound2(t *testing.T) {
	cases := []struct{ v, want float64 }{{0, 0}, {1.234, 1.23}, {1.235, 1.24}, {7.995, 8}}
	for _, c := range cases {
		if got := round2(c.v); got != c.want {
			t.Fatalf("round2(%v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestR2L10FormatCoverage(t *testing.T) {
	if got := formatName("macho"); got != "mach-o" {
		t.Fatalf("formatName(macho) = %q", got)
	}
	m, err := runInspectFormatCoverage("")
	if err != nil {
		t.Fatal(err)
	}
	out := r2decode(t, m)
	if len(r2arr(t, out, "supported_formats")) == 0 {
		t.Fatalf("supported_formats empty: %v", out)
	}
}

// --- g3: format containers --------------------------------------------------

func TestR2L10DartAOT(t *testing.T) {
	m := opStatic(t, "inspect_dart_aot", opStaticFile(t, "snapshot", sfDartAOT()))
	if r2str(t, m, "kind") == "" {
		t.Fatalf("dart kind empty: %v", m)
	}
	bad := append([]byte(nil), sfDartAOT()...)
	binary.LittleEndian.PutUint64(bad[4:], 999)
	r2mustErr(t, "inspect_dart_aot", opStaticFile(t, "snapshot-bad", bad))
}

func TestR2L10Devicetree(t *testing.T) {
	m := opStatic(t, "inspect_devicetree", opStaticFile(t, "board.dtb", sfFDT()))
	if r2num(t, m, "nodes") < 1 {
		t.Fatalf("nodes = %v", m["nodes"])
	}
	bad := make([]byte, 64)
	copy(bad, []byte("not a dtb"))
	r2mustErr(t, "inspect_devicetree", opStaticFile(t, "bad.dtb", bad))
}

func TestR2L10ElfNotes(t *testing.T) {
	m := opStatic(t, "inspect_elf_notes", opStaticFile(t, "note.elf", sfELFNote()))
	if r2str(t, m, "build_id") == "" || len(r2arr(t, m, "owners")) == 0 {
		t.Fatalf("elf notes = %v", m)
	}
}

func TestR2L10ErlangBeam(t *testing.T) {
	m := opStatic(t, "inspect_erlang_beam", opStaticFile(t, "mod.beam", sfBEAM()))
	if r2num(t, m, "atoms") < 1 {
		t.Fatalf("atoms = %v", m["atoms"])
	}
	bad := []byte("FOR1\x00\x00\x00\x04BAD!")
	r2mustErr(t, "inspect_erlang_beam", opStaticFile(t, "bad.beam", bad))
}

func TestR2L10FatbinAndCubinArch(t *testing.T) {
	m := opStatic(t, "inspect_gpu_code_objects", opStaticFile(t, "k.fatbin", sfFatbin()))
	if r2num(t, m, "ptx") < 1 {
		t.Fatalf("ptx = %v", m["ptx"])
	}
	elf := make([]byte, 0x40) // cubinArch requires a full 64-byte ELF64 header
	copy(elf, []byte{0x7f, 'E', 'L', 'F'})
	elf[4], elf[5] = 2, 1                        // ELFCLASS64, little-endian
	binary.LittleEndian.PutUint16(elf[16:], 2)   // e_type = ET_EXEC
	binary.LittleEndian.PutUint16(elf[18:], 190) // e_machine = SM_70
	if got := cubinArch(elf); got != "sm_70+" {
		t.Fatalf("cubinArch(190) = %q", got)
	}
}

func TestR2L10JebClient(t *testing.T) {
	dex := jebdDex(t)
	m := opStatic(t, "inspect_jeb_client", jebdApk(t, dex))
	if r2num(t, m, "classes") < 1 || r2num(t, m, "dex_files") < 1 {
		t.Fatalf("jeb counts = %v", m)
	}
	if got := r2str(t, m, "reason"); !strings.Contains(got, "DEX classes across") {
		t.Fatalf("jeb reason = %q", got)
	}
}

func TestR2L10KeyedArchive(t *testing.T) {
	p := opStaticFile(t, "keyed", sfBplist([]sfBP{
		{kind: 'd', keys: []byte{1, 2}, vals: []byte{3, 4}},
		{kind: 's', str: "$archiver"},
		{kind: 's', str: "$objects"},
		{kind: 's', str: "NSKeyedArchiver"},
		{kind: 'a', refs: []byte{5}},
		{kind: 'd', keys: []byte{7}, vals: []byte{6}},
		{kind: 'd', keys: []byte{9}, vals: []byte{8}},
		{kind: 's', str: "$class"},
		{kind: 's', str: "NSString"},
		{kind: 's', str: "$classname"},
	}))
	m := opStatic(t, "inspect_keyed_archive", p)
	if r2str(t, m, "archiver") != "NSKeyedArchiver" || r2num(t, m, "classes") != 1 {
		t.Fatalf("keyed archive = %v", m)
	}
}

// --- g4: refusal paths ------------------------------------------------------

func TestR2L10DesktopRefusesPlain(t *testing.T) {
	m := opStatic(t, "inspect_desktop_application", opStaticFile(t, "plain", []byte("plain text")))
	if !strings.Contains(r2str(t, m, "skipped"), "not a desktop app bundle") {
		t.Fatalf("desktop refusal = %v", m)
	}
}

func TestR2L10FirmwareRefusesVerifiedAndCarvesUnknown(t *testing.T) {
	carve := opStatic(t, "inspect_firmware_regions", opStaticFile(t, "fw", sfFirmware()))
	if r2num(t, carve, "regions") < 1 || r2optStr(carve, "kind") == "" {
		t.Fatalf("carve = %v", carve)
	}
	verified := opStatic(t, "inspect_firmware_regions", opStaticFile(t, "plain", []byte("plain text")))
	if !strings.Contains(r2optStr(verified, "skipped"), "not a firmware image") {
		t.Fatalf("verified-kind must refuse: %v", verified)
	}
}

func TestR2L10EvmSelectorsAndBytecode(t *testing.T) {
	code := []byte{0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14, 0x57}
	if got := evmSelectors(code); len(got) != 1 || got[0] != "0xaabbccdd" {
		t.Fatalf("evmSelectors = %v", got)
	}
	b, err := evmBytecode([]byte("0x63aabbccdd14"))
	if err != nil || !bytes.Equal(b, []byte{0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14}) {
		t.Fatalf("evmBytecode = %x, %v", b, err)
	}
	m := opStatic(t, "inspect_evm_interface", opStaticFile(t, "macho-evm", objcMachO([]objcSect{{name: "__text", data: code}})))
	if r2str(t, m, "skipped") == "" {
		t.Fatalf("verified format must refuse: %v", m)
	}
}

// --- g5: electron page (transport seam) ------------------------------------

func TestR2L10ElectronPage(t *testing.T) {
	fakeDriver(t, webOut{Steps: []webStepResult{
		okStep("Runtime.enable", nil),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "string", "value": "1"}}),
		okStep("Runtime.evaluate", map[string]any{"result": map[string]any{"type": "string", "value": "Mozilla/5.0 Electron/28.1.0 Chrome/120.0"}}),
	}})
	m, err := opInspectElectronPage("127.0.0.1:9333")
	if err != nil {
		t.Fatal(err)
	}
	out := r2decode(t, m)
	if out["electron_version"] != "28.1.0" {
		t.Fatalf("electron page = %v", out)
	}
}

// --- g6: managed metadata ---------------------------------------------------

func TestR2L10ManagedArtifact(t *testing.T) {
	m := opStatic(t, "inspect_managed_artifact", opStaticFile(t, "plain", []byte("plain text")))
	if r2str(t, m, "skipped") == "" {
		t.Fatalf("non-managed must refuse: %v", m)
	}
}

func TestR2L10ManagedMembersRefusesNonAssembly(t *testing.T) {
	r2mustErr(t, "inspect_managed_members", opStaticFile(t, "plain", []byte("plain text")))
}

func TestR2L10Il2cppMetadata(t *testing.T) {
	m := opStatic(t, "inspect_il2cpp_metadata", constELF(t, []byte("global-metadata.dat\x00Unity 2021.3.15f1\x00")))
	if r2optStr(m, "error") != "" {
		t.Fatalf("il2cpp error = %v", m)
	}
	caps := r2arr(t, m, "capabilities")
	found := false
	for _, c := range caps {
		if s, _ := c.(string); s == "il2cpp" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected il2cpp capability: %v", m)
	}
}

// --- g7: electron fuses / go binary -----------------------------------------

func TestR2L10ElectronFuses(t *testing.T) {
	off, wire, err := fuseWire(opStaticFile(t, "fuses", sfElectronFuses()))
	if err != nil || off < 0 || len(wire) < 5 || wire[0] != 1 || wire[1] != 3 {
		t.Fatalf("fuseWire = off %d wire %x err %v", off, wire, err)
	}
	if wire[2] != '1' || wire[3] != '0' || wire[4] != 'r' {
		t.Fatalf("fuse states = %x", wire[2:5])
	}
}

func TestR2L10HasMarker(t *testing.T) {
	p := writeTemp(t, "buildid.bin", append(bytes.Repeat([]byte{0xcc}, 4096), goBuildIDMarker...))
	if !hasMarker(p, goBuildIDMarker, maxGoInfoScan) {
		t.Fatal("hasMarker missed an embedded build-id marker")
	}
	if hasMarker(opStaticFile(t, "absent", []byte("plain")), goBuildIDMarker, maxGoInfoScan) {
		t.Fatal("hasMarker invented a marker")
	}
}

// A real ELF target is covered even though its digest kind (elf) and the
// advertised format name (elf) agree: the coverage lookup must not miss it.
func TestR2L10FormatCoverageKnownELF(t *testing.T) {
	p := constELF(t, nil)
	m := opStatic(t, "inspect_format_coverage", p)
	if got := r2str(t, m, "target_kind"); got != "elf" {
		t.Fatalf("target_kind = %q, want elf", got)
	}
	if covered, ok := m["covered"].(bool); !ok || !covered {
		t.Fatalf("covered = %v (%T), want true for an ELF", m["covered"], m["covered"])
	}
}
