package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// opStatic runs an op against a fixture and decodes its JSON into a map so the
// assertions can name the documented fields instead of the Go struct.
func opStatic(t *testing.T, name, path string) map[string]any {
	t.Helper()
	v, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: result is not JSON: %v", name, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%s: %s: %v", name, raw, err)
	}
	return m
}

func opStaticFile(t *testing.T, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name+".fixture")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func opStaticNum(t *testing.T, m map[string]any, key string) int {
	t.Helper()
	f, ok := m[key].(float64)
	if !ok {
		t.Fatalf("%s = %v (%T), want a number", key, m[key], m[key])
	}
	return int(f)
}

func opStaticStr(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("%s = %v (%T), want a string", key, m[key], m[key])
	}
	return s
}

// sfFDT builds a version-17 flattened device tree: root with compatible+model,
// one "soc" child with a reg property.
func sfFDT() []byte {
	strs := "compatible\x00model\x00reg\x00"
	nameOff := map[string]int{"compatible": 0, "model": 11, "reg": 17}
	var st []byte
	put := func(v uint32) {
		st = append(st, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	}
	pad := func() {
		for len(st)%4 != 0 {
			st = append(st, 0)
		}
	}
	node := func(name string) {
		put(1)
		st = append(st, name...)
		st = append(st, 0)
		pad()
	}
	prop := func(name string, val []byte) {
		put(3)
		put(uint32(len(val)))
		put(uint32(nameOff[name]))
		st = append(st, val...)
		pad()
	}
	node("")
	prop("compatible", []byte("acme,sim\x00"))
	prop("model", []byte("Sim One\x00"))
	node("soc")
	prop("reg", []byte{1, 2, 3, 4})
	put(2)
	put(2)
	put(9)

	hdr := make([]byte, 40)
	be := binary.BigEndian
	be.PutUint32(hdr[0:], 0xd00dfeed)
	be.PutUint32(hdr[4:], uint32(40+len(st)+len(strs)))
	be.PutUint32(hdr[8:], 40)
	be.PutUint32(hdr[12:], uint32(40+len(st)))
	be.PutUint32(hdr[16:], 40)
	be.PutUint32(hdr[20:], 17)
	be.PutUint32(hdr[24:], 16)
	be.PutUint32(hdr[32:], uint32(len(strs)))
	be.PutUint32(hdr[36:], uint32(len(st)))
	return append(append(hdr, st...), []byte(strs)...)
}

// sfBEAM builds a FOR1/BEAM IFF container with an Atom table (foo, bar) and a
// CInf compiler chunk.
func sfBEAM() []byte {
	atom := []byte{0, 0, 0, 2, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'}
	cinf := []byte("8.5.0\x00\x00\x00")
	var body []byte
	add := func(id string, payload []byte) {
		body = append(body, id...)
		n := uint32(len(payload))
		body = append(body, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
		body = append(body, payload...)
	}
	add("Atom", atom)
	add("CInf", cinf)
	out := []byte("FOR1")
	n := uint32(4 + len(body))
	out = append(out, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	out = append(out, "BEAM"...)
	return append(out, body...)
}

func sfEntropyFixture() []byte {
	b := make([]byte, 8192)
	for i := 4096; i < len(b); i++ {
		b[i] = byte(i % 256)
	}
	return b
}

func sfDartAOT() []byte {
	const hash = "0123456789abcdef0123456789abcdef"
	b := make([]byte, 20+len(hash))
	binary.LittleEndian.PutUint32(b, 0xdcdcf5f5)
	binary.LittleEndian.PutUint64(b[4:], uint64(len(b)-4))
	binary.LittleEndian.PutUint64(b[12:], 2)
	copy(b[20:], hash)
	return b
}

func sfElectronFuses() []byte {
	b := make([]byte, 100)
	for i := range b {
		b[i] = 0xAA
	}
	b = append(b, fuseSentinel...)
	return append(b, 1, 3, '1', '0', 'r')
}

func sfFirmware() []byte {
	b := make([]byte, 64)
	b = append(b, "hsqs"...)
	b = append(b, 1, 2, 3, 4)
	b = append(b, 0xd0, 0x0d, 0xfe, 0xed)
	return append(b, 9, 9, 9, 9)
}

// sfNIB builds a minimal but real NIBArchive: a 50-byte header followed by the
// four tables (objects, keys, values, class names). Counts are VInt32 with the
// high bit on the LAST byte, not on continuation bytes, and the outlet/action
// name lives in an NSString object the connector's NSLabel points at.
func sfNIB() []byte {
	vint := func(v int) []byte {
		var out []byte
		for {
			out = append(out, byte(v&0x7f))
			v >>= 7
			if v == 0 {
				break
			}
		}
		out[len(out)-1] |= 0x80
		return out
	}
	le := binary.LittleEndian

	keys := []string{"NSLabel", "NS.bytes", "title"}
	const objects = 2
	const values = 2
	const classes = 1
	action := "onTapAction"
	className := "NSNibControlConnector"

	objectTable := []byte{}
	for i := range objects {
		objectTable = append(objectTable, vint(0)...) // class 0
		objectTable = append(objectTable, vint(i)...) // valueStart
		objectTable = append(objectTable, vint(1)...) // valueCount
	}
	keyTable := []byte{}
	for _, k := range keys {
		keyTable = append(keyTable, vint(len(k))...)
		keyTable = append(keyTable, k...)
	}
	valueTable := []byte{}
	// 0: NSLabel -> reference to object 1
	valueTable = append(valueTable, vint(0)...)
	valueTable = append(valueTable, nibValueReference, 1, 0, 0, 0)
	// 1: NS.bytes -> the string itself
	valueTable = append(valueTable, vint(1)...)
	valueTable = append(valueTable, nibValueBytes)
	valueTable = append(valueTable, vint(len(action))...)
	valueTable = append(valueTable, action...)
	classTable := []byte{}
	classTable = append(classTable, vint(len(className))...)
	classTable = append(classTable, vint(0)...) // no fallback classes
	classTable = append(classTable, className...)

	b := make([]byte, nibHeaderSize)
	copy(b, "NIBArchive")
	le.PutUint32(b[10:], 1) // version
	le.PutUint32(b[14:], 10)
	le.PutUint32(b[18:], objects)
	le.PutUint32(b[22:], uint32(len(b)))
	b = append(b, objectTable...)
	le.PutUint32(b[26:], uint32(len(keys)))
	le.PutUint32(b[30:], uint32(len(b)))
	b = append(b, keyTable...)
	le.PutUint32(b[34:], values)
	le.PutUint32(b[38:], uint32(len(b)))
	b = append(b, valueTable...)
	le.PutUint32(b[42:], classes)
	le.PutUint32(b[46:], uint32(len(b)))
	b = append(b, classTable...)
	return b
}

// sfELFNote is a 64-bit ELF carrying one PT_NOTE with a 20-byte GNU build id.
func sfELFNote() []byte {
	const ehdr, phdr = 64, 56
	id := []byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	note := make([]byte, 0, 12+4+len(id))
	le := binary.LittleEndian
	note = append(note, 4, 0, 0, 0) // namesz "GNU\0"
	note = append(note, byte(len(id)), 0, 0, 0)
	note = append(note, 3, 0, 0, 0) // NT_GNU_BUILD_ID
	note = append(note, 'G', 'N', 'U', 0)
	note = append(note, id...)

	b := make([]byte, ehdr+phdr, ehdr+phdr+len(note))
	copy(b, "\x7fELF")
	b[4], b[5], b[6] = 2, 1, 1 // ELFCLASS64, ELFDATA2LSB, EV_CURRENT
	le.PutUint16(b[16:], 2)    // ET_EXEC
	le.PutUint16(b[18:], 62)   // EM_X86_64
	le.PutUint32(b[20:], 1)    // EV_CURRENT
	le.PutUint64(b[32:], ehdr)
	le.PutUint16(b[52:], ehdr)
	le.PutUint16(b[54:], phdr)
	le.PutUint16(b[56:], 1)
	le.PutUint16(b[58:], 64)
	le.PutUint64(b[ehdr:], 4) // PT_NOTE, p_offset = note body
	le.PutUint32(b[ehdr+4:], 4)
	le.PutUint64(b[ehdr+8:], ehdr+phdr)
	le.PutUint64(b[ehdr+32:], uint64(len(note)))
	le.PutUint64(b[ehdr+40:], uint64(len(note)))
	le.PutUint64(b[ehdr+48:], 4)
	return append(b, note...)
}

// sfFatbin wraps one PTX TLV in a bare NV fatbin container.
func sfFatbin() []byte {
	const hdr, tlv = 32, 16
	b := make([]byte, hdr+tlv+8)
	le := binary.LittleEndian
	copy(b[0:], []byte{0x50, 0xED, 0x55, 0xBA})
	le.PutUint16(b[4:], 1)
	le.PutUint16(b[6:], hdr)
	le.PutUint64(b[8:], uint64(len(b)))
	le.PutUint32(b[hdr:], 1)
	le.PutUint16(b[hdr+4:], 1)
	le.PutUint16(b[hdr+6:], tlv)
	le.PutUint64(b[hdr+8:], 8)
	copy(b[hdr+tlv:], ".version")
	return b
}

func TestOpStaticTier(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
		fixture func(t *testing.T) string
		want    func(t *testing.T, m map[string]any)
	}{
		{
			name:    "inspect_byte_entropy",
			fixture: func(t *testing.T) string { return opStaticFile(t, "entropy", sfEntropyFixture()) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "blocks") != 2 || opStaticNum(t, m, "plain_blocks") != 1 ||
					opStaticNum(t, m, "packed_blocks") != 1 || opStaticNum(t, m, "block_bytes") != 4096 {
					t.Fatalf("entropy block partition = %v", m)
				}
			},
		},
		{
			name:    "inspect_dart_aot",
			fixture: func(t *testing.T) string { return opStaticFile(t, "snapshot", sfDartAOT()) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "kind") != "full-aot" || !m["length_consistent"].(bool) ||
					opStaticNum(t, m, "declared_bytes") != 52 || opStaticNum(t, m, "actual_bytes") != 52 {
					t.Fatalf("dart header = %v", m)
				}
			},
		},
		{
			name:    "inspect_electron_fuses",
			fixture: func(t *testing.T) string { return opStaticFile(t, "electron", sfElectronFuses()) },
			want: func(t *testing.T, m map[string]any) {
				fuses := m["fuses"].([]any)
				first := fuses[0].(map[string]any)
				last := fuses[2].(map[string]any)
				if opStaticNum(t, m, "wire_offset") != 100 || opStaticNum(t, m, "wire_version") != 1 ||
					opStaticNum(t, m, "fuse_count") != 3 {
					t.Fatalf("fuse wire header = %v", m)
				}
				if first["name"] != "RunAsNode" || first["state"] != "enabled" ||
					last["name"] != "EnableNodeOptionsEnvironmentVariable" || last["state"] != "removed" {
					t.Fatalf("fuse states = %v", fuses)
				}
			},
		},
		{
			name: "inspect_evm_interface",
			fixture: func(t *testing.T) string {
				return opStaticFile(t, "runtime.hex", []byte("0x63aabbccdd14631122334414\n"))
			},
			want: func(t *testing.T, m map[string]any) {
				vals := m["values"].([]any)
				if opStaticNum(t, m, "code_bytes") != 12 || opStaticNum(t, m, "selectors") != 2 ||
					vals[0] != "0xaabbccdd" || vals[1] != "0x11223344" {
					t.Fatalf("evm dispatcher = %v", m)
				}
			},
		},
		{
			name:    "inspect_devicetree",
			fixture: func(t *testing.T) string { return opStaticFile(t, "board.dtb", sfFDT()) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "version") != 17 || opStaticNum(t, m, "nodes") != 2 ||
					opStaticNum(t, m, "max_depth") != 2 || opStaticNum(t, m, "properties") != 3 ||
					opStaticStr(t, m, "model") != "Sim One" || opStaticStr(t, m, "compatible") != "acme,sim" {
					t.Fatalf("fdt walk = %v", m)
				}
			},
		},
		{
			name:    "inspect_erlang_beam",
			fixture: func(t *testing.T) string { return opStaticFile(t, "mod.beam", sfBEAM()) },
			want: func(t *testing.T, m map[string]any) {
				chunks := m["chunks"].([]any)
				first := chunks[0].(map[string]any)
				if opStaticNum(t, m, "total_bytes") != 48 || len(chunks) != 2 ||
					first["id"] != "Atom" || opStaticNum(t, first, "bytes") != 12 ||
					opStaticNum(t, first, "offset") != 12 ||
					opStaticNum(t, m, "atoms") != 2 || opStaticStr(t, m, "compiler") != "8.5.0" {
					t.Fatalf("beam container = %v", m)
				}
			},
		},
		{
			name: "inspect_android_class",
			fixture: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "classes.dex")
				if err := os.WriteFile(p, jebdDex(t), 0o644); err != nil {
					t.Fatal(err)
				}
				return p + "#com.example.Alpha"
			},
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "class") != "com/example/Alpha" ||
					opStaticNum(t, m, "access_flags") != 0 ||
					opStaticNum(t, m, "methods") != 2 || opStaticNum(t, m, "fields") != 0 {
					t.Fatalf("dex class = %v", m)
				}
			},
		},
		{
			name: "inspect_android_method",
			fixture: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "classes.dex")
				if err := os.WriteFile(p, jebdDex(t), 0o644); err != nil {
					t.Fatal(err)
				}
				return p + "#com.example.Alpha"
			},
			want: func(t *testing.T, m map[string]any) {
				rows := m["rows"].([]any)
				first := rows[0].(map[string]any)
				if opStaticNum(t, m, "methods") != 2 || opStaticNum(t, first, "code_off") != 0x10 ||
					first["name"] != "a" {
					t.Fatalf("dex methods = %v", m)
				}
			},
		},
		{
			name:    "inspect_apk_signature",
			fixture: func(t *testing.T) string { return jebdApk(t, jebdDex(t)) },
			// The fixture has neither a v1 signature file nor a signing block,
			// so the op answers signed:false instead of claiming a scheme.
			want: func(t *testing.T, m map[string]any) {
				if v, ok := m["signed"].(bool); !ok || v {
					t.Fatalf("signed = %v", m)
				}
				if schemes, _ := m["schemes"].([]any); len(schemes) != 0 {
					t.Fatalf("schemes = %v", schemes)
				}
			},
		},
		{
			name:    "inspect_jeb_client",
			fixture: func(t *testing.T) string { return jebdApk(t, jebdDex(t)) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "classes") != 2 {
					t.Fatalf("jeb client class count = %v", m)
				}
			},
		},
		{
			name:    "inspect_managed_members",
			fixture: func(t *testing.T) string { return metaManagedPE(t) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "types") != 2 || opStaticNum(t, m, "methods") != 3 {
					t.Fatalf("managed member counts = %v", m)
				}
			},
		},
		{
			name:    "compare_managed_members",
			fixture: func(t *testing.T) string { p := metaManagedPE(t); return p + "," + p },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "left_types") != 2 || opStaticNum(t, m, "right_types") != 2 {
					t.Fatalf("managed self-diff = %v", m)
				}
			},
		},
		{
			name: "compare_wasm_interfaces",
			fixture: func(t *testing.T) string {
				return writeTemp(t, "a.wasm", sfWasmModule()) + "," + writeTemp(t, "b.wasm", sfWasmModule())
			},
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "left_imports") != 1 || opStaticNum(t, m, "right_imports") != 1 ||
					opStaticNum(t, m, "left_exports") != 1 || opStaticNum(t, m, "right_exports") != 1 {
					t.Fatalf("wasm self-diff = %v", m)
				}
			},
		},
		{
			name:    "inspect_kernel_module",
			fixture: func(t *testing.T) string { return writeTemp(t, "plain.macho", sfMachOWithSignature(t)) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "skipped") != "" {
					return
				}
				t.Fatalf("non-kext was not skipped: %v", m)
			},
		},
		{
			name:    "get_objc_classes",
			fixture: func(t *testing.T) string { return writeTemp(t, "plain.macho", sfMachOWithSignature(t)) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "skipped") == "" {
					t.Fatalf("mach-o without __objc_classlist was not skipped: %v", m)
				}
			},
		},
		{
			name:    "get_objc_protocols",
			fixture: func(t *testing.T) string { return writeTemp(t, "plain.macho", sfMachOWithSignature(t)) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "skipped") == "" {
					t.Fatalf("mach-o without __objc_protolist was not skipped: %v", m)
				}
			},
		},
		{
			name:    "decode_interface_builder",
			fixture: func(t *testing.T) string { return opStaticFile(t, "view.nib", sfNIB()) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "version") != 1 || opStaticNum(t, m, "objects") != 2 ||
					opStaticNum(t, m, "keys") != 3 {
					t.Fatalf("nib header = %v", m)
				}
				if acts := m["actions"].([]any); len(acts) != 1 || acts[0] != "onTapAction" {
					t.Fatalf("nib actions = %v", m["actions"])
				}
			},
		},
		{
			name:    "inspect_elf_notes",
			fixture: func(t *testing.T) string { return opStaticFile(t, "note.elf", sfELFNote()) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "build_id") != "deadbeef0102030405060708090a0b0c0d0e0f10" {
					t.Fatalf("elf notes = %v", m)
				}
				notes := m["notes"].([]any)
				first := notes[0].(map[string]any)
				if len(notes) != 1 || first["owner"] != "GNU" || opStaticNum(t, first, "type") != 3 ||
					opStaticNum(t, first, "bytes") != 20 {
					t.Fatalf("elf note record = %v", notes)
				}
			},
		},
		{
			name:    "inspect_gpu_code_objects",
			fixture: func(t *testing.T) string { return opStaticFile(t, "k.fatbin", sfFatbin()) },
			want: func(t *testing.T, m map[string]any) {
				entries := m["entries"].([]any)
				first := entries[0].(map[string]any)
				if opStaticNum(t, m, "wrapper_version") != 1 || opStaticNum(t, m, "header_bytes") != 32 ||
					opStaticNum(t, m, "total_bytes") != 56 || opStaticNum(t, m, "ptx") != 1 ||
					first["kind"] != "ptx" || opStaticNum(t, first, "offset") != 32 ||
					opStaticNum(t, first, "payload_bytes") != 8 {
					t.Fatalf("fatbin walk = %v", m)
				}
			},
		},
		{
			name:    "compare_source_to_bundle",
			fixture: func(t *testing.T) string { return writeAsar(t) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticNum(t, m, "scripts") != 2 || opStaticNum(t, m, "maps") != 0 {
					t.Fatalf("asar source/bundle counts = %v", m)
				}
			},
		},
		{
			name:    "demangle_swift",
			fixture: func(t *testing.T) string { return writeTemp(t, "plain.macho", sfMachOWithSignature(t)) },
			want: func(t *testing.T, m map[string]any) {
				if opStaticStr(t, m, "skipped") == "" {
					t.Fatalf("mach-o without swift symbols was not skipped: %v", m)
				}
			},
		},
		{
			name:    "analyze_swift_types",
			fixture: func(t *testing.T) string { return writeTemp(t, "plain.macho", sfMachOWithSignature(t)) },
			want: func(t *testing.T, m map[string]any) {
				// The field is an array in the contract, so a Mach-O with no
				// swift sections answers [] rather than null.
				secs, ok := m["sections"].([]any)
				if opStaticNum(t, m, "slices") != 1 || !ok || len(secs) != 0 {
					t.Fatalf("mach-o without __swift5_types: %v", m)
				}
			},
		},
		{
			name:    "inspect_managed_native_boundaries",
			fixture: func(t *testing.T) string { return metaManagedPE(t) },
			want: func(t *testing.T, m map[string]any) {
				// The fixture declares no ImplMap rows, so the op must say so
				// instead of inventing native callees.
				if opStaticStr(t, m, "skipped") == "" {
					t.Fatalf("assembly without P/Invoke was not skipped: %v", m)
				}
			},
		},
		{
			name:    "extract_firmware",
			fixture: func(t *testing.T) string { return opStaticFile(t, "dump.bin", sfFirmware()) },
			want: func(t *testing.T, m map[string]any) {
				// Two magics in the dump: squashfs at 64, dtb at 72. Carving
				// must split them on the next hit, not on the file end.
				parts, _ := m["parts"].([]any)
				if len(parts) != 2 {
					t.Fatalf("carved %d parts, want 2: %v", len(parts), m)
				}
				for i, want := range []struct {
					name string
					off  float64
					size float64
				}{{"squashfs", 64, 8}, {"dtb", 72, 8}} {
					p, _ := parts[i].(map[string]any)
					if p["name"] != want.name || p["offset"] != want.off || p["bytes"] != want.size {
						t.Fatalf("part %d = %v, want %s@%v+%v", i, p, want.name, want.off, want.size)
					}
					b, err := os.ReadFile(filepath.Join(opStaticStr(t, m, "dir"), p["file"].(string)))
					if err != nil || float64(len(b)) != want.size {
						t.Fatalf("part %d file: %v (%d bytes)", i, err, len(b))
					}
				}
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := c.fixture(t)
			if c.mutate != nil {
				path = c.mutate(path)
			}
			if c.wantErr != "" {
				_, err := runOp(c.name, path)
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("%s error = %v, want %q", c.name, err, c.wantErr)
				}
				return
			}
			c.want(t, opStatic(t, c.name, path))
		})
	}
}
