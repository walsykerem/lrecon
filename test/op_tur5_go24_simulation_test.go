package main

// Tur5 lane 24: behaviour simulations for the assigned sim surface. Each test
// drives the real implementation through a hand-built artifact and checks the
// bytes or the refusal, not a happy-path stub.

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tur5Go24PE wraps one section of method-body bytes in a minimal PE32+ image.
// The section maps RVA 0x2000 to file offset 0x200, so a body placed at `body`
// can be read back through peImage.at without a toolchain.
func tur5Go24PE(t *testing.T, body []byte, span ...uint32) (peImage, uint32) {
	t.Helper()
	const rva = uint32(0x2000)
	secSpan := uint32(len(body) + 0x100)
	if len(span) > 0 {
		secSpan = span[0]
	}
	img := make([]byte, 0x200+len(body)+0x100)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x40)
	copy(img[0x40:], "PE\x00\x00")
	coff := img[0x44:]
	binary.LittleEndian.PutUint16(coff[0:], 0x8664)
	binary.LittleEndian.PutUint16(coff[2:], 1)
	binary.LittleEndian.PutUint16(coff[16:], 240)
	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)
	binary.LittleEndian.PutUint32(opt[32:], 0x1000)
	binary.LittleEndian.PutUint32(opt[36:], 0x200)
	binary.LittleEndian.PutUint32(opt[108:], 16)
	sec := coff[20+240:]
	copy(sec, ".text\x00\x00\x00")
	binary.LittleEndian.PutUint32(sec[8:], secSpan)
	binary.LittleEndian.PutUint32(sec[12:], rva)
	binary.LittleEndian.PutUint32(sec[16:], secSpan)
	binary.LittleEndian.PutUint32(sec[20:], 0x200)
	copy(img[0x200:], body)
	imgd, ok := openPEImage(bytes.NewReader(img))
	if !ok {
		t.Fatal("openPEImage refused the hand-built PE")
	}
	return imgd, rva
}

func TestTur5Go24CilBodyHeaderForms(t *testing.T) {
	// Tiny: (6<<2)|2, six IL bytes. Fat: 3 words, maxStack 8, 4 IL bytes,
	// locals token 0x11000001, placed 0x40 bytes past the tiny body.
	body := make([]byte, 0x100)
	body[0] = 0x1a
	copy(body[1:7], []byte{0x00, 0x17, 0x1a, 0x2a, 0x00, 0x2a})
	fat := body[0x40:]
	binary.LittleEndian.PutUint16(fat[0:], 0x3003) // flags=3 (fat), 3 words
	binary.LittleEndian.PutUint16(fat[2:], 8)
	binary.LittleEndian.PutUint32(fat[4:], 4)
	binary.LittleEndian.PutUint32(fat[8:], 0x11000001)
	copy(fat[cliFatHeaderSize:], []byte{0x02, 0x17, 0x2a, 0x2a})
	img, rva := tur5Go24PE(t, body)

	code, header, stack, locals, err := cilBody(img, rva)
	if err != nil || header != "tiny" || stack != 8 || locals != 0 {
		t.Fatalf("tiny header = %q/%d/%d, err %v", header, stack, locals, err)
	}
	if !bytes.Equal(code, []byte{0x00, 0x17, 0x1a, 0x2a, 0x00, 0x2a}) {
		t.Fatalf("tiny code %x", code)
	}
	fcode, fheader, fstack, flocals, err := cilBody(img, rva+0x40)
	if err != nil || fheader != "fat" || fstack != 8 || flocals != 0x11000001 {
		t.Fatalf("fat header = %q/%d/0x%x, err %v", fheader, fstack, flocals, err)
	}
	if !bytes.Equal(fcode, []byte{0x02, 0x17, 0x2a, 0x2a}) {
		t.Fatalf("fat code %x", fcode)
	}

	// Reserved flag bits (0 and 1) must be named, never decoded as code.
	bad := make([]byte, 0x40)
	img2, rva2 := tur5Go24PE(t, bad)
	if _, _, _, _, err := cilBody(img2, rva2); err == nil || !strings.Contains(err.Error(), "reserved flags 0x0") {
		t.Fatalf("reserved flags: %v", err)
	}
	// A tiny body that claims more IL bytes than the section holds is truncated.
	over := []byte{0xfe}                   // tiny header, 63 IL bytes
	img2b, rva2b := tur5Go24PE(t, over, 8) // 8-byte section cannot hold 63
	if _, _, _, _, err := cilBody(img2b, rva2b); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("tiny overrun: %v", err)
	}
	// A fat header claiming more than maxCILMethodBody is refused before a read.
	binBody := make([]byte, 0x100)
	binary.LittleEndian.PutUint16(binBody[0:], 0x3003)
	binary.LittleEndian.PutUint32(binBody[4:], maxCILMethodBody+1)
	img3, rva3 := tur5Go24PE(t, binBody)
	if _, _, _, _, err := cilBody(img3, rva3); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("fat cap: %v", err)
	}
}

func TestTur5Go24ExportWebScriptsArtifactsAndGuards(t *testing.T) {
	dir := t.TempDir()
	archive := writeAsarArchive(t, dir, "app.asar", map[string][]byte{
		"main.js":              []byte("module.exports = 1;\n"),
		"node_modules/x/y.mjs": []byte("export default 2;\n"),
		"readme.md":            []byte("not a script"),
	})
	old := opOutput
	opOutput = filepath.Join(dir, "out")
	t.Cleanup(func() { opOutput = old })
	res, err := runOp("export_web_scripts", archive)
	if err != nil {
		t.Fatalf("export asar: %v", err)
	}
	f := fields(t, res)
	if f["written"] != float64(2) || f["bytes"] != float64(len("module.exports = 1;\n")+len("export default 2;\n")) {
		t.Fatalf("export counts = %v", f)
	}
	for rel, want := range map[string]string{
		"main.js":              "module.exports = 1;\n",
		"node_modules/x/y.mjs": "export default 2;\n",
	} {
		b, err := os.ReadFile(filepath.Join(opOutput, rel))
		if err != nil || string(b) != want {
			t.Fatalf("%s = %q / %v", rel, b, err)
		}
	}
	if _, err := os.Stat(filepath.Join(opOutput, "readme.md")); err == nil {
		t.Fatal("non-script member was exported")
	}

	// writeExported itself rejects traversal (including a backslash that
	// path.Clean would pass through on Windows) but allows a ..foo.js name.
	if err := writeExported(opOutput, "../evil.js", []byte("x")); err == nil {
		t.Fatal("../evil.js escaped")
	}
	if err := writeExported(opOutput, `..\evil.js`, []byte("x")); err == nil {
		t.Fatal("backslash escape accepted")
	}
	if err := writeExported(opOutput, "..tracked.js", []byte("ok")); err != nil {
		t.Fatalf("leading-dot name refused: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(opOutput, "..tracked.js")); err != nil || string(b) != "ok" {
		t.Fatalf("..tracked.js = %q / %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "evil.js")); err == nil {
		t.Fatal("a guarded path still escaped the export directory")
	}
}

func TestTur5Go24GRouteRequiresFromOpsJSON(t *testing.T) {
	tbl, err := loadOpTable(opTablePath)
	if err != nil {
		t.Fatal(err)
	}
	requires := map[string]string{
		"compare_functions":            "LRECON_FROM",
		"inspect_native_data_type":     "LRECON_NAME",
		"resolve_containing_procedure": "LRECON_AT",
	}
	for _, row := range tbl.Ops {
		if want, ok := requires[row.Name]; ok && row.Expect.Requires != want {
			t.Fatalf("%s requires %q, ops.json says %q", row.Name, want, row.Expect.Requires)
		}
	}

	target := writeTemp(t, "host.macho", machoHost(0x01000007))
	t.Setenv("LRECON_FROM", "")
	t.Setenv("LRECON_TO", "")
	if _, err := runOp("compare_functions", target); err == nil || !strings.Contains(err.Error(), "LRECON_FROM") {
		t.Fatalf("compare_functions without pair = %v", err)
	}
	t.Setenv("LRECON_NAME", "")
	if _, err := runOp("inspect_native_data_type", target); err == nil || !strings.Contains(err.Error(), "LRECON_NAME") {
		t.Fatalf("inspect_native_data_type without name = %v", err)
	}
	t.Setenv("LRECON_AT", "")
	if _, err := runOp("resolve_containing_procedure", target); err == nil || !strings.Contains(err.Error(), "LRECON_AT") {
		t.Fatalf("resolve_containing_procedure without address = %v", err)
	}

	// set_inline_comment's job-field check is only reached on a native target;
	// a text job is refused earlier by the kind gate (both are honest).
	job := writeTemp(t, "job.json", []byte(`{}`))
	res, err := runOp("set_inline_comment", job)
	if err == nil {
		m, ok := res.(*skip)
		if !ok || !strings.Contains(m.Reason, "decompiler") {
			t.Fatalf("set_inline_comment incomplete job = %v / %#v", res, res)
		}
	} else if !strings.Contains(err.Error(), `job needs "address" and "text"`) {
		t.Fatalf("set_inline_comment incomplete job = %v", err)
	}
	// A native job file with no address/text must name the missing fields.
	nativeJob := writeTemp(t, "nj.json", []byte(`{"file":"`+target+`"}`))
	if _, err := runOp("set_inline_comment", nativeJob); err == nil || !strings.Contains(err.Error(), `job needs "address" and "text"`) {
		t.Fatalf("set_inline_comment native incomplete job = %v", err)
	}
}
