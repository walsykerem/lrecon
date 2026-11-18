package main

import (
	"debug/pe"
	"encoding/binary"
	"os"
	"strings"
	"testing"
)

// buildCLIPE hand-writes a minimal PE32+ image carrying a CLI header plus a
// metadata root (BSJB), which real toolchains emit. withCLI=false zeroes the
// COM descriptor so the file stays a plain native PE.
func buildCLIPE(t *testing.T, withCLI bool) string {
	t.Helper()
	if !withCLI {
		return buildPEWithMeta(t, "managed.exe", cliMetadataBlob(), false)
	}
	return buildPEWithMeta(t, "managed.exe", cliMetadataBlob(), true)
}

// buildPEWithMeta hand-writes a minimal PE32+ image around one metadata root,
// which real toolchains emit. withCLI=false zeroes the COM descriptor so the
// file stays a plain native PE.
func buildPEWithMeta(t *testing.T, name string, meta []byte, withCLI bool) string {
	t.Helper()
	size := max(0x400+len(meta), 0x600)
	img := make([]byte, (size+0x1ff)&^0x1ff)
	copy(img, "MZ")
	binary.LittleEndian.PutUint32(img[0x3c:], 0x40)

	peOff := 0x40
	copy(img[peOff:], "PE\x00\x00")
	coff := img[peOff+4:]
	binary.LittleEndian.PutUint16(coff[0:], pe.IMAGE_FILE_MACHINE_AMD64)
	binary.LittleEndian.PutUint16(coff[2:], 1)       // one section
	binary.LittleEndian.PutUint16(coff[16:], 240)    // SizeOfOptionalHeader (PE32+)
	binary.LittleEndian.PutUint16(coff[18:], 0x0022) // executable | large address aware

	opt := coff[20:]
	binary.LittleEndian.PutUint16(opt[0:], 0x20b)   // PE32+
	binary.LittleEndian.PutUint32(opt[32:], 0x1000) // SectionAlignment
	binary.LittleEndian.PutUint32(opt[36:], 0x200)  // FileAlignment
	rawSize := (0x200 + len(meta) + 0x1ff) &^ 0x1ff
	binary.LittleEndian.PutUint32(opt[56:], uint32(0x1000+((0x200+len(meta)+0xfff)&^0xfff))) // SizeOfImage
	binary.LittleEndian.PutUint32(opt[60:], 0x200)                                           // SizeOfHeaders
	binary.LittleEndian.PutUint16(opt[68:], 3)                                               // console subsystem
	binary.LittleEndian.PutUint32(opt[108:], 16)                                             // NumberOfRvaAndSizes
	if withCLI {
		dd := 112 + pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR*8
		binary.LittleEndian.PutUint32(opt[dd:], 0x1000) // CLI header RVA
		binary.LittleEndian.PutUint32(opt[dd+4:], 0x48) // 72 bytes
	}

	sec := img[0x148:]
	copy(sec, ".text")
	binary.LittleEndian.PutUint32(sec[8:], uint32(0x200+len(meta))) // VirtualSize
	binary.LittleEndian.PutUint32(sec[12:], 0x1000)                 // VirtualAddress
	binary.LittleEndian.PutUint32(sec[16:], uint32(rawSize))        // SizeOfRawData
	binary.LittleEndian.PutUint32(sec[20:], 0x200)                  // PointerToRawData
	binary.LittleEndian.PutUint32(sec[36:], 0x60000020)             // code | execute | read

	cli := img[0x200:]
	binary.LittleEndian.PutUint32(cli[0:], 0x48)   // cb
	binary.LittleEndian.PutUint16(cli[4:], 2)      // runtime major
	binary.LittleEndian.PutUint16(cli[6:], 5)      // runtime minor
	binary.LittleEndian.PutUint32(cli[8:], 0x1200) // metadata RVA
	binary.LittleEndian.PutUint32(cli[12:], uint32(len(meta)))
	binary.LittleEndian.PutUint32(cli[16:], 1) // COMIMAGE_FLAGS_ILONLY
	binary.LittleEndian.PutUint32(cli[20:], 0x06000001)
	copy(img[0x400:], meta)

	path := writeTemp(t, name, img)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return path
}

// cliMetadataBlob is a BSJB root with #~ and #Strings streams, laid out the way
// ECMA-335 does it: 4-byte padded version string, padded stream names.
func cliMetadataBlob() []byte {
	version := "v4.0.30319\x00\x00"
	heap := []byte("\x00kernel32.dll\x00user32.dll\x00Hello\x00.NETCoreApp,Version=v8.0\x00")
	tables := make([]byte, 24) // 0x18-byte #~ header, no rows
	tables[4], tables[7] = 2, 1

	const hdr = 32 // root header through the stream count
	const shdrs = 12 + 20
	meta := make([]byte, hdr+shdrs+len(tables)+len(heap))
	binary.LittleEndian.PutUint32(meta[0:], bsjbSignature)
	binary.LittleEndian.PutUint16(meta[4:], 1)
	binary.LittleEndian.PutUint16(meta[6:], 1)
	binary.LittleEndian.PutUint32(meta[12:], uint32(len(version)))
	copy(meta[16:], version)
	binary.LittleEndian.PutUint16(meta[30:], 2) // stream count

	binary.LittleEndian.PutUint32(meta[32:], uint32(hdr+shdrs)) // #~ offset
	binary.LittleEndian.PutUint32(meta[36:], uint32(len(tables)))
	copy(meta[40:], "#~\x00\x00")

	binary.LittleEndian.PutUint32(meta[44:], uint32(hdr+shdrs+len(tables))) // #Strings offset
	binary.LittleEndian.PutUint32(meta[48:], uint32(len(heap)))
	copy(meta[52:], "#Strings\x00")

	copy(meta[hdr+shdrs:], tables)
	copy(meta[hdr+shdrs+len(tables):], heap)
	return meta
}

func TestProbeDotNetPE(t *testing.T) {
	d, err := Probe(buildCLIPE(t, true))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe-dotnet" {
		t.Fatalf("kind = %q, want pe-dotnet", d.Kind)
	}
	if !containsStr(d.Capabilities, "managed") {
		t.Fatalf("capabilities = %v, want managed", d.Capabilities)
	}
	if !containsStr(d.Capabilities, "pinvoke") {
		t.Fatalf("capabilities = %v, want pinvoke (2 native modules in #Strings)", d.Capabilities)
	}
	if !strings.Contains(d.Toolchain, "dotnet CLR v4.0.30319") {
		t.Fatalf("toolchain = %q, want dotnet CLR version", d.Toolchain)
	}
	if !strings.Contains(d.Toolchain, ".NETCoreApp,Version=v8.0") {
		t.Fatalf("toolchain = %q, want target framework", d.Toolchain)
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "#Strings") {
		t.Fatalf("notes missing stream list:\n%s", notes)
	}
	if !strings.Contains(notes, "pinvoke: 1") {
		t.Fatalf("notes missing pinvoke count:\n%s", notes)
	}
}

func TestProbeNativePEHasNoManaged(t *testing.T) {
	d, err := Probe(buildCLIPE(t, false))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if d.Kind != "pe" {
		t.Fatalf("kind = %q, want pe", d.Kind)
	}
	if containsStr(d.Capabilities, "managed") {
		t.Fatalf("capabilities = %v, want no managed", d.Capabilities)
	}
}

func TestParseMetadata(t *testing.T) {
	md, ok := parseMetadata(cliMetadataBlob())
	if !ok {
		t.Fatal("parseMetadata rejected a well-formed root")
	}
	if md.version != "v4.0.30319" {
		t.Fatalf("version = %q", md.version)
	}
	if strings.Join(md.streams, ",") != "#~,#Strings" {
		t.Fatalf("streams = %v", md.streams)
	}
	if !strings.Contains(string(md.strings), "kernel32.dll") {
		t.Fatalf("#Strings heap = %q", md.strings)
	}
	if _, ok := parseMetadata([]byte("not metadata at all")); ok {
		t.Fatal("parseMetadata accepted garbage")
	}
}

func TestTargetFramework(t *testing.T) {
	if got := targetFramework(cliMetadataBlob()); got != ".NETCoreApp,Version=v8.0" {
		t.Fatalf("targetFramework = %q", got)
	}
	if got := targetFramework([]byte("\x00\x00")); got != "" {
		t.Fatalf("targetFramework(garbage) = %q, want empty", got)
	}
}

func TestNativeModules(t *testing.T) {
	heap := []byte("\x00kernel32.dll\x00user32.dll\x00Hello\x00System.Runtime\x00")
	if n := nativeModules(heap); n != 1 {
		t.Fatalf("nativeModules = %d, want 1 (2 .dll names minus the module itself)", n)
	}
	if n := nativeModules([]byte("\x00Hello\x00")); n != 0 {
		t.Fatalf("nativeModules(pure managed) = %d, want 0", n)
	}
}

func TestIL2CPPMarkers(t *testing.T) {
	img := []byte("\x7fELF\x00UnityPlayer\x002021.3.15f1\x00il2cpp_init\x00Data/Managed/Metadata/global-metadata.dat\x00")
	ver, found := il2cppMarkers(img)
	if !found {
		t.Fatal("global-metadata.dat reference not found")
	}
	if ver != "2021.3.15f1" {
		t.Fatalf("unity version = %q, want 2021.3.15f1", ver)
	}
	// A bare file name is not a marker: lrecon's own text mentions it. The
	// metadata magic (or an il2cpp_init symbol / Unity version) has to agree.
	if _, found := il2cppMarkers([]byte("global-metadata.dat\x00")); found {
		t.Fatal("il2cppMarkers matched a bare file name reference")
	}
	withMagic := append([]byte("global-metadata.dat\x00"), 0xaf, 0x1b, 0xb1, 0xfa)
	if _, found := il2cppMarkers(withMagic); !found {
		t.Fatal("il2cppMarkers missed global-metadata.dat next to the metadata magic")
	}
	if _, found := il2cppMarkers([]byte("\x7fELF no markers here")); found {
		t.Fatal("il2cppMarkers matched a plain ELF")
	}
	if got := unityVersion([]byte("no unity marker 2021.3.15f1")); got != "" {
		t.Fatalf("unityVersion without marker = %q, want empty", got)
	}
}

func TestManagedDotNetDeepNote(t *testing.T) {
	d := probeFixture(t, buildCLIPE(t, true))
	if d.Kind != "pe-dotnet" {
		t.Fatalf("kind = %q, want pe-dotnet", d.Kind)
	}
	notes := strings.Join(d.Notes, "\n")
	if !strings.Contains(notes, "deep: ") || !strings.Contains(notes, "metadata") {
		t.Fatalf("notes = %v, want a deep: note about the metadata root", d.Notes)
	}
	for _, tool := range []string{"ilspy", "ghidra", "frida", "monodis"} {
		if strings.Contains(strings.ToLower(notes), tool) {
			t.Fatalf("notes mention the tool %q: %v", tool, d.Notes)
		}
	}
}

func TestManagedIL2CPPMetadataDeepNote(t *testing.T) {
	p := writeTemp(t, "global-metadata.dat", []byte("\xaf\x1b\xb1\xfa metadata"))
	d := Digest{}
	inspectManaged(p, &d)
	if d.Kind != "il2cpp-metadata" {
		t.Fatalf("kind = %q, want il2cpp-metadata", d.Kind)
	}
	if notes := strings.Join(d.Notes, "\n"); !strings.Contains(notes, "deep: ") || !strings.Contains(notes, "metadata") {
		t.Fatalf("notes = %v, want a deep: note about the metadata file", d.Notes)
	}
}
