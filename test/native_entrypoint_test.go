package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/json"
	"runtime"
	"testing"
)

// TestEntrypointELF: the digest entry point is the ELF e_entry.
func TestEntrypointELF(t *testing.T) {
	path := buildTarget(t, "linux", "amd64", "hello.elf")
	f, err := elf.Open(path)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()
	d := probeFixture(t, path)
	if d.Entrypoint == nil {
		t.Fatalf("elf entrypoint = null, want %#x", f.Entry)
	}
	if *d.Entrypoint != f.Entry {
		t.Errorf("elf entrypoint = %#x, want %#x", *d.Entrypoint, f.Entry)
	}
}

// TestEntrypointPE: the digest entry point is ImageBase + AddressOfEntryPoint.
func TestEntrypointPE(t *testing.T) {
	path := buildTarget(t, "windows", "amd64", "hello.exe")
	f, err := pe.Open(path)
	if err != nil {
		t.Fatalf("pe.Open: %v", err)
	}
	defer f.Close()
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("optional header = %T, want *pe.OptionalHeader64", f.OptionalHeader)
	}
	d := probeFixture(t, path)
	if d.Entrypoint == nil {
		t.Fatal("pe entrypoint = null, want a number")
	}
	want := oh.ImageBase + uint64(oh.AddressOfEntryPoint)
	if *d.Entrypoint != want {
		t.Errorf("pe entrypoint = %#x, want %#x", *d.Entrypoint, want)
	}
}

// TestEntrypointMachO: a Mach-O image without LC_MAIN still names its entry.
func TestEntrypointMachO(t *testing.T) {
	path := buildTarget(t, "darwin", "arm64", "hello.macho")
	d := probeFixture(t, path)
	if d.Entrypoint == nil {
		t.Fatal("macho entrypoint = null, want a number")
	}
	if *d.Entrypoint == 0 {
		t.Error("macho entrypoint = 0, want a real address")
	}
}

// TestEntrypointNull: a target that declares no entry point carries JSON null,
// not an empty string and not zero.
func TestEntrypointNull(t *testing.T) {
	b, err := json.Marshal(Digest{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, ok := got["entrypoint"]
	if !ok {
		t.Fatal("digest JSON has no entrypoint key")
	}
	if v != nil {
		t.Errorf("empty digest entrypoint = %#v, want null", v)
	}
}

// TestMachoHostSlice: a fat file whose host arch is not slice 0 must name the
// host slice's entry, not slice 0's.
func TestMachoHostSlice(t *testing.T) {
	arches := []macho.FatArch{
		{FatArchHeader: macho.FatArchHeader{Cpu: macho.Cpu386}},
		{FatArchHeader: macho.FatArchHeader{Cpu: macho.CpuArm64}},
		{FatArchHeader: macho.FatArchHeader{Cpu: macho.CpuAmd64}},
	}
	got := machoHostSlice(arches)
	arch := machoArch(arches[got].Cpu)
	if arch != runtime.GOARCH && !(runtime.GOARCH == "amd64" && arch == "x86-64") {
		t.Errorf("host slice %d = %s, want %s", got, arch, runtime.GOARCH)
	}
	if got := machoHostSlice(arches[:1]); got != 0 {
		t.Errorf("no-match slice = %d, want 0 (slice 0 fallback)", got)
	}
}
