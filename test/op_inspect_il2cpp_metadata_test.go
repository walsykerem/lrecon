package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIl2cppMetadataTables builds a minimal v29 file with one type and one
// method, so the offsets that Il2CppDumper documents are checked against bytes.
func TestIl2cppMetadataTables(t *testing.T) {
	strs := []byte("System\x00Foo\x00Bar\x00")
	const header = 168
	methodsOff := header + len(strs)
	typesOff := methodsOff + 32
	b := make([]byte, typesOff+88)
	binary.LittleEndian.PutUint32(b[0:], 0xFAB11BAF)
	binary.LittleEndian.PutUint32(b[4:], 29)
	binary.LittleEndian.PutUint32(b[24:], header)
	binary.LittleEndian.PutUint32(b[28:], uint32(len(strs)))
	binary.LittleEndian.PutUint32(b[48:], uint32(methodsOff))
	binary.LittleEndian.PutUint32(b[52:], 32)
	binary.LittleEndian.PutUint32(b[160:], uint32(typesOff))
	binary.LittleEndian.PutUint32(b[164:], 88)
	copy(b[header:], strs)

	m := b[methodsOff:]
	binary.LittleEndian.PutUint32(m[0:], 11) // "Bar"
	binary.LittleEndian.PutUint32(m[4:], 0)  // declaringType 0
	binary.LittleEndian.PutUint32(m[20:], 0x06000001)
	binary.LittleEndian.PutUint16(m[30:], 0)

	ty := b[typesOff:]
	binary.LittleEndian.PutUint32(ty[0:], 7)  // "Foo"
	binary.LittleEndian.PutUint32(ty[4:], 0)  // "System"
	binary.LittleEndian.PutUint32(ty[36:], 0) // methodStart
	binary.LittleEndian.PutUint16(ty[64:], 1) // method_count
	binary.LittleEndian.PutUint32(ty[84:], 0x02000001)

	p := filepath.Join(t.TempDir(), "global-metadata.dat")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := inspectIl2cppMetadata(p)
	if err != nil {
		t.Fatal(err)
	}
	got := v.(struct {
		Kind         string         `json:"kind"`
		Version      int            `json:"version"`
		TypesCount   int            `json:"types_count"`
		Types        []il2cppType   `json:"types,omitempty"`
		MethodsCount int            `json:"methods_count"`
		Methods      []il2cppMethod `json:"methods,omitempty"`
		Truncated    bool           `json:"truncated,omitempty"`
	})
	if got.Version != 29 || got.TypesCount != 1 || got.MethodsCount != 1 {
		t.Fatalf("counts = %+v", got)
	}
	if len(got.Types) != 1 || got.Types[0].Name != "System.Foo" || got.Types[0].Methods != 1 {
		t.Fatalf("types = %+v", got.Types)
	}
	if len(got.Methods) != 1 || got.Methods[0].Name != "Bar" || got.Methods[0].Type != "System.Foo" {
		t.Fatalf("methods = %+v", got.Methods)
	}

	// A table that declares bytes past the file must refuse, not read them.
	binary.LittleEndian.PutUint32(b[164:], 1<<20)
	os.WriteFile(p, b, 0o644)
	if _, err := inspectIl2cppMetadata(p); err == nil || !strings.Contains(err.Error(), "past the") {
		t.Fatalf("want a table-bounds error, got %v", err)
	}
}
