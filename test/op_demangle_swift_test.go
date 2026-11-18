package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sfSwiftMachO writes a thin Mach-O 64 whose string table carries real Swift
// mangled names. LC_SYMTAB + LC_DYSYMTAB is the table manglingNames reads.
func sfSwiftMachO(t *testing.T, names ...string) string {
	t.Helper()
	le := binary.LittleEndian
	strtab := []byte{0}
	offsets := make([]uint32, len(names))
	for i, name := range names {
		offsets[i] = uint32(len(strtab))
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
	}
	syms := make([]byte, 16) // null symbol
	for _, off := range offsets {
		e := make([]byte, 16)
		le.PutUint32(e[0:], off)
		e[4] = 0x0f // N_SECT | N_EXT, section 1
		e[5] = 1
		syms = append(syms, e...)
	}
	const (
		hdrSize     = 32
		symtabCmd   = 24
		dysymtabCmd = 80
	)
	symoff := hdrSize + symtabCmd + dysymtabCmd
	stroff := symoff + len(syms)
	b := make([]byte, stroff+len(strtab))
	le.PutUint32(b[0:], 0xfeedfacf)
	le.PutUint32(b[4:], 0x01000007)
	le.PutUint32(b[8:], 3)
	le.PutUint32(b[12:], 2)
	le.PutUint32(b[16:], 2)
	le.PutUint32(b[20:], symtabCmd+dysymtabCmd)
	le.PutUint32(b[32:], 0x2)
	le.PutUint32(b[36:], symtabCmd)
	le.PutUint32(b[40:], uint32(symoff))
	le.PutUint32(b[44:], uint32(len(names)+1))
	le.PutUint32(b[48:], uint32(stroff))
	le.PutUint32(b[52:], uint32(len(strtab)))
	d := b[56:]
	le.PutUint32(d[0:], 0xb)
	le.PutUint32(d[4:], dysymtabCmd)
	le.PutUint32(d[24:], 1)
	le.PutUint32(d[28:], uint32(len(names)))
	copy(b[symoff:], syms)
	copy(b[stroff:], strtab)
	return writeTemp(t, "swift.macho", b)
}

func TestDemangleSwiftRealData(t *testing.T) {
	p := sfSwiftMachO(t, "_$s4main3fooyyF", "$s4main3baryyF", "$sSo8NSObjectC", "_plain_c")
	res, err := ops["demangle_swift"].run(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Swift   int `json:"swift_symbols"`
		Targets []struct {
			Symbols int `json:"symbols"`
			Mangled int `json:"swift_symbols"`
			Names   []struct {
				Mangled   string `json:"mangled"`
				Demangled string `json:"demangled"`
			} `json:"names"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Swift < 3 {
		t.Fatalf("swift_symbols=%d, want >=3; output %s", got.Swift, b)
	}
	var decoded []string
	for _, e := range got.Targets {
		for _, n := range e.Names {
			decoded = append(decoded, n.Demangled)
		}
	}
	for _, want := range []string{"main.foo", "main.bar"} {
		found := false
		for _, d := range decoded {
			if strings.HasPrefix(d, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("demangled %q missing from %v", want, decoded)
		}
	}
	var mangled []string
	for _, e := range got.Targets {
		for _, n := range e.Names {
			mangled = append(mangled, n.Mangled)
		}
	}
	stdlib := false
	for _, n := range mangled {
		if n == "$sSo8NSObjectC" {
			stdlib = true
		}
	}
	if !stdlib {
		t.Errorf("stdlib symbol missing from %v", mangled)
	}
}

func TestCorrelateStaticRuntimeRealData(t *testing.T) {
	bin := "testdata/fixtures/macho"
	d, err := loadDigest(bin)
	if err != nil {
		t.Fatal(err)
	}
	if d.UUID == "" {
		t.Fatalf("%s carries no uuid", bin)
	}
	dir := t.TempDir()
	crash := filepath.Join(dir, "match.ips")
	ips := fmt.Sprintf("{\"bug_type\":\"309\",\"name\":\"prog\",\"os_version\":\"macOS 15.0\"}\n"+
		"{\"procName\":\"prog\",\"osVersion\":\"macOS 15.0\",\"usedImages\":[{\"name\":\"prog\",\"uuid\":%q,\"arch\":\"arm64\"},{\"name\":\"other.dylib\",\"uuid\":\"11111111-2222-3333-4444-555555555555\"}]}\n", d.UUID)
	if err := os.WriteFile(crash, []byte(ips), 0o644); err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(dir, "job.json")
	if err := os.WriteFile(job, []byte(fmt.Sprintf(`{"file":%q,"crash":%q}`, bin, crash)), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := ops["correlate_static_and_runtime"].run(job)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("result type %T", res)
	}
	if m["matches"] != 1 || m["mismatches"] != 1 {
		t.Fatalf("matches=%v mismatches=%v; output %+v", m["matches"], m["mismatches"], m)
	}
	if m["verdict"] != "static image matches the crashing image uuid" {
		t.Errorf("verdict=%v", m["verdict"])
	}
}
