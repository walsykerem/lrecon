package main

// Evergreen 19: a flat byte scan sees the same bytes no matter how they nest,
// a tree walk does not. Two pairs of equal-byte fixtures:
//
//   - .go pair: flat top-level declarations vs nested blocks, both of exactly
//     the same byte length. go/ast depth must separate them by a wide margin,
//     which is what makes the pair a fair structural fixture.
//   - FDT pair: lrecon's own inspect_devicetree walk, again equal byte length.
//     The deep blob holds FEWER nodes than the flat one, so a flat token count
//     cannot produce the depth ratio; only a nesting walk can.
//
// Depth ratios are used instead of wall-clock budgets, so the test is
// deterministic.

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ev19GoFlat returns a package whose statements all sit at one level.
func ev19GoFlat(n int) string {
	var b strings.Builder
	b.WriteString("package p\n\n")
	for i := 0; i < n; i++ {
		b.WriteString("var f")
		b.WriteString(strconv.Itoa(i))
		b.WriteString(" = ")
		b.WriteString(strconv.Itoa(i))
		b.WriteString("\n")
	}
	return b.String()
}

// ev19GoDeep returns a package whose single function nests depth if-blocks.
func ev19GoDeep(depth int) string {
	var b strings.Builder
	b.WriteString("package p\n\nfunc deep() {\n")
	for i := 0; i < depth; i++ {
		b.WriteString("if true {\n")
	}
	b.WriteString("_ = 0\n")
	for i := 0; i < depth; i++ {
		b.WriteString("}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// ev19Pad appends filler of exactly n bytes that cannot change tree shape.
func ev19Pad(s string, n int) string {
	if n <= 0 {
		return s
	}
	if n < 4 {
		return s + strings.Repeat(" ", n)
	}
	return s + "//" + strings.Repeat("x", n-3) + "\n"
}

// ev19AstDepth reports the deepest node nesting go/ast reaches in src.
func ev19AstDepth(t *testing.T, src string) int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	depth, max := 0, 0
	ast.Inspect(f, func(n ast.Node) bool {
		if n == nil {
			depth--
			return false
		}
		depth++
		if depth > max {
			max = depth
		}
		return true
	})
	return max
}

var ev19FDTStrings = []byte("model\x00v\x00compatible\x00c\x00")

const (
	ev19FDTModel = 0  // "model\0"
	ev19FDTChild = 19 // "c\0", the value name every child node uses
)

func ev19FDTU32(b *bytes.Buffer, v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	b.Write(t[:])
}

func ev19FDTPad4(b *bytes.Buffer) {
	for b.Len()%4 != 0 {
		b.WriteByte(0)
	}
}

// ev19FDTStructBlock emits begin/prop tokens: breadth sibling nodes plus one
// chain of depth nested nodes, padded with nops so callers can match a size.
func ev19FDTStructBlock(depth, breadth, nops int) []byte {
	var b bytes.Buffer
	begin := func(name string) {
		ev19FDTU32(&b, 1)
		b.WriteString(name)
		b.WriteByte(0)
		ev19FDTPad4(&b)
	}
	prop := func(nameOff int, val string) {
		ev19FDTU32(&b, 3)
		ev19FDTU32(&b, uint32(len(val)))
		ev19FDTU32(&b, uint32(nameOff))
		b.WriteString(val)
		ev19FDTPad4(&b)
	}
	end := func() { ev19FDTU32(&b, 2) }

	begin("root")
	prop(ev19FDTModel, "v\x00")
	for i := 0; i < breadth; i++ {
		begin("n" + strconv.Itoa(i))
		prop(ev19FDTChild, "c\x00")
		end()
	}
	for i := 0; i < depth; i++ {
		begin("d")
		prop(ev19FDTChild, "c\x00")
	}
	for i := 0; i < depth; i++ {
		end()
	}
	for i := 0; i < nops; i++ {
		ev19FDTU32(&b, 4) // FDT_NOP: walked, adds no node and no depth
	}
	end()
	ev19FDTU32(&b, 9) // FDT_END
	return b.Bytes()
}

// ev19FDTFile wraps a struct block in a v17 header plus reservation map.
func ev19FDTFile(block []byte) []byte {
	const hdr = 40
	structOff := hdr + 16 // 16-byte empty memory reservation map
	strOff := structOff + len(block)
	total := strOff + len(ev19FDTStrings)

	var b bytes.Buffer
	ev19FDTU32(&b, 0xd00dfeed)
	ev19FDTU32(&b, uint32(total))
	ev19FDTU32(&b, uint32(structOff))
	ev19FDTU32(&b, uint32(strOff))
	ev19FDTU32(&b, hdr) // off_mem_rsvmap
	ev19FDTU32(&b, 17)  // version
	ev19FDTU32(&b, 16)  // last_comp_version
	ev19FDTU32(&b, 0)   // boot_cpuid_phys
	ev19FDTU32(&b, uint32(len(ev19FDTStrings)))
	ev19FDTU32(&b, uint32(len(block)))
	// Empty reservation map: two zero u64 entries, matching structOff.
	ev19FDTU32(&b, 0)
	ev19FDTU32(&b, 0)
	ev19FDTU32(&b, 0)
	ev19FDTU32(&b, 0)
	b.Write(block)
	b.Write(ev19FDTStrings)
	return b.Bytes()
}

type ev19FDTResult struct {
	Nodes    int `json:"nodes"`
	MaxDepth int `json:"max_depth"`
}

func ev19FDTWalk(t *testing.T, path string) ev19FDTResult {
	t.Helper()
	bin := "." + string(os.PathSeparator) + "lrecon"
	out, err := exec.Command(bin, "--json", "--op", "inspect_devicetree", path).Output()
	if err != nil {
		t.Fatalf("lrecon inspect_devicetree %s: %v", filepath.Base(path), err)
	}
	var env struct {
		Result ev19FDTResult `json:"result"`
	}
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("inspect_devicetree output is not JSON: %v (%q)", err, out)
	}
	return env.Result
}

func TestEvergreen19AstDepthRatio(t *testing.T) {
	dir := t.TempDir()

	// --- Pair 1: equal-byte .go sources, flat vs nested -------------------
	flatSrc := ev19GoFlat(240)
	deepSrc := ev19GoDeep(14)
	target := len(flatSrc)
	if len(deepSrc) > target {
		target = len(deepSrc)
	}
	flatSrc = ev19Pad(flatSrc, target-len(flatSrc))
	deepSrc = ev19Pad(deepSrc, target-len(deepSrc))
	if len(flatSrc) != len(deepSrc) {
		t.Fatalf("go fixtures differ in size: %d vs %d", len(flatSrc), len(deepSrc))
	}

	flatPath := filepath.Join(dir, "flat.go")
	deepPath := filepath.Join(dir, "deep.go")
	if err := os.WriteFile(flatPath, []byte(flatSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deepPath, []byte(deepSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	flatGoDepth := ev19AstDepth(t, flatSrc)
	deepGoDepth := ev19AstDepth(t, deepSrc)
	if flatGoDepth > 8 {
		t.Fatalf("flat go fixture is not flat: depth %d", flatGoDepth)
	}
	if deepGoDepth < 3*flatGoDepth {
		t.Fatalf("go fixtures are not structurally distinct: flat depth %d, deep depth %d",
			flatGoDepth, deepGoDepth)
	}

	// --- Pair 2: equal-byte FDT blobs, broad vs deep ----------------------
	flatBlock := ev19FDTStructBlock(0, 40, 0)
	deepBlock := ev19FDTStructBlock(12, 0, 0)
	if len(flatBlock) < len(deepBlock) {
		t.Fatalf("construct the broad blob first, got %d < %d", len(flatBlock), len(deepBlock))
	}
	if diff := len(flatBlock) - len(deepBlock); diff%4 != 0 {
		t.Fatalf("nop padding cannot equalize a %d-byte gap", diff)
	} else {
		deepBlock = ev19FDTStructBlock(12, 0, diff/4)
	}

	flatBlob := ev19FDTFile(flatBlock)
	deepBlob := ev19FDTFile(deepBlock)
	if len(flatBlob) != len(deepBlob) {
		t.Fatalf("fdt fixtures differ in size: %d vs %d", len(flatBlob), len(deepBlob))
	}

	flatBlobPath := filepath.Join(dir, "flat.dtb")
	deepBlobPath := filepath.Join(dir, "deep.dtb")
	if err := os.WriteFile(flatBlobPath, flatBlob, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(deepBlobPath, deepBlob, 0o644); err != nil {
		t.Fatal(err)
	}

	// --- Structural measure: lrecon's own tree walk ----------------------
	flat := ev19FDTWalk(t, flatBlobPath)
	deep := ev19FDTWalk(t, deepBlobPath)

	t.Logf("go fixtures: %d bytes each, ast depth flat=%d deep=%d (%.1fx)",
		len(flatSrc), flatGoDepth, deepGoDepth, float64(deepGoDepth)/float64(flatGoDepth))
	t.Logf("fdt fixtures: %d bytes each, nodes flat=%d deep=%d, max_depth flat=%d deep=%d (%.1fx)",
		len(flatBlob), flat.Nodes, deep.Nodes, flat.MaxDepth, deep.MaxDepth,
		float64(deep.MaxDepth)/float64(flat.MaxDepth))

	if flat.MaxDepth < 2 {
		t.Fatalf("flat blob reports depth %d, want root plus one level", flat.MaxDepth)
	}
	// The inverted node count is what rules out a flat scan: the deep blob is
	// smaller in node terms yet deeper in tree terms.
	if deep.Nodes >= flat.Nodes {
		t.Fatalf("deep blob should hold fewer nodes than the broad one: deep=%d flat=%d",
			deep.Nodes, flat.Nodes)
	}
	if deep.MaxDepth < 3*flat.MaxDepth {
		t.Fatalf("tree walk does not separate the shapes: flat max_depth %d, deep max_depth %d",
			flat.MaxDepth, deep.MaxDepth)
	}
}
