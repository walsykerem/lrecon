package main

// ECMA-335 CIL disassembly behind decompile_all. ghidra headless imports
// machine code only, so a managed assembly (kind pe-dotnet) needs a reader for
// the method bodies the metadata tables point at: MethodDef rows carry an RVA,
// that RVA holds a tiny or fat header, and the bytes after the header are IL.
// Every line this file emits is decoded from those bytes; nothing is guessed.
//
// shortcut: method and member names print without their #Blob signatures, upgrade by decoding the signature blobs when parameter types are needed.
// shortcut: TypeSpec parents and tokens print as hex (0x1B......), upgrade by decoding ELEMENT_TYPE_GENERICINST signature blobs.
// shortcut: fat method exception handler sections are not listed, upgrade by walking the EH table that follows the code.

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Caps: an assembly can hold tens of thousands of methods and one list that big
// cannot be JSON. The counts and capped flag keep a cut listing honest.
const (
	maxCILTypes          = 512
	maxCILMethodsPerType = 128
	maxCILPerMethod      = 1024
	maxCILTotalLines     = 20000
	maxCILMethodBody     = 1 << 20 // one MethodDef code size sanity bound
	maxCILSwitchCases    = 1 << 16
	cliFatHeaderSize     = 12
)

type cilListing struct {
	Format       string    `json:"format"`
	Assembly     string    `json:"assembly,omitempty"`
	Module       string    `json:"module,omitempty"`
	Types        int       `json:"types"`
	Methods      int       `json:"methods"`
	Disassembled int       `json:"disassembled"`
	NoBody       int       `json:"no_body"`
	Failed       int       `json:"failed"`
	ILBytes      int       `json:"il_bytes"`
	ILLines      int       `json:"il_lines"`
	Capped       bool      `json:"capped"`
	Listing      []cilType `json:"listing"`
}

type cilType struct {
	Type    string      `json:"type"`
	Token   string      `json:"token"`
	Methods []cilMethod `json:"methods"`
}

type cilMethod struct {
	Token     string   `json:"token"`
	Name      string   `json:"name"`
	Header    string   `json:"header"`
	MaxStack  int      `json:"max_stack,omitempty"`
	CodeSize  int      `json:"code_size"`
	Locals    string   `json:"locals,omitempty"`
	IL        []string `json:"il,omitempty"`
	Truncated bool     `json:"truncated,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// decompileManaged lists every TypeDef with the IL of each method it owns.
func decompileManaged(path string) (any, error) {
	c, err := openCLIView(path)
	if err != nil {
		return skipf("%s: %v", path, err), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, ok := openPEImage(f)
	if !ok {
		return skipf("%s: no PE image for the CLI metadata", path), nil
	}
	x := newCILIndex(c)
	res := cilListing{Format: "ecma-335-cil", Types: c.n(0x02), Methods: c.n(0x06)}
	res.Module, res.Assembly = x.module, x.assembly

	lines := 0
	for ti := 1; ti <= res.Types; ti++ {
		name := x.typeDefName(ti)
		ct := cilType{Type: name, Token: fmt.Sprintf("0x%08X", 0x02000000|ti), Methods: []cilMethod{}}
		m0 := x.listStart(ti, 5, res.Methods)
		m1 := x.listStart(ti+1, 5, res.Methods)
		if res.Types > maxCILTypes && ti > maxCILTypes {
			res.Capped = true
			break
		}
		for m := m0; m < m1; m++ {
			mr := c.row(0x06, m)
			rva := idxAt(mr, x.mdO[0], x.mdW[0])
			if rva == 0 {
				res.NoBody++ // abstract, extern or P/Invoke: no body to decode
				continue
			}
			if len(ct.Methods) >= maxCILMethodsPerType || lines >= maxCILTotalLines {
				res.Capped = true
				continue
			}
			cm := cilMethod{Token: fmt.Sprintf("0x%08X", 0x06000000|(m+1)),
				Name: c.str(idxAt(mr, x.mdO[3], x.mdW[3]))}
			body, header, maxStack, locals, err := cilBody(img, rva)
			if err != nil {
				cm.Error = err.Error()
				res.Failed++
				ct.Methods = append(ct.Methods, cm)
				continue
			}
			cm.Header, cm.MaxStack, cm.CodeSize = header, int(maxStack), len(body)
			if locals != 0 {
				cm.Locals = fmt.Sprintf("0x%08X", locals)
			}
			cm.IL, cm.Truncated = disassembleCIL(body, x, maxCILPerMethod)
			res.Disassembled++
			res.ILBytes += len(body)
			res.ILLines += len(cm.IL)
			lines += len(cm.IL)
			if cm.Truncated {
				res.Capped = true
			}
			ct.Methods = append(ct.Methods, cm)
		}
		res.Listing = append(res.Listing, ct)
	}
	return res, nil
}

// cilBody reads one MethodDef body: a tiny header is the high six bits of one
// byte; a fat header is a 12-byte block holding flags, max stack, code size and
// the locals signature token.
func cilBody(img peImage, rva uint32) (code []byte, header string, maxStack uint16, locals uint32, err error) {
	h, ok := img.at(rva, 1)
	if !ok {
		return nil, "", 0, 0, fmt.Errorf("method header at RVA 0x%x is outside every section", rva)
	}
	switch h[0] & 3 {
	case 2:
		size := int(h[0] >> 2)
		code, ok = img.at(rva+1, uint32(size))
		if !ok {
			return nil, "", 0, 0, fmt.Errorf("tiny body at RVA 0x%x is truncated (%d bytes)", rva, size)
		}
		return code, "tiny", 8, 0, nil
	case 3:
		fat, ok := img.at(rva, cliFatHeaderSize)
		if !ok {
			return nil, "", 0, 0, fmt.Errorf("fat header at RVA 0x%x is truncated", rva)
		}
		if words := int(u16le(fat, 0) >> 12); words*4 < cliFatHeaderSize {
			return nil, "", 0, 0, fmt.Errorf("fat header at RVA 0x%x claims %d words", rva, words)
		}
		size := int(u32le(fat, 4))
		if size > maxCILMethodBody {
			return nil, "", 0, 0, fmt.Errorf("fat body at RVA 0x%x claims %d bytes, above the %d cap", rva, size, maxCILMethodBody)
		}
		code, ok = img.at(rva+cliFatHeaderSize, uint32(size))
		if !ok {
			return nil, "", 0, 0, fmt.Errorf("fat body at RVA 0x%x is truncated (%d bytes)", rva, size)
		}
		return code, "fat", u16le(fat, 2), u32le(fat, 8), nil
	}
	return nil, "", 0, 0, fmt.Errorf("method header at RVA 0x%x has reserved flags 0x%02x", rva, h[0]&3)
}

// ---------------------------------------------------------------- opcodes
//
// ECMA-335 Partition VI opcode table. The kind fixes the operand width and how
// the operand is rendered; an empty name marks a reserved byte.

const (
	ckNone = iota
	ckByte
	ckShortVar
	ckVar
	ckShortI
	ckI
	ckI8
	ckShortR
	ckR
	ckBrShort
	ckBr
	ckSwitch
	ckString
	ckField
	ckMethodTok
	ckTypeTok
	ckTok
	ckSig
)

type cilOp struct {
	name string
	kind int
}

var cilOps1 = [256]cilOp{
	0x00: {"nop", ckNone},
	0x01: {"break", ckNone},
	0x02: {"ldarg.0", ckNone},
	0x03: {"ldarg.1", ckNone},
	0x04: {"ldarg.2", ckNone},
	0x05: {"ldarg.3", ckNone},
	0x06: {"ldloc.0", ckNone},
	0x07: {"ldloc.1", ckNone},
	0x08: {"ldloc.2", ckNone},
	0x09: {"ldloc.3", ckNone},
	0x0A: {"stloc.0", ckNone},
	0x0B: {"stloc.1", ckNone},
	0x0C: {"stloc.2", ckNone},
	0x0D: {"stloc.3", ckNone},
	0x0E: {"ldarg.s", ckShortVar},
	0x0F: {"ldarga.s", ckShortVar},
	0x10: {"starg.s", ckShortVar},
	0x11: {"ldloc.s", ckShortVar},
	0x12: {"ldloca.s", ckShortVar},
	0x13: {"stloc.s", ckShortVar},
	0x14: {"ldnull", ckNone},
	0x15: {"ldc.i4.m1", ckNone},
	0x16: {"ldc.i4.0", ckNone},
	0x17: {"ldc.i4.1", ckNone},
	0x18: {"ldc.i4.2", ckNone},
	0x19: {"ldc.i4.3", ckNone},
	0x1A: {"ldc.i4.4", ckNone},
	0x1B: {"ldc.i4.5", ckNone},
	0x1C: {"ldc.i4.6", ckNone},
	0x1D: {"ldc.i4.7", ckNone},
	0x1E: {"ldc.i4.8", ckNone},
	0x1F: {"ldc.i4.s", ckShortI},
	0x20: {"ldc.i4", ckI},
	0x21: {"ldc.i8", ckI8},
	0x22: {"ldc.r4", ckShortR},
	0x23: {"ldc.r8", ckR},
	0x25: {"dup", ckNone},
	0x26: {"pop", ckNone},
	0x27: {"jmp", ckMethodTok},
	0x28: {"call", ckMethodTok},
	0x29: {"calli", ckSig},
	0x2A: {"ret", ckNone},
	0x2B: {"br.s", ckBrShort},
	0x2C: {"brfalse.s", ckBrShort},
	0x2D: {"brtrue.s", ckBrShort},
	0x2E: {"beq.s", ckBrShort},
	0x2F: {"bge.s", ckBrShort},
	0x30: {"bgt.s", ckBrShort},
	0x31: {"ble.s", ckBrShort},
	0x32: {"blt.s", ckBrShort},
	0x33: {"bne.un.s", ckBrShort},
	0x34: {"bge.un.s", ckBrShort},
	0x35: {"bgt.un.s", ckBrShort},
	0x36: {"ble.un.s", ckBrShort},
	0x37: {"blt.un.s", ckBrShort},
	0x38: {"br", ckBr},
	0x39: {"brfalse", ckBr},
	0x3A: {"brtrue", ckBr},
	0x3B: {"beq", ckBr},
	0x3C: {"bge", ckBr},
	0x3D: {"bgt", ckBr},
	0x3E: {"ble", ckBr},
	0x3F: {"blt", ckBr},
	0x40: {"bne.un", ckBr},
	0x41: {"bge.un", ckBr},
	0x42: {"bgt.un", ckBr},
	0x43: {"ble.un", ckBr},
	0x44: {"blt.un", ckBr},
	0x45: {"switch", ckSwitch},
	0x46: {"ldind.i1", ckNone},
	0x47: {"ldind.u1", ckNone},
	0x48: {"ldind.i2", ckNone},
	0x49: {"ldind.u2", ckNone},
	0x4A: {"ldind.i4", ckNone},
	0x4B: {"ldind.u4", ckNone},
	0x4C: {"ldind.i8", ckNone},
	0x4D: {"ldind.i", ckNone},
	0x4E: {"ldind.r4", ckNone},
	0x4F: {"ldind.r8", ckNone},
	0x50: {"ldind.ref", ckNone},
	0x51: {"stind.ref", ckNone},
	0x52: {"stind.i1", ckNone},
	0x53: {"stind.i2", ckNone},
	0x54: {"stind.i4", ckNone},
	0x55: {"stind.i8", ckNone},
	0x56: {"stind.r4", ckNone},
	0x57: {"stind.r8", ckNone},
	0x58: {"add", ckNone},
	0x59: {"sub", ckNone},
	0x5A: {"mul", ckNone},
	0x5B: {"div", ckNone},
	0x5C: {"div.un", ckNone},
	0x5D: {"rem", ckNone},
	0x5E: {"rem.un", ckNone},
	0x5F: {"and", ckNone},
	0x60: {"or", ckNone},
	0x61: {"xor", ckNone},
	0x62: {"shl", ckNone},
	0x63: {"shr", ckNone},
	0x64: {"shr.un", ckNone},
	0x65: {"neg", ckNone},
	0x66: {"not", ckNone},
	0x67: {"conv.i1", ckNone},
	0x68: {"conv.i2", ckNone},
	0x69: {"conv.i4", ckNone},
	0x6A: {"conv.i8", ckNone},
	0x6B: {"conv.r4", ckNone},
	0x6C: {"conv.r8", ckNone},
	0x6D: {"conv.u4", ckNone},
	0x6E: {"conv.u8", ckNone},
	0x6F: {"callvirt", ckMethodTok},
	0x70: {"cpobj", ckTypeTok},
	0x71: {"ldobj", ckTypeTok},
	0x72: {"ldstr", ckString},
	0x73: {"newobj", ckMethodTok},
	0x74: {"castclass", ckTypeTok},
	0x75: {"isinst", ckTypeTok},
	0x76: {"conv.r.un", ckNone},
	0x79: {"unbox", ckTypeTok},
	0x7A: {"throw", ckNone},
	0x7B: {"ldfld", ckField},
	0x7C: {"ldflda", ckField},
	0x7D: {"stfld", ckField},
	0x7E: {"ldsfld", ckField},
	0x7F: {"ldsflda", ckField},
	0x80: {"stsfld", ckField},
	0x81: {"stobj", ckTypeTok},
	0x82: {"conv.ovf.i1.un", ckNone},
	0x83: {"conv.ovf.i2.un", ckNone},
	0x84: {"conv.ovf.i4.un", ckNone},
	0x85: {"conv.ovf.i8.un", ckNone},
	0x86: {"conv.ovf.u1.un", ckNone},
	0x87: {"conv.ovf.u2.un", ckNone},
	0x88: {"conv.ovf.u4.un", ckNone},
	0x89: {"conv.ovf.u8.un", ckNone},
	0x8A: {"conv.ovf.i.un", ckNone},
	0x8B: {"conv.ovf.u.un", ckNone},
	0x8C: {"box", ckTypeTok},
	0x8D: {"newarr", ckTypeTok},
	0x8E: {"ldlen", ckNone},
	0x8F: {"ldelema", ckTypeTok},
	0x90: {"ldelem.i1", ckNone},
	0x91: {"ldelem.u1", ckNone},
	0x92: {"ldelem.i2", ckNone},
	0x93: {"ldelem.u2", ckNone},
	0x94: {"ldelem.i4", ckNone},
	0x95: {"ldelem.u4", ckNone},
	0x96: {"ldelem.i8", ckNone},
	0x97: {"ldelem.i", ckNone},
	0x98: {"ldelem.r4", ckNone},
	0x99: {"ldelem.r8", ckNone},
	0x9A: {"ldelem.ref", ckNone},
	0x9B: {"stelem.i", ckNone},
	0x9C: {"stelem.i1", ckNone},
	0x9D: {"stelem.i2", ckNone},
	0x9E: {"stelem.i4", ckNone},
	0x9F: {"stelem.i8", ckNone},
	0xA0: {"stelem.r4", ckNone},
	0xA1: {"stelem.r8", ckNone},
	0xA2: {"stelem.ref", ckNone},
	0xA3: {"ldelem", ckTypeTok},
	0xA4: {"stelem", ckTypeTok},
	0xA5: {"unbox.any", ckTypeTok},
	0xB3: {"conv.ovf.i1", ckNone},
	0xB4: {"conv.ovf.u1", ckNone},
	0xB5: {"conv.ovf.i2", ckNone},
	0xB6: {"conv.ovf.u2", ckNone},
	0xB7: {"conv.ovf.i4", ckNone},
	0xB8: {"conv.ovf.u4", ckNone},
	0xB9: {"conv.ovf.i8", ckNone},
	0xBA: {"conv.ovf.u8", ckNone},
	0xC2: {"refanyval", ckTypeTok},
	0xC3: {"ckfinite", ckNone},
	0xC6: {"mkrefany", ckTypeTok},
	0xD0: {"ldtoken", ckTok},
	0xD1: {"conv.u2", ckNone},
	0xD2: {"conv.u1", ckNone},
	0xD3: {"conv.i", ckNone},
	0xD4: {"conv.ovf.i", ckNone},
	0xD5: {"conv.ovf.u", ckNone},
	0xD6: {"add.ovf", ckNone},
	0xD7: {"add.ovf.un", ckNone},
	0xD8: {"mul.ovf", ckNone},
	0xD9: {"mul.ovf.un", ckNone},
	0xDA: {"sub.ovf", ckNone},
	0xDB: {"sub.ovf.un", ckNone},
	0xDC: {"endfinally", ckNone},
	0xDD: {"leave", ckBr},
	0xDE: {"leave.s", ckBrShort},
	0xDF: {"stind.i", ckNone},
	0xE0: {"conv.u", ckNone},
}

var cilOpsFE = [256]cilOp{
	0x00: {"arglist", ckNone},
	0x01: {"ceq", ckNone},
	0x02: {"cgt", ckNone},
	0x03: {"cgt.un", ckNone},
	0x04: {"clt", ckNone},
	0x05: {"clt.un", ckNone},
	0x06: {"ldftn", ckMethodTok},
	0x07: {"ldvirtftn", ckMethodTok},
	0x09: {"ldarg", ckVar},
	0x0A: {"ldarga", ckVar},
	0x0B: {"starg", ckVar},
	0x0C: {"ldloc", ckVar},
	0x0D: {"ldloca", ckVar},
	0x0E: {"stloc", ckVar},
	0x0F: {"localloc", ckNone},
	0x11: {"endfilter", ckNone},
	0x12: {"unaligned.", ckByte},
	0x13: {"volatile.", ckNone},
	0x14: {"tail.", ckNone},
	0x15: {"initobj", ckTypeTok},
	0x16: {"constrained.", ckTypeTok},
	0x17: {"cpblk", ckNone},
	0x18: {"initblk", ckNone},
	0x19: {"no.", ckByte},
	0x1A: {"rethrow", ckNone},
	0x1C: {"sizeof", ckTypeTok},
	0x1D: {"refanytype", ckNone},
	0x1E: {"readonly.", ckNone},
}

// disassembleCIL decodes one method body. An opcode or operand that does not
// fit the bytes is reported as truncated at the offset it stopped; a reserved
// opcode is named by its bytes, never skipped silently.
func disassembleCIL(code []byte, x *cilIndex, max int) (lines []string, truncated bool) {
	for pc := 0; pc < len(code); {
		start := pc
		b := code[pc]
		pc++
		op := cilOps1[b]
		if b == 0xFE {
			if pc >= len(code) {
				lines = append(lines, fmt.Sprintf("IL_%04X: <truncated 0xfe prefix>", start))
				return lines, true
			}
			op = cilOpsFE[code[pc]]
			pc++
		}
		if op.name == "" {
			lines = append(lines, fmt.Sprintf("IL_%04X: <reserved 0x%02x>", start, b))
		} else {
			text, next, ok := cilOperand(code, pc, op.kind, x)
			if !ok {
				lines = append(lines, fmt.Sprintf("IL_%04X: %s <truncated operand>", start, op.name))
				return lines, true
			}
			pc = next
			if text != "" {
				lines = append(lines, fmt.Sprintf("IL_%04X: %s %s", start, op.name, text))
			} else {
				lines = append(lines, fmt.Sprintf("IL_%04X: %s", start, op.name))
			}
		}
		if len(lines) >= max && pc < len(code) {
			lines = append(lines, fmt.Sprintf("IL_%04X: <truncated at %d instructions>", pc, max))
			return lines, true
		}
	}
	return lines, false
}

// cilOperand renders one operand and returns the offset after it. pc is the
// first operand byte.
func cilOperand(code []byte, pc, kind int, x *cilIndex) (string, int, bool) {
	need := func(n int) bool { return pc+n <= len(code) }
	switch kind {
	case ckNone:
		return "", pc, true
	case ckByte:
		if !need(1) {
			return "", pc, false
		}
		return strconv.Itoa(int(code[pc])), pc + 1, true
	case ckShortVar, ckShortI:
		if !need(1) {
			return "", pc, false
		}
		return strconv.Itoa(int(int8(code[pc]))), pc + 1, true
	case ckVar:
		if !need(2) {
			return "", pc, false
		}
		return strconv.Itoa(int(u16le(code, pc))), pc + 2, true
	case ckI:
		if !need(4) {
			return "", pc, false
		}
		return strconv.FormatInt(int64(int32(u32le(code, pc))), 10), pc + 4, true
	case ckI8:
		if !need(8) {
			return "", pc, false
		}
		return strconv.FormatInt(int64(binary.LittleEndian.Uint64(code[pc:])), 10), pc + 8, true
	case ckShortR:
		if !need(4) {
			return "", pc, false
		}
		f := math.Float32frombits(u32le(code, pc))
		return strconv.FormatFloat(float64(f), 'g', -1, 32), pc + 4, true
	case ckR:
		if !need(8) {
			return "", pc, false
		}
		f := math.Float64frombits(binary.LittleEndian.Uint64(code[pc:]))
		return strconv.FormatFloat(f, 'g', -1, 64), pc + 8, true
	case ckBrShort:
		if !need(1) {
			return "", pc, false
		}
		next := pc + 1
		return fmt.Sprintf("IL_%04X", next+int(int8(code[pc]))), next, true
	case ckBr:
		if !need(4) {
			return "", pc, false
		}
		next := pc + 4
		return fmt.Sprintf("IL_%04X", next+int(int32(u32le(code, pc)))), next, true
	case ckSwitch:
		if !need(4) {
			return "", pc, false
		}
		n := int(int32(u32le(code, pc)))
		end := pc + 4 + 4*n
		if n < 0 || n > maxCILSwitchCases || end > len(code) {
			return "", pc, false
		}
		targets := make([]string, n)
		for i := range n {
			targets[i] = fmt.Sprintf("IL_%04X", end+int(int32(u32le(code, pc+4+4*i))))
		}
		return "(" + strings.Join(targets, ", ") + ")", end, true
	case ckString, ckField, ckMethodTok, ckTypeTok, ckTok, ckSig:
		if !need(4) {
			return "", pc, false
		}
		tok := u32le(code, pc)
		if kind == ckString && tok>>24 == 0x70 {
			if s := x.userString(int(tok & 0xFFFFFF)); s != "" {
				return strconv.Quote(s), pc + 4, true
			}
		}
		return x.token(tok), pc + 4, true
	}
	return "", pc, false
}

// ------------------------------------------------------------- name lookup
//
// Every token is resolved through the metadata tables so a listing names its
// callee instead of printing a number: [System.Runtime]System.Object::.ctor is
// a fact from TypeRef + ResolutionScope, not a prettification.

type cilIndex struct {
	c           *cliView
	tdW, tdO    []int
	mdW, mdO    []int
	enclosing   map[int]int    // 1-based nested TypeDef -> 1-based enclosing TypeDef
	methodOwner map[int]string // 1-based MethodDef -> TypeDef display name
	fieldOwner  map[int]string // 1-based Field -> TypeDef display name
	module      string
	assembly    string
}

func newCILIndex(c *cliView) *cilIndex {
	x := &cilIndex{c: c, enclosing: map[int]int{}, methodOwner: map[int]string{}, fieldOwner: map[int]string{}}
	x.tdW, x.tdO = c.cols(0x02)
	x.mdW, x.mdO = c.cols(0x06)
	if n := c.n(0x29); n > 0 {
		w, o := c.cols(0x29)
		for i := range n {
			r := c.row(0x29, i)
			x.enclosing[int(idxAt(r, o[0], w[0]))] = int(idxAt(r, o[1], w[1]))
		}
	}
	if c.n(0x00) > 0 {
		w, o := c.cols(0x00)
		x.module = c.str(idxAt(c.row(0x00, 0), o[1], w[1]))
	}
	if c.n(0x20) > 0 {
		w, o := c.cols(0x20)
		x.assembly = c.str(idxAt(c.row(0x20, 0), o[7], w[7]))
	}
	types, methods, fields := c.n(0x02), c.n(0x06), c.n(0x04)
	for ti := 1; ti <= types; ti++ {
		name := x.typeDefName(ti)
		m0, m1 := x.listStart(ti, 5, methods), x.listStart(ti+1, 5, methods)
		for m := m0; m < m1; m++ {
			x.methodOwner[m+1] = name
		}
		f0, f1 := x.listStart(ti, 4, fields), x.listStart(ti+1, 4, fields)
		for fi := f0; fi < f1; fi++ {
			x.fieldOwner[fi+1] = name
		}
	}
	return x
}

// listStart is a TypeDef list column (4 FieldList, 5 MethodList) as a 0-based
// row index, clamped to the table so a corrupt row cannot slice past it.
func (x *cilIndex) listStart(ti, col, n int) int {
	if ti < 1 || ti > x.c.n(0x02) {
		return n
	}
	v := int(idxAt(x.c.row(0x02, ti-1), x.tdO[col], x.tdW[col])) - 1
	if v < 0 {
		return 0
	}
	if v > n {
		return n
	}
	return v
}

func (x *cilIndex) typeDefName(i int) string { return x.typeDefNameDepth(i, 0) }

func (x *cilIndex) typeDefNameDepth(i, depth int) string {
	if i < 1 || i > x.c.n(0x02) || depth > 16 {
		return ""
	}
	r := x.c.row(0x02, i-1)
	name := x.c.str(idxAt(r, x.tdO[1], x.tdW[1]))
	if enc, ok := x.enclosing[i]; ok {
		return x.typeDefNameDepth(enc, depth+1) + "/" + name
	}
	if ns := x.c.str(idxAt(r, x.tdO[2], x.tdW[2])); ns != "" {
		return ns + "." + name
	}
	return name
}

func (x *cilIndex) typeRefName(i int) string { return x.typeRefNameDepth(i, 0) }

func (x *cilIndex) typeRefNameDepth(i, depth int) string {
	if i < 1 || i > x.c.n(0x01) || depth > 16 {
		return ""
	}
	w, o := x.c.cols(0x01)
	r := x.c.row(0x01, i-1)
	name := x.c.str(idxAt(r, o[1], w[1]))
	ns := x.c.str(idxAt(r, o[2], w[2]))
	full := name
	if ns != "" {
		full = ns + "." + name
	}
	table, idx := x.coded("ResolutionScope", idxAt(r, o[0], w[0]))
	switch table {
	case 0x23: // AssemblyRef
		if a := x.assemblyRefName(idx); a != "" {
			return "[" + a + "]" + full
		}
	case 0x1A: // ModuleRef
		if m := x.moduleRefName(idx); m != "" {
			return "[" + m + "]" + full
		}
	case 0x01: // nesting TypeRef: the namespace lives on the outer name
		return x.typeRefNameDepth(idx, depth+1) + "/" + name
	}
	return full
}

func (x *cilIndex) assemblyRefName(i int) string {
	if i < 1 || i > x.c.n(0x23) {
		return ""
	}
	w, o := x.c.cols(0x23)
	return x.c.str(idxAt(x.c.row(0x23, i-1), o[6], w[6]))
}

func (x *cilIndex) moduleRefName(i int) string {
	if i < 1 || i > x.c.n(0x1A) {
		return ""
	}
	w, o := x.c.cols(0x1A)
	return x.c.str(idxAt(x.c.row(0x1A, i-1), o[0], w[0]))
}

func (x *cilIndex) methodDefName(i int) string {
	if i < 1 || i > x.c.n(0x06) {
		return ""
	}
	name := x.c.str(idxAt(x.c.row(0x06, i-1), x.mdO[3], x.mdW[3]))
	if owner := x.methodOwner[i]; owner != "" {
		return owner + "::" + name
	}
	return name
}

func (x *cilIndex) fieldDefName(i int) string {
	if i < 1 || i > x.c.n(0x04) {
		return ""
	}
	w, o := x.c.cols(0x04)
	name := x.c.str(idxAt(x.c.row(0x04, i-1), o[1], w[1]))
	if owner := x.fieldOwner[i]; owner != "" {
		return owner + "::" + name
	}
	return name
}

func (x *cilIndex) memberRefName(i int) string {
	if i < 1 || i > x.c.n(0x0A) {
		return ""
	}
	w, o := x.c.cols(0x0A)
	r := x.c.row(0x0A, i-1)
	name := x.c.str(idxAt(r, o[1], w[1]))
	table, idx := x.coded("MemberRefParent", idxAt(r, o[0], w[0]))
	switch table {
	case 0x02:
		return x.typeDefName(idx) + "::" + name
	case 0x01:
		return x.typeRefName(idx) + "::" + name
	case 0x06:
		return x.methodDefName(idx) + "::" + name
	case 0x1B: // TypeSpec: a generic instantiation, whose signature is not decoded
		return fmt.Sprintf("0x%08X::%s", 0x1B000000|idx, name)
	}
	return "::" + name
}

func (x *cilIndex) methodSpecName(i int) string {
	if i < 1 || i > x.c.n(0x2B) {
		return ""
	}
	w, o := x.c.cols(0x2B)
	table, idx := x.coded("MethodDefOrRef", idxAt(x.c.row(0x2B, i-1), o[0], w[0]))
	var base string
	switch table {
	case 0x06:
		base = x.methodDefName(idx)
	case 0x0A:
		base = x.memberRefName(idx)
	}
	if base == "" {
		return ""
	}
	return base + "<>"
}

// userString decodes a #US entry: a compressed byte count (the trailing
// terminal byte included), then UTF-16LE.
func (x *cilIndex) userString(i int) string {
	h := x.c.md.data["#US"]
	if i <= 0 || i >= len(h) {
		return ""
	}
	n, used := compressedUint(h[i:])
	if n < 1 || i+used+n > len(h) {
		return ""
	}
	b := h[i+used : i+used+n-1]
	u := make([]uint16, len(b)/2)
	for k := range u {
		u[k] = binary.LittleEndian.Uint16(b[k*2:])
	}
	return string(utf16.Decode(u))
}

func compressedUint(b []byte) (int, int) {
	switch {
	case len(b) == 0:
		return 0, 0
	case b[0]&0x80 == 0:
		return int(b[0]), 1
	case b[0]&0xC0 == 0x80 && len(b) >= 2:
		return int(b[0]&0x3F)<<8 | int(b[1]), 2
	case b[0]&0xE0 == 0xC0 && len(b) >= 4:
		return int(b[0]&0x1F)<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3]), 4
	}
	return 0, 0
}

// coded splits a coded index into its table id and 1-based row.
func (x *cilIndex) coded(name string, v uint32) (int, int) {
	tags := codedTagTables[name]
	bits := 0
	for len(tags) > 1<<bits {
		bits++
	}
	tag := int(v & ((1 << bits) - 1))
	if tag >= len(tags) || tags[tag] < 0 {
		return -1, 0
	}
	return tags[tag], int(v >> bits)
}

func (x *cilIndex) token(tok uint32) string {
	var s string
	i := int(tok & 0xFFFFFF)
	switch tok >> 24 {
	case 0x01:
		s = x.typeRefName(i)
	case 0x02:
		s = x.typeDefName(i)
	case 0x04:
		s = x.fieldDefName(i)
	case 0x06:
		s = x.methodDefName(i)
	case 0x0A:
		s = x.memberRefName(i)
	case 0x2B:
		s = x.methodSpecName(i)
	}
	if s == "" {
		return fmt.Sprintf("0x%08X", tok)
	}
	return s
}
