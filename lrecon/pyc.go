package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
)

// CPython .pyc: a u16 magic whose last two bytes are always 0d 0a, then a
// version-dependent header, then one marshalled code object. The magic number
// IS the version: the file carries no other version field. All numbers below
// and in the decoder are little-endian, and every raw int is a plain u32, not a
// marshalled TYPE_INT.
const (
	pycMaxRead    = 16 << 20
	pycMaxImports = 64
	pycDepth      = 1000 // 2000 from 3.14
)

func init() {
	register(reader{
		format: "pyc",
		reasons: []string{
			"pyc-version-unverified",
			"pyc-flags-unsupported",
			"pyc-marshal-truncated",
			"pyc-marshal-too-deep",
			"pyc-not-code",
			"pyc-too-big",
		},
		match:   pycMatch,
		inspect: inspectPyc,
	})
}

// pycMatch takes the fixed half of the magic plus a plausible magic-number
// window. The window keeps text files that happen to hold "\r\n" at 2-3 out,
// while a real but unmapped version still gets claimed and refused by name.
func pycMatch(head []byte, size int64) bool {
	if len(head) < 4 || head[2] != 0x0d || head[3] != 0x0a {
		return false
	}
	n := int(binary.LittleEndian.Uint16(head[:2]))
	return n >= 3100 && n <= 3999
}

// pycVersions maps magic numbers to minor versions as ranges: pre-releases bump
// the number by one (3.11 beta writes 3496).
var pycVersions = []struct {
	lo, hi, minor int
}{
	{3360, 3379, 6},
	{3390, 3394, 7},
	{3400, 3413, 8},
	{3420, 3425, 9},
	{3430, 3439, 10},
	{3450, 3495, 11},
	{3500, 3531, 12},
	{3550, 3571, 13},
	{3600, 3627, 14},
}

func pycVersion(n int) (int, bool) {
	for _, v := range pycVersions {
		if n >= v.lo && n <= v.hi {
			return v.minor, true
		}
	}
	return 0, false
}

func inspectPyc(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		d.Notes = append(d.Notes, "pyc: "+err.Error())
		return
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() >= pycMaxRead {
		d.Kind = "skipped" // too big to read: no format claim, only the refusal
		d.skip("pyc-too-big", fmt.Sprintf("%d bytes, cap %d", st.Size(), pycMaxRead))
		return
	}
	buf, _ := io.ReadAll(io.LimitReader(f, pycMaxRead))
	n := len(buf)
	d.scanned(int64(n))
	if n < 4 {
		d.skip("pyc-version-unverified", fmt.Sprintf("%d bytes", n))
		return
	}
	magic := int(binary.LittleEndian.Uint16(buf[:2]))
	minor, ok := pycVersion(magic)
	if !ok {
		d.skip("pyc-version-unverified", fmt.Sprint(magic))
		return
	}
	ver := 300 + minor
	header, mode := 12, "timestamp"
	if minor >= 7 {
		header = 16
	}
	if n < header {
		d.skip("pyc-marshal-truncated", fmt.Sprintf("header %d/%d bytes", n, header))
		return
	}
	if minor >= 7 {
		flags := binary.LittleEndian.Uint32(buf[4:8])
		if flags&^0x3 != 0 {
			d.skip("pyc-flags-unsupported", fmt.Sprintf("3.%d flags %#x", minor, flags))
			return
		}
		if flags&1 != 0 {
			mode = "unchecked-hash"
			if flags&2 != 0 {
				mode = "checked-hash"
			}
		}
	}
	cap := pycDepth
	if minor >= 14 {
		cap = 2000
	}
	d.Notes = append(d.Notes, fmt.Sprintf("pyc: %d-byte header, %s invalidation, marshal depth cap %d", header, mode, cap))

	dec := &pycDec{b: buf[header:], ver: ver, maxDepth: cap}
	v, err := dec.value()
	if errors.Is(err, errPycDeep) {
		d.skip("pyc-marshal-too-deep", fmt.Sprint(cap))
		return
	}
	if err != nil {
		d.skip("pyc-marshal-truncated", err.Error())
		return
	}
	top, ok := v.(*pyCode)
	if !ok {
		d.skip("pyc-not-code", "top-level marshal value is not a code object")
		return
	}
	if dec.pos < len(dec.b) {
		d.Notes = append(d.Notes, fmt.Sprintf("pyc: %d trailing bytes after the code object", len(dec.b)-dec.pos))
	}

	objs := pycWalk(top)
	d.Toolchain = fmt.Sprintf("cpython 3.%d", minor)
	d.Capabilities = append(d.Capabilities, fmt.Sprintf("pyc:code_objects=%d", len(objs)))
	seen := make(map[string]bool, len(objs))
	var names []string
	for _, c := range objs {
		d.parsed()
		q := c.qualname
		if q == "" {
			q = c.name
		}
		if q != "" && !seen[q] {
			seen[q] = true
			names = append(names, q)
		}
	}
	sort.Strings(names)
	if len(names) > pycMaxImports {
		names = names[:pycMaxImports]
		d.Notes = append(d.Notes, fmt.Sprintf("pyc: qualnames capped at %d", pycMaxImports))
	}
	d.Imports = names
	if top.file != "" {
		d.Notes = append(d.Notes, fmt.Sprintf("pyc: source %q", top.file))
	}
	d.claim(d.Toolchain, "pyc-magic", 0)
	deepNote(d, "walk the code object tree for the qualnames, then decode the marshalled co_code and its linetable to recover the calls and the original line numbers; import targets are not recoverable without that opcode pass")
}

// pyCode keeps only what names need: the marshal payload carries the bytecode,
// the line table and the exception table as opaque bytes, and no opcode is
// decoded here.
type pyCode struct {
	name, qualname, file string
	consts               []any
}

// pycWalk flattens the code object tree. seen guards the one shape a hand-built
// file can add and CPython never writes: a const that back-references its own
// code object.
func pycWalk(c *pyCode) []*pyCode {
	out := []*pyCode{}
	seen := map[*pyCode]bool{}
	var walk func(*pyCode)
	walk = func(c *pyCode) {
		if c == nil || seen[c] {
			return
		}
		seen[c] = true
		out = append(out, c)
		for _, v := range c.consts {
			if inner, ok := v.(*pyCode); ok {
				walk(inner)
			}
		}
	}
	walk(c)
	return out
}

// pycDec reads the marshal stream. Values are decoded into any so the ref table
// can hold them, in first-encounter order, exactly as the writer reserved them.
type pycDec struct {
	b        []byte
	pos      int
	ver      int // 306..314
	refs     []any
	depth    int
	maxDepth int
}

var errPycDeep = errors.New("marshal nesting too deep")

func (p *pycDec) short() error {
	return fmt.Errorf("truncated at byte %d of %d", p.pos, len(p.b))
}

func (p *pycDec) take(n int) ([]byte, error) {
	if n < 0 || n > len(p.b)-p.pos {
		return nil, p.short()
	}
	s := p.b[p.pos : p.pos+n]
	p.pos += n
	return s, nil
}

func (p *pycDec) u8() (byte, error) {
	b, err := p.take(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (p *pycDec) u32() (uint32, error) {
	b, err := p.take(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (p *pycDec) u64() (uint64, error) {
	b, err := p.take(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func (p *pycDec) str32() (string, error) {
	n, err := p.u32()
	if err != nil {
		return "", err
	}
	b, err := p.take(int(n))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// value reads one type byte and its payload. A 0x80 flag only means the writer
// reserved a ref slot before writing: a type-'r' value never carries it.
func (p *pycDec) value() (any, error) {
	if p.depth >= p.maxDepth {
		return nil, errPycDeep
	}
	p.depth++
	defer func() { p.depth-- }()
	code, err := p.u8()
	if err != nil {
		return nil, err
	}
	return p.typed(code)
}

func (p *pycDec) typed(code byte) (any, error) {
	slot := -1
	if code&0x80 != 0 {
		p.refs = append(p.refs, nil)
		slot = len(p.refs) - 1
	}
	v, err := p.body(code &^ 0x80)
	if err != nil {
		return nil, err
	}
	if slot >= 0 {
		p.refs[slot] = v
	}
	return v, nil
}

func (p *pycDec) body(t byte) (any, error) {
	switch t {
	case '0', 'N', '.', 'S': // NULL, None, Ellipsis, StopIteration
		return nil, nil
	case 'F':
		return false, nil
	case 'T':
		return true, nil
	case 'i':
		v, err := p.u32()
		return int64(int32(v)), err
	case 'I':
		v, err := p.u64()
		return int64(v), err
	case 'l': // int too big for 64 bits: 15-bit digits, sign in the count
		n, err := p.u32()
		if err != nil {
			return nil, err
		}
		nd := int64(int32(n))
		if nd < 0 {
			nd = -nd
		}
		if _, err := p.take(int(2 * nd)); err != nil {
			return nil, err
		}
		return nil, nil
	case 'f', 'x': // float / complex written as text
		n, err := p.u8()
		if err != nil {
			return nil, err
		}
		b, err := p.take(int(n))
		if err != nil {
			return nil, err
		}
		if t == 'x' { // imaginary half follows in the same text form
			if _, err := p.body('f'); err != nil {
				return nil, err
			}
		}
		f, _ := strconv.ParseFloat(string(b), 64)
		return f, nil
	case 'g', 'y': // binary float / binary complex
		v, err := p.u64()
		if err != nil {
			return nil, err
		}
		if t == 'y' {
			if _, err := p.take(8); err != nil {
				return nil, err
			}
		}
		return math.Float64frombits(v), nil
	case 's', 't', 'u', 'a', 'A':
		return p.str32()
	case 'z', 'Z':
		n, err := p.u8()
		if err != nil {
			return nil, err
		}
		b, err := p.take(int(n))
		return string(b), err
	case 'r':
		ix, err := p.u32()
		if err != nil {
			return nil, err
		}
		if int64(ix) >= int64(len(p.refs)) || p.refs[ix] == nil {
			return nil, fmt.Errorf("back-reference %d outside the table", ix)
		}
		return p.refs[ix], nil
	case '(':
		n, err := p.u32()
		if err != nil {
			return nil, err
		}
		return p.seq(int64(n))
	case ')':
		n, err := p.u8()
		if err != nil {
			return nil, err
		}
		return p.seq(int64(n))
	case '[', '<', '>':
		n, err := p.u32()
		if err != nil {
			return nil, err
		}
		return p.seq(int64(n))
	case '{':
		return p.dict()
	case 'c':
		return p.code()
	}
	return nil, fmt.Errorf("marshal type %q at byte %d", t, p.pos-1)
}

func (p *pycDec) seq(n int64) ([]any, error) {
	// every element costs at least one type byte, so a count past the rest of
	// the buffer is a truncated write, not an allocation to honour
	if n < 0 || n > int64(len(p.b)-p.pos) {
		return nil, p.short()
	}
	out := make([]any, 0, n)
	for range n {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// dict ends with a bare TYPE_NULL ('0'), which is not a value of its own.
func (p *pycDec) dict() ([]any, error) {
	var out []any
	for {
		code, err := p.u8()
		if err != nil {
			return nil, err
		}
		if code&^0x80 == '0' {
			return out, nil
		}
		k, err := p.typed(code)
		if err != nil {
			return nil, err
		}
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, k, v)
	}
}

// code reads one code object in the field order of its own version. 3.6/3.7:
// argcount,kwonlyargcount,nlocals,stacksize,flags. 3.8-3.10 add posonlyargcount.
// 3.11+ drop nlocals and swap varnames/freevars/cellvars for
// localsplusnames+localspluskinds, and add qualname and exceptiontable.
func (p *pycDec) code() (any, error) {
	ints := 5
	if p.ver >= 308 && p.ver <= 310 {
		ints = 6
	}
	if _, err := p.take(4 * ints); err != nil {
		return nil, err
	}
	vals, err := p.values(3) // co_code, co_consts, co_names
	if err != nil {
		return nil, err
	}
	vars := 3 // varnames, freevars, cellvars
	if p.ver >= 311 {
		vars = 2 // localsplusnames, localspluskinds
	}
	if _, err := p.values(vars); err != nil {
		return nil, err
	}
	head, err := p.values(2) // co_filename, co_name
	if err != nil {
		return nil, err
	}
	if p.ver >= 311 {
		q, err := p.value() // co_qualname
		if err != nil {
			return nil, err
		}
		head = append(head, q)
	}
	if _, err := p.take(4); err != nil { // co_firstlineno
		return nil, err
	}
	tail := 1 // co_linetable
	if p.ver >= 311 {
		tail = 2 // + co_exceptiontable
	}
	if _, err := p.values(tail); err != nil {
		return nil, err
	}
	c := &pyCode{file: pycText(head[0]), name: pycText(head[1])}
	if p.ver >= 311 {
		c.qualname = pycText(head[2])
	}
	if l, ok := vals[1].([]any); ok {
		c.consts = l
	}
	return c, nil
}

func (p *pycDec) values(n int) ([]any, error) {
	out := make([]any, 0, n)
	for range n {
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

func pycText(v any) string {
	s, _ := v.(string)
	return s
}
