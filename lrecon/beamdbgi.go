package main

// Erlang debug-info recovery. beam.go stops at the atom table, so a shipped
// .beam names its imports but not its own functions. The Dbgi chunk carries the
// compiler's abstract format: an External Term Format term holding
// {debug_info_v1, erl_abstract_code, {Forms, Opts}}, where every
// {function, Anno, Name, Arity, Clauses} form is one function the module
// defines. Reading that term recovers the module's own function/arity list and
// the source line of each, which is the part a reverse engineer needs first.
//
// The reader is a post pass: beam.go already claimed the file and counted the
// chunk as unknown. Nothing here changes Kind, and a file without a Dbgi/Abst
// chunk is left alone (release builds ship stripped) so the existing beam
// coverage stays the one answer for that file.

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const (
	// A Dbgi chunk is zlib-compressed ETF; 8 MiB of compressed bytes is far
	// beyond any hand-written module and still bounds a hostile declared size.
	beamDbgiMax = 8 << 20
	etfMaxDepth = 64
)

var beamDbgiReasons = []string{
	"beamdbgi-absent",
	"beamdbgi-etf-unsupported",
	"beamdbgi-zlib-failed",
}

func init() {
	reasonRegistry["beamdbgi"] = reasonSet(beamDbgiReasons...)
	register(reader{
		format:  "beamdbgi",
		reasons: beamDbgiReasons,
		match:   beamMatch,
		inspect: inspectBeamDbgi,
		post:    true,
	})
}

// inspectBeamDbgi re-walks the IFF table because beam.go keeps its chunk walk
// private. It stops at the first Dbgi or Abst chunk: both are written by the
// compiler and carry the same abstract forms, and a file with two would be
// hand-edited rather than compiled.
func inspectBeamDbgi(path string, d *Digest) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return
	}
	size := st.Size()
	if size < beamHeaderLen {
		return
	}
	var hdr [beamHeaderLen]byte
	if !beamReadAt(f, hdr[:], 0, d) || string(hdr[:4]) != "FOR1" || string(hdr[8:12]) != "BEAM" {
		return
	}

	var (
		payload []byte
		found   bool
	)
	for off := int64(beamHeaderLen); off < size; {
		if size-off < beamChunkLen {
			break
		}
		var ch [beamChunkLen]byte
		if !beamReadAt(f, ch[:], off, d) {
			break
		}
		id := string(ch[:4])
		n := int64(binary.BigEndian.Uint32(ch[4:8]))
		data := off + beamChunkLen
		if n > size-data {
			break
		}
		if id == "Dbgi" || id == "Abst" {
			found = true
			if n > 0 {
				// Read the chunk, never trust its length as an allocation: a
				// bounded SectionReader keeps a lying size from reserving RAM.
				sec := io.NewSectionReader(f, data, n)
				raw, _ := io.ReadAll(io.LimitReader(sec, beamDbgiMax+1))
				d.scanned(int64(len(raw)))
				if len(raw) > beamDbgiMax {
					d.skip("beamdbgi-etf-unsupported", fmt.Sprintf("%s chunk exceeds %d bytes", id, beamDbgiMax))
					return
				}
				payload = raw
			}
			break
		}
		next := data + n
		if pad := next % 4; pad != 0 {
			next += 4 - pad
		}
		if next > size {
			break
		}
		off = next
	}
	if !found {
		// The beam reader already counted this chunk as unknown. A skip here
		// would make every stripped release build look refused, so absence is
		// silent unless the chunk itself is present but empty.
		return
	}
	if len(payload) == 0 {
		d.skip("beamdbgi-absent", "Dbgi/Abst chunk carries no bytes")
		return
	}

	body, reason, detail := beamDbgiTerm(payload)
	if reason != "" {
		d.skip(reason, detail)
		return
	}
	term, _, err := etfTerm(body, 0, 0)
	if err != nil {
		d.skip("beamdbgi-etf-unsupported", err.Error())
		return
	}
	mod := d.Mod
	forms := &beamAst{}
	beamAstWalk(term, mod, forms, 0)
	if len(forms.items) == 0 {
		d.skip("beamdbgi-etf-unsupported", "term carries no {function,...} forms")
		return
	}
	d.parsed()
	cappedDeepNotes(d, "beam-ast ", forms.items)
}

// beamDbgiTerm unwraps the three shapes a debug-info chunk has taken:
//
//	131 + term                          plain term_to_binary (Abst, pre-OTP 20)
//	80 + u32 dest_len + zlib(term)      term_to_binary(...,[compressed]) (OTP 20+)
//	u32 original_len + zlib(term)       legacy size-prefixed container
//
// The compressed ETF tag is the one modern shape; the size prefix is accepted
// because older producers and rewriters emitted it, and refusing a payload we
// can decode is worse than accepting an extra container.
func beamDbgiTerm(raw []byte) ([]byte, string, string) {
	var body []byte
	switch {
	case len(raw) > 0 && raw[0] == 131:
		body = raw[1:]
	case len(raw) >= 5 && raw[0] == 80:
		// dest_len at [1:5] is a witness: a zlib stream ends itself, and a
		// wrong witness must not hide the terms behind it.
		out, err := beamInflate(raw[5:])
		if err != nil {
			return nil, "beamdbgi-zlib-failed", "compressed ETF: " + err.Error()
		}
		body = out
	case len(raw) >= 5 && raw[4] == 0x78:
		out, err := beamInflate(raw[4:])
		if err != nil {
			return nil, "beamdbgi-zlib-failed", "size-prefixed chunk: " + err.Error()
		}
		body = out
	case len(raw) > 0 && raw[0] == 0x78:
		out, err := beamInflate(raw)
		if err != nil {
			return nil, "beamdbgi-zlib-failed", "raw zlib chunk: " + err.Error()
		}
		body = out
	default:
		return nil, "beamdbgi-etf-unsupported", fmt.Sprintf("payload starts %#02x, not a term/zlib", raw[0])
	}
	// The compressed-tag stream omits the version byte, the legacy one keeps
	// it; accept both rather than keying the parser on the container.
	if len(body) > 0 && body[0] == 131 {
		body = body[1:]
	}
	if len(body) == 0 {
		return nil, "beamdbgi-absent", "debug-info payload decompressed to nothing"
	}
	// Encrypted debug info: <<0:8, N:8, Mode:N/binary, Rest/binary>>. The term
	// after the mode is ciphertext, so there is nothing honest to recover.
	if body[0] == 0 && len(body) >= 2 {
		n := int(body[1])
		if n > 0 && 2+n <= len(body) && beamPrintable(string(body[2:2+n])) {
			return nil, "beamdbgi-etf-unsupported", "encrypted debug info, mode " + string(body[2:2+n])
		}
	}
	return body, "", ""
}

func beamInflate(b []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, beamDbgiMax+1))
	if err != nil {
		return nil, err
	}
	if len(out) > beamDbgiMax {
		return nil, fmt.Errorf("inflated term exceeds %d bytes", beamDbgiMax)
	}
	return out, nil
}

// beamTerm is the subset of an ETF value this reader walks. Numbers collapse
// into n (arity and source line are small), atoms and strings into text,
// containers into elems. Anything outside that shape is refused by the decoder
// rather than coerced into a plausible value.
type beamTerm struct {
	tag   byte
	text  string
	n     int64
	elems []beamTerm
}

func (t beamTerm) atom(s string) bool {
	switch t.tag {
	case 100, 115, 118, 119: // ATOM_EXT, SMALL_ATOM_EXT, *_UTF8_EXT
		return t.text == s
	}
	return false
}

// etfTerm decodes one External Term Format term without the 131 version byte.
// The tag list is deliberately closed: an unknown tag is a refusal, because a
// guessed tag could turn a big integer into an arity.
func etfTerm(b []byte, off, depth int) (beamTerm, int, error) {
	if depth > etfMaxDepth {
		return beamTerm{}, off, fmt.Errorf("term nesting exceeds %d", etfMaxDepth)
	}
	if off >= len(b) {
		return beamTerm{}, off, fmt.Errorf("truncated at byte %d", off)
	}
	tag := b[off]
	off++
	take := func(n int) ([]byte, error) {
		if n < 0 || off+n > len(b) {
			return nil, fmt.Errorf("tag %d claims %d bytes at %d, %d left", tag, n, off, len(b)-off)
		}
		v := b[off : off+n]
		off += n
		return v, nil
	}
	u8 := func() (int, error) {
		v, err := take(1)
		if err != nil {
			return 0, err
		}
		return int(v[0]), nil
	}
	u16 := func() (int, error) {
		v, err := take(2)
		if err != nil {
			return 0, err
		}
		return int(binary.BigEndian.Uint16(v)), nil
	}
	u32 := func() (int, error) {
		v, err := take(4)
		if err != nil {
			return 0, err
		}
		n := binary.BigEndian.Uint32(v)
		if uint64(n) > uint64(len(b)) {
			return 0, fmt.Errorf("tag %d length %d over %d-byte term", tag, n, len(b))
		}
		return int(n), nil
	}

	switch tag {
	case 97: // SMALL_INTEGER_EXT
		v, err := u8()
		return beamTerm{tag: tag, n: int64(v)}, off, err
	case 98: // INTEGER_EXT
		v, err := take(4)
		if err != nil {
			return beamTerm{}, off, err
		}
		return beamTerm{tag: tag, n: int64(int32(binary.BigEndian.Uint32(v)))}, off, nil
	case 99: // FLOAT_EXT: 31 bytes of ASCII
		_, err := take(31)
		return beamTerm{tag: tag}, off, err
	case 70: // NEW_FLOAT_EXT
		_, err := take(8)
		return beamTerm{tag: tag}, off, err
	case 100, 118: // ATOM_EXT (latin-1), ATOM_UTF8_EXT (already UTF-8)
		n, err := u16()
		if err != nil {
			return beamTerm{}, off, err
		}
		v, err := take(n)
		if err != nil {
			return beamTerm{}, off, err
		}
		if tag == 100 {
			return beamTerm{tag: tag, text: beamLatin1(v)}, off, nil
		}
		return beamTerm{tag: tag, text: string(v)}, off, nil
	case 115, 119: // SMALL_ATOM_EXT (latin-1), SMALL_ATOM_UTF8_EXT (already UTF-8)
		n, err := u8()
		if err != nil {
			return beamTerm{}, off, err
		}
		v, err := take(n)
		if err != nil {
			return beamTerm{}, off, err
		}
		if tag == 115 {
			return beamTerm{tag: tag, text: beamLatin1(v)}, off, nil
		}
		return beamTerm{tag: tag, text: string(v)}, off, nil
	case 104, 105: // SMALL_TUPLE_EXT, LARGE_TUPLE_EXT
		var n int
		var err error
		if tag == 104 {
			n, err = u8()
		} else {
			n, err = u32()
		}
		if err != nil {
			return beamTerm{}, off, err
		}
		elems := make([]beamTerm, 0, min(n, 64))
		for i := 0; i < n; i++ {
			var e beamTerm
			e, off, err = etfTerm(b, off, depth+1)
			if err != nil {
				return beamTerm{}, off, err
			}
			elems = append(elems, e)
		}
		return beamTerm{tag: tag, elems: elems}, off, nil
	case 106: // NIL_EXT
		return beamTerm{tag: tag}, off, nil
	case 107: // STRING_EXT
		n, err := u16()
		if err != nil {
			return beamTerm{}, off, err
		}
		v, err := take(n)
		if err != nil {
			return beamTerm{}, off, err
		}
		return beamTerm{tag: tag, text: beamLatin1(v)}, off, nil
	case 108: // LIST_EXT
		n, err := u32()
		if err != nil {
			return beamTerm{}, off, err
		}
		elems := make([]beamTerm, 0, min(n, 64))
		for range n {
			var e beamTerm
			e, off, err = etfTerm(b, off, depth+1)
			if err != nil {
				return beamTerm{}, off, err
			}
			elems = append(elems, e)
		}
		tail, next, err := etfTerm(b, off, depth+1)
		if err != nil {
			return beamTerm{}, next, err
		}
		off = next
		if tail.tag != 106 {
			elems = append(elems, tail)
		}
		return beamTerm{tag: tag, elems: elems}, off, nil
	case 109: // BINARY_EXT
		n, err := u32()
		if err != nil {
			return beamTerm{}, off, err
		}
		v, err := take(n)
		if err != nil {
			return beamTerm{}, off, err
		}
		return beamTerm{tag: tag, text: string(v)}, off, nil
	case 110, 111: // SMALL_BIG_EXT, LARGE_BIG_EXT
		var n int
		var err error
		if tag == 110 {
			n, err = u8()
		} else {
			n, err = u32()
		}
		if err != nil {
			return beamTerm{}, off, err
		}
		v, err := take(n + 1) // sign byte + little-endian magnitude
		if err != nil {
			return beamTerm{}, off, err
		}
		var val int64
		for i := min(n, 8) - 1; i >= 0; i-- {
			val = val<<8 | int64(v[1+i])
		}
		if v[0] != 0 {
			val = -val
		}
		return beamTerm{tag: tag, n: val}, off, nil
	case 116: // MAP_EXT
		n, err := u32()
		if err != nil {
			return beamTerm{}, off, err
		}
		if n > (len(b)-off)/2 {
			return beamTerm{}, off, fmt.Errorf("map of %d pairs over %d bytes", n, len(b)-off)
		}
		elems := make([]beamTerm, 0, min(n*2, 64))
		for i := 0; i < n*2; i++ {
			var e beamTerm
			e, off, err = etfTerm(b, off, depth+1)
			if err != nil {
				return beamTerm{}, off, err
			}
			elems = append(elems, e)
		}
		return beamTerm{tag: tag, elems: elems}, off, nil
	case 77: // BIT_BINARY_EXT
		n, err := u32()
		if err != nil {
			return beamTerm{}, off, err
		}
		_, err = take(n + 1)
		return beamTerm{tag: tag}, off, err
	case 131: // version byte seen mid-stream: skip it
		return etfTerm(b, off, depth)
	}
	return beamTerm{}, off, fmt.Errorf("unsupported ETF tag %d at %d", tag, off-1)
}

// beamAst accumulates the function forms and keeps the note list bounded. The
// cap is on what is printed, not on what is walked: the "+N more" line has to
// report the real count.
type beamAst struct {
	items []string
	total int
}

func beamAstWalk(t beamTerm, mod string, out *beamAst, depth int) {
	if depth > etfMaxDepth {
		return
	}
	if len(t.elems) >= 4 && t.elems[0].atom("function") {
		name := t.elems[2]
		arity := t.elems[3]
		if (name.tag == 100 || name.tag == 115 || name.tag == 118 || name.tag == 119) &&
			beamPrintable(name.text) && (arity.tag == 97 || arity.tag == 98) && arity.n >= 0 {
			line := beamAstLine(t.elems[1], 0)
			s := name.text + "/" + fmt.Sprint(arity.n)
			if mod != "" {
				s = mod + ":" + s
			}
			if line > 0 {
				s += fmt.Sprintf(" @%d", line)
			}
			out.total++
			if len(out.items) < 4096 {
				out.items = append(out.items, s)
			}
		}
	}
	for _, e := range t.elems {
		beamAstWalk(e, mod, out, depth+1)
	}
}

// beamAstLine reads the annotation of a form. Modern compilers write
// {Line, Column}; older ones wrote the bare line integer, and a missing line is
// 0 rather than a claim.
func beamAstLine(t beamTerm, depth int) int64 {
	if depth > 8 {
		return 0
	}
	if t.tag == 97 || t.tag == 98 {
		if t.n > 0 {
			return t.n
		}
		return 0
	}
	if len(t.elems) > 0 {
		return beamAstLine(t.elems[0], depth+1)
	}
	return 0
}

// beamLatin1 widens the latin-1 encoding of ATOM_EXT/STRING_EXT. UTF-8 tags
// pass through untouched; the caller validates printability before using them.
func beamLatin1(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < utf8.RuneSelf {
			sb.WriteByte(c)
		} else {
			sb.WriteRune(rune(c))
		}
	}
	return sb.String()
}
