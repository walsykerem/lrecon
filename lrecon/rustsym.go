package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Rust symbol demangler and glue classifier. mangling.go labels the family;
// this reader is the one that decodes a name back to its source spelling, so a
// reader can tell a user function from compiler-generated drop glue.
//
// Two families, two parsers:
//
//	legacy  _ZN<len><elem>...17h<hash>E   rustc-demangle:src/legacy.rs:49
//	v0      _R<path>                      rustc-demangle:src/v0.rs:37
//
// The subset is deliberate and refused, never guessed: legacy is complete
// (elements, `$` escapes, stripped hash), v0 covers the path/ident/type/generic
// forms a stripped binary actually carries. v0 punycode idents (Unicode crate
// or module names), dyn trait objects, fn pointers and const expressions outside
// integer/char/bool literals return "unknown" and land in rust-demangle-unverified
// instead of printing a half-decoded name.
const (
	rustSymSampleMax = 3   // demangled names printed in notes
	rustSymDepthMax  = 128 // v0 recursion bound; rustc-demangle uses 500
	rustSymNoteCap   = 120 // one sample cannot crowd the text budget
)

func init() {
	register(reader{
		format: "rustsym",
		reasons: []string{
			"rust-demangle-unverified",
			"rust-drop-glue",
			"rust-panic-unwind",
		},
		post:    true,
		inspect: inspectRustSym,
	})
}

func init() {
	reasonRegistry["rustsym"] = reasonSet(
		"rust-demangle-unverified",
		"rust-drop-glue",
		"rust-panic-unwind",
	)
}

// inspectRustSym runs after the magic switch and never changes the host kind.
// It reuses manglingNames rather than opening a second symbol-table parser: the
// same names must produce the same family and the same count in both readers.
func inspectRustSym(path string, d *Digest) {
	switch d.Kind {
	case "macho", "elf", "pe":
	default:
		return
	}
	names, truncated, total, err := manglingNames(path, d)
	if err != nil && len(names) == 0 {
		// mangling.go already refused this table; a second refusal is noise.
		return
	}
	st := rustSymScan(names)
	if st.total == 0 {
		return // no Rust-shaped name is no evidence, not an empty result
	}
	if truncated {
		d.Notes = append(d.Notes, fmt.Sprintf("rustsym: demangled the first %d of %d symbol names", len(names), total))
	}
	d.Capabilities = append(d.Capabilities, fmt.Sprintf("rustsym:names=%d", st.total))
	if st.glue > 0 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("rustsym:drop-glue=%d", st.glue))
	}
	if st.panic > 0 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("rustsym:panic=%d", st.panic))
	}
	if st.closure > 0 {
		d.Capabilities = append(d.Capabilities, fmt.Sprintf("rustsym:closure=%d", st.closure))
	}
	d.Notes = append(d.Notes, fmt.Sprintf(
		"rustsym: %d symbols (legacy %d, v0 %d), drop-glue %d, panic %d, closure %d",
		st.total, st.legacy, st.v0, st.glue, st.panic, st.closure))
	for i, s := range st.crates {
		if i >= maxRustCrates {
			break
		}
		d.RustCrates = appendUnique(d.RustCrates, s)
	}
	if st.mainCrate != "" && (d.Mod == "" || d.Mod == rustModUnknown) {
		d.Mod = st.mainCrate
	}
	for _, s := range st.samples {
		d.Notes = append(d.Notes, "rustsym: "+rustClip(s, rustSymNoteCap))
	}
	// A table that only holds compiler glue still proves Rust, but it names no
	// user function: the counts make that refusal visible instead of silent.
	if st.glue == st.total {
		d.skip("rust-drop-glue", fmt.Sprintf("%d of %d names are drop glue or vtable shims, no user function named", st.glue, st.total))
	} else if st.panic == st.total {
		d.skip("rust-panic-unwind", fmt.Sprintf("%d of %d names are panic/unwind runtime, no user function named", st.panic, st.total))
	}
	if st.refused > 0 {
		d.skip("rust-demangle-unverified", fmt.Sprintf("%d of %d rust-shaped names outside the ported subset", st.refused, st.total))
	}
}

// rustSymStats is what one symbol table said. Counts are separate so a caller
// can refuse on "only glue" without re-reading the names.
type rustSymStats struct {
	total, legacy, v0             int
	refused, glue, panic, closure int
	crates                        []string
	mainCrate                     string
	samples                       []string
}

// rustSymScan demangles every Rust-shaped name once. A name is Rust-shaped only
// when manglingFamily says so: `_ZN...E` without the hash suffix and a bare
// `_R` prefix are C++/noise, not a demangler failure.
func rustSymScan(names []string) rustSymStats {
	var st rustSymStats
	for _, name := range names {
		name = manglingLLVMRe.ReplaceAllString(strings.TrimSpace(name), "")
		fam, _ := manglingFamily(name)
		if fam != "rust-legacy" && fam != "rust-v0" {
			continue
		}
		st.total++
		var demangled string
		var ok bool
		if fam == "rust-legacy" {
			st.legacy++
			demangled, ok = rustLegacyDemangle(name)
		} else {
			st.v0++
			demangled, ok = rustV0Demangle(name)
		}
		if !ok {
			st.refused++
			continue
		}
		if rustSymGlue(demangled) {
			st.glue++
			continue
		}
		if rustSymPanic(demangled) {
			st.panic++
			continue
		}
		if rustSymClosure(demangled) {
			st.closure++
			continue // compiler glue, not a user function to sample
		}
		if root := rustSymCrate(demangled); root != "" {
			if len(st.crates) < maxRustCrates {
				st.crates = appendUnique(st.crates, root)
			}
			if st.mainCrate == "" && rustSymIsMain(demangled) {
				st.mainCrate = root
			}
		}
		if len(st.samples) < rustSymSampleMax {
			st.samples = appendUnique(st.samples, demangled)
		}
	}
	return st
}

// rustSymGlue names compiler-generated teardown: drop glue, vtable shims and
// the legacy `{{vtable.shim}}` spelling (rustc-demangle prints the doubled
// braces the symbol itself carries).
func rustSymGlue(s string) bool {
	return strings.Contains(s, "drop_in_place") ||
		strings.Contains(s, "{{vtable.shim}}") ||
		strings.Contains(s, "{{drop}}") ||
		strings.Contains(s, "drop_glue")
}

func rustSymPanic(s string) bool {
	// A path merely containing "panic" is a user function (`panic_handler`);
	// only the runtime's own names mean the unwind machinery was linked.
	for _, marker := range []string{
		"::panicking::", "panic_unwind", "panic_abort", "rust_panic",
		"begin_unwind", "::unwind::", "panic_fmt", "panic_nounwind",
		"panic_cannot_unwind", "panic_in_cleanup",
	} {
		if strings.Contains(s, marker) {
			return true
		}
	}
	return false
}

func rustSymClosure(s string) bool {
	return strings.Contains(s, "{{closure}}") || strings.Contains(s, "{closure")
}

// rustSymIsMain names the function the linker keeps as the program entry. A
// module called `main` inside a library is not this: only a path whose final
// segment is exactly `main` counts.
func rustSymIsMain(s string) bool {
	return strings.HasSuffix(s, "::main")
}

// rustSymCrate keeps the leading path segment when it is a crate of the target,
// not one every Rust binary links: sysroot crates say nothing about the product.
func rustSymCrate(s string) string {
	if s == "" || s[0] == '<' || s[0] == '(' {
		return ""
	}
	root := s
	if i := strings.Index(root, "::"); i > 0 {
		root = root[:i]
	}
	if i := strings.IndexAny(root, "[(<"); i > 0 {
		root = root[:i]
	}
	switch root {
	case "", "std", "core", "alloc", "compiler_builtins", "panic_unwind", "panic_abort", "unwind", "proc_macro", "test", "__rustc", "___rustc":
		return ""
	}
	return root
}

// appendUnique keeps first-seen order, which keeps notes deterministic.
func appendUnique(list []string, s string) []string {
	if slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

// testSafeClip cuts a note to one line's worth of bytes. Text() sanitizes
// control bytes later; this only bounds the field.
func rustClip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..." // the ellipsis counts toward the note budget
}

// --- legacy ---

// rustLegacyDemangle ports rustc-demangle legacy.rs:49. Accept the three
// prefixes rustc itself accepts (`__ZN` on Mach-O, `ZN` where dbghelp stripped
// the underscore); the trailing `.llvm.<n>` is removed by the caller.
func rustLegacyDemangle(s string) (string, bool) {
	switch {
	case strings.HasPrefix(s, "__ZN"):
		s = s[4:]
	case strings.HasPrefix(s, "_ZN"):
		s = s[3:]
	case strings.HasPrefix(s, "ZN"):
		s = s[2:]
	default:
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i]&0x80 != 0 {
			return "", false
		}
	}
	var elems []string
	i := 0
	for {
		if i >= len(s) {
			return "", false
		}
		if s[i] == 'E' {
			i++
			break
		}
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return "", false
		}
		n, err := strconv.Atoi(s[start:i])
		if err != nil || n < 0 || i+n > len(s) {
			return "", false
		}
		elems = append(elems, s[i:i+n])
		i += n
	}
	// rustc-demangle tolerates a suffix (it returns it to the caller). A symbol
	// table entry with trailing junk is not a name we can vouch for.
	if i != len(s) {
		return "", false
	}
	if n := len(elems); n > 0 && rustLegacyHash(elems[n-1]) {
		elems = elems[:n-1]
	}
	if len(elems) == 0 {
		return "", false
	}
	out := make([]string, len(elems))
	for j, e := range elems {
		out[j] = rustLegacyElement(e)
	}
	return strings.Join(out, "::"), true
}

// rustLegacyHash is legacy.rs:100: an `h` followed only by hex digits.
func rustLegacyHash(s string) bool {
	if len(s) < 2 || s[0] != 'h' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// rustLegacyElement ports the legacy.rs:71-97 escape loop. `..` becomes `::`,
// a single dot stays a dot, and `$SP$`..`$RP$` plus `$uXX$` are the escapes the
// compiler emits. An unknown `$...$` is printed literally, exactly like rustc.
func rustLegacyElement(e string) string {
	if strings.HasPrefix(e, "_$") {
		e = e[1:] // `_$self` means the keyword collided with the separator
	}
	var b strings.Builder
	for e != "" {
		switch {
		case strings.HasPrefix(e, ".."):
			b.WriteString("::")
			e = e[2:]
		case e[0] == '.':
			b.WriteByte('.')
			e = e[1:]
		case e[0] == '$':
			end := strings.IndexByte(e[1:], '$')
			if end < 0 {
				b.WriteString(e)
				return b.String()
			}
			esc, after := e[1:1+end], e[1+end+1:]
			switch esc {
			case "SP":
				b.WriteByte('@')
			case "BP":
				b.WriteByte('*')
			case "RF":
				b.WriteByte('&')
			case "LT":
				b.WriteByte('<')
			case "GT":
				b.WriteByte('>')
			case "LP":
				b.WriteByte('(')
			case "RP":
				b.WriteByte(')')
			case "C":
				b.WriteByte(',')
			default:
				if r, ok := rustLegacyUnicode(esc); ok {
					b.WriteRune(r)
				} else {
					b.WriteString(e[:1+end+1])
				}
			}
			e = after
		default:
			i := strings.IndexAny(e, "$.")
			if i < 0 {
				b.WriteString(e)
				return b.String()
			}
			b.WriteString(e[:i])
			e = e[i:]
		}
	}
	return b.String()
}

// rustLegacyUnicode decodes `$u<lower-hex>$`; control code points are refused,
// like rustc-demangle, so a name cannot inject a terminal escape.
func rustLegacyUnicode(esc string) (rune, bool) {
	if len(esc) < 2 || esc[0] != 'u' {
		return 0, false
	}
	for i := 1; i < len(esc); i++ {
		c := esc[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(esc[1:], 16, 32)
	if err != nil || v > 0x10ffff || v >= 0xd800 && v <= 0xdfff {
		return 0, false
	}
	r := rune(v)
	if unicode.IsControl(r) {
		return 0, false
	}
	return r, true
}

// --- v0 ---

// rustV0Demangle ports the common subset of rustc-demangle v0.rs:37: one path,
// an optional instantiating-crate path that must also parse but is not printed,
// and nothing after it. The version byte some old symbols carried is not in
// rustc-demangle's parser either, so it is refused here too.
func rustV0Demangle(s string) (string, bool) {
	switch {
	case strings.HasPrefix(s, "__R"):
		s = s[3:]
	case strings.HasPrefix(s, "_R"):
		s = s[2:]
	case strings.HasPrefix(s, "R"):
		s = s[1:]
	default:
		return "", false
	}
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i]&0x80 != 0 {
			return "", false
		}
	}
	p := &rustV0{sym: s}
	// The top-level path is a value, so instantiation generic args on it print
	// as `::<...>`; the instantiating crate path below is parsed but not shown.
	out, ok := p.path(true)
	if !ok {
		return "", false
	}
	if p.next < len(s) && s[p.next] >= 'A' && s[p.next] <= 'Z' {
		if _, ok := p.path(false); !ok {
			return "", false
		}
	}
	if p.next != len(s) {
		return "", false
	}
	return out, true
}

type rustV0 struct {
	sym   string
	next  int
	depth int
}

func (p *rustV0) peek() (byte, bool) {
	if p.next >= len(p.sym) {
		return 0, false
	}
	return p.sym[p.next], true
}

func (p *rustV0) eat(b byte) bool {
	if c, ok := p.peek(); ok && c == b {
		p.next++
		return true
	}
	return false
}

func (p *rustV0) byte() (byte, bool) {
	c, ok := p.peek()
	if !ok {
		return 0, false
	}
	p.next++
	return c, true
}

func (p *rustV0) enter() bool {
	p.depth++
	return p.depth <= rustSymDepthMax
}

func (p *rustV0) leave() { p.depth-- }

func (p *rustV0) digit62() (uint64, bool) {
	c, ok := p.peek()
	if !ok {
		return 0, false
	}
	switch {
	case c >= '0' && c <= '9':
		p.next++
		return uint64(c - '0'), true
	case c >= 'a' && c <= 'z':
		p.next++
		return uint64(10 + c - 'a'), true
	case c >= 'A' && c <= 'Z':
		p.next++
		return uint64(10 + 26 + c - 'A'), true
	}
	return 0, false
}

// integer62 is v0.rs:471: `_` is zero, otherwise base-62 digits up to `_` plus
// one. The plus one keeps zero available for "absent disambiguator".
func (p *rustV0) integer62() (uint64, bool) {
	if p.eat('_') {
		return 0, true
	}
	var x uint64
	for !p.eat('_') {
		d, ok := p.digit62()
		if !ok {
			return 0, false
		}
		if x > (1<<64-1)/62 {
			return 0, false
		}
		x *= 62
		if x > 1<<64-1-d {
			return 0, false
		}
		x += d
	}
	if x == 1<<64-1 {
		return 0, false
	}
	return x + 1, true
}

func (p *rustV0) optInteger62(tag byte) (uint64, bool) {
	if !p.eat(tag) {
		return 0, true
	}
	v, ok := p.integer62()
	if !ok || v == 1<<64-1 {
		return 0, false
	}
	return v + 1, true
}

// ident is v0.rs:523 without the punycode arm. A `u` prefix means a Unicode
// insertion code, which this subset refuses rather than printing the raw ASCII
// half of a name that would be wrong.
func (p *rustV0) ident() (string, bool) {
	if p.eat('u') {
		return "", false
	}
	start := p.next
	for {
		c, ok := p.peek()
		if !ok || c < '0' || c > '9' {
			break
		}
		p.next++
	}
	if p.next == start {
		return "", false
	}
	n, err := strconv.Atoi(p.sym[start:p.next])
	if err != nil || n < 0 {
		return "", false
	}
	p.eat('_') // optional separator
	if n > len(p.sym)-p.next {
		return "", false
	}
	s := p.sym[p.next : p.next+n]
	p.next += n
	return s, true
}

// backref is v0.rs:508: the target must start before the `B` itself, which is
// what makes the grammar finite. The main cursor stays after the offset.
func (p *rustV0) backref(f func(*rustV0) (string, bool)) (string, bool) {
	at := p.next - 1
	i, ok := p.integer62()
	if !ok || i >= uint64(at) {
		return "", false
	}
	q := &rustV0{sym: p.sym, next: int(i), depth: p.depth}
	if !q.enter() {
		return "", false
	}
	defer q.leave()
	return f(q)
}

// path is v0.rs:795 subset: C, N, I, B and the M/X/Y impl wrappers. Anything
// else is unknown, never a partial print.
func (p *rustV0) path(inValue bool) (string, bool) {
	if !p.enter() {
		return "", false
	}
	defer p.leave()
	tag, ok := p.byte()
	if !ok {
		return "", false
	}
	switch tag {
	case 'C':
		// The disambiguator is crate identity, not a source path element; the
		// alternate spelling omits it and so does this reader.
		if _, ok := p.optInteger62('s'); !ok {
			return "", false
		}
		return p.ident()
	case 'N':
		ns, ok := p.byte()
		if !ok {
			return "", false
		}
		inner, ok := p.path(inValue)
		if !ok {
			return "", false
		}
		// v0.rs:825 reads the disambiguator only for the uppercase namespaces
		// that print a closure/shim suffix; a lowercase ns owns no
		// disambiguator, so its ident starts immediately.
		upper := ns >= 'A' && ns <= 'Z'
		var dis uint64
		if upper {
			if dis, ok = p.optInteger62('s'); !ok {
				return "", false
			}
		}
		name, ok := p.ident()
		if !ok {
			return "", false
		}
		if upper {
			kind := string(ns)
			switch ns {
			case 'C':
				kind = "closure"
			case 'S':
				kind = "shim"
			}
			inner += "::{" + kind
			if name != "" {
				inner += ":" + name
			}
			return inner + "#" + strconv.FormatUint(dis, 10) + "}", true
		}
		if name != "" {
			inner += "::" + name
		}
		return inner, true
	case 'I':
		inner, ok := p.path(inValue)
		if !ok {
			return "", false
		}
		if inValue {
			inner += "::"
		}
		inner += "<"
		for first := true; ; first = false {
			if p.eat('E') {
				break
			}
			arg, ok := p.genericArg()
			if !ok {
				return "", false
			}
			if !first {
				inner += ", "
			}
			inner += arg
		}
		return inner + ">", true
	case 'B':
		return p.backref(func(q *rustV0) (string, bool) { return q.path(inValue) })
	case 'M', 'X', 'Y':
		if tag != 'Y' {
			if _, ok := p.optInteger62('s'); !ok {
				return "", false
			}
			if _, ok := p.path(false); !ok { // impl's own path is not printed
				return "", false
			}
		}
		ty, ok := p.typ()
		if !ok {
			return "", false
		}
		out := "<" + ty
		if tag != 'M' {
			as, ok := p.path(false)
			if !ok {
				return "", false
			}
			out += " as " + as
		}
		return out + ">", true
	}
	return "", false
}

// genericArg is v0.rs:891. A nonzero lifetime index needs the binder stack a
// generic argument does not carry here, so it is refused instead of invented.
func (p *rustV0) genericArg() (string, bool) {
	if p.eat('L') {
		lt, ok := p.integer62()
		if !ok || lt != 0 {
			return "", false
		}
		return "'_", true
	}
	if p.eat('K') {
		return p.constVal()
	}
	return p.typ()
}

var rustV0BasicTypes = map[byte]string{
	'b': "bool", 'c': "char", 'e': "str", 'u': "()",
	'a': "i8", 's': "i16", 'l': "i32", 'x': "i64", 'n': "i128", 'i': "isize",
	'h': "u8", 't': "u16", 'm': "u32", 'y': "u64", 'o': "u128", 'j': "usize",
	'f': "f32", 'd': "f64", 'z': "!", 'p': "_", 'v': "...",
}

// typ is v0.rs:370 basic_type plus refs, pointers, slices/arrays, tuples,
// backrefs and a path fallthrough. dyn/fn/pattern tags are refused by omission.
func (p *rustV0) typ() (string, bool) {
	if !p.enter() {
		return "", false
	}
	defer p.leave()
	tag, ok := p.byte()
	if !ok {
		return "", false
	}
	if basic, ok := rustV0BasicTypes[tag]; ok {
		return basic, true
	}
	switch tag {
	case 'R', 'Q':
		out := "&"
		if p.eat('L') {
			lt, ok := p.integer62()
			if !ok || lt != 0 {
				return "", false
			}
			out += "'_ "
		}
		if tag == 'Q' {
			out += "mut "
		}
		inner, ok := p.typ()
		return out + inner, ok
	case 'P', 'O':
		out := "*const "
		if tag == 'O' {
			out = "*mut "
		}
		inner, ok := p.typ()
		return out + inner, ok
	case 'A', 'S':
		inner, ok := p.typ()
		if !ok {
			return "", false
		}
		out := "[" + inner
		if tag == 'A' {
			c, ok := p.constVal()
			if !ok {
				return "", false
			}
			out += "; " + c
		}
		return out + "]", true
	case 'T':
		var out strings.Builder
		out.WriteString("(")
		n := 0
		for !p.eat('E') {
			inner, ok := p.typ()
			if !ok {
				return "", false
			}
			if n > 0 {
				out.WriteString(", ")
			}
			out.WriteString(inner)
			n++
		}
		if n == 1 {
			out.WriteString(",")
		}
		return out.String() + ")", true
	case 'F':
		// in_binder: we have no closures over lifetimes to name, so a binder
		// (G) is refused instead of printing a wrong `for<...>` list.
		if p.eat('G') {
			n, ok := p.integer62()
			if !ok || n != 0 {
				return "", false
			}
		}
		out := ""
		if p.eat('U') {
			out = "unsafe "
		}
		if p.eat('K') {
			abi := "C"
			if !p.eat('C') {
				id, ok := p.ident()
				if !ok || id == "" {
					return "", false
				}
				abi = strings.ReplaceAll(id, "_", "-")
			}
			out += `extern "` + abi + `" `
		}
		out += "fn("
		for first := true; ; first = false {
			if p.eat('E') {
				break
			}
			arg, ok := p.typ()
			if !ok {
				return "", false
			}
			if !first {
				out += ", "
			}
			out += arg
		}
		out += ")"
		if !p.eat('u') { // 'u' is the omitted `() -> ()` return type
			ret, ok := p.typ()
			if !ok {
				return "", false
			}
			out += " -> " + ret
		}
		return out, true
	case 'D':
		inner, ok := p.path(false)
		if !ok {
			return "", false
		}
		if p.eat('p') { // associated type bindings need the full dyn printer
			return "", false
		}
		return "dyn " + inner, true
	case 'B':
		return p.backref(func(q *rustV0) (string, bool) { return q.typ() })
	case 'C', 'N', 'I', 'M', 'X', 'Y':
		p.next-- // a path tag; print_path owns it
		return p.path(false)
	}
	return "", false
}

// constVal is the literal subset of v0.rs:1128: placeholder, unsigned/signed
// integers and bool. Strings, chars needing escapes, array/tuple/struct
// expressions and const paths are refused.
func (p *rustV0) constVal() (string, bool) {
	tag, ok := p.byte()
	if !ok {
		return "", false
	}
	switch tag {
	case 'p':
		return "_", true
	case 'b':
		v, ok := p.hexNibbles()
		if !ok {
			return "", false
		}
		switch v {
		case 0:
			return "false", true
		case 1:
			return "true", true
		}
		return "", false
	case 'h', 't', 'm', 'y', 'o', 'j', 'a', 's', 'l', 'x', 'n', 'i':
		neg := false
		if tag != 'h' && tag != 't' && tag != 'm' && tag != 'y' && tag != 'o' && tag != 'j' {
			neg = p.eat('n')
		}
		v, ok := p.hexNibbles()
		if !ok {
			return "", false
		}
		out := strconv.FormatUint(v, 10) + rustV0BasicTypes[tag]
		if neg {
			out = "-" + out
		}
		return out, true
	}
	return "", false
}

func (p *rustV0) hexNibbles() (uint64, bool) {
	var v uint64
	n := 0
	for {
		c, ok := p.peek()
		if !ok {
			return 0, false
		}
		if c == '_' {
			p.next++
			if n == 0 {
				return 0, false
			}
			return v, true
		}
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(10 + c - 'a')
		default:
			return 0, false
		}
		if v > (1<<64-1)>>4 {
			return 0, false // wider than u64: refuse, do not wrap
		}
		v = v<<4 | d
		p.next++
		n++
	}
}
