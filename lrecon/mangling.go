package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"regexp"
	"strings"
)

// Symbol mangling family classifier. It labels the scheme that produced a symbol
// name and counts witnesses; it never decodes a name. There is no demangler and
// no disassembler here, and the inspected target is never executed: the symbol
// tables are read in-process through the standard library, or reused from the
// host reader's imports.
//
// A label is a family, not a language: two families share the `_ZN` prefix, so a
// name is attributed to the narrowest family that explains its whole shape and a
// family is only reported once it has manglingMinWitness witnesses.

const (
	manglingMinWitness = 3
	manglingMaxNames   = 200000
)

// manglingFamilies also fixes the order capabilities and notes print in.
var manglingFamilies = []string{"itanium", "msvc", "rust-legacy", "rust-v0", "swift", "objc", "go"}

func init() {
	register(reader{
		format: "mangling",
		reasons: []string{
			"mangling-no-symbols",
			"mangling-symbolic-unreadable",
			"mangling-too-many-symbols",
			"mangling-under-threshold",
		},
		inspect: inspectMangling,
		post:    true,
	})
}

// inspectMangling runs after the magic switch; the host kind is already known,
// so the reader never changes it.
func inspectMangling(path string, d *Digest) {
	switch d.Kind {
	case "macho", "elf", "pe":
	default:
		return
	}
	names, truncated, total, err := manglingNames(path, d)
	if err != nil && len(names) == 0 {
		d.Capabilities = append(d.Capabilities, "mangling:unknown")
		d.skip("mangling-symbolic-unreadable", err.Error())
		return
	}
	if err != nil {
		d.Notes = append(d.Notes, "mangling: symbol table unreadable, classified import names only")
	}
	if len(names) == 0 {
		d.Capabilities = append(d.Capabilities, "mangling:unknown")
		d.skip("mangling-no-symbols", "no symbol names in the table")
		return
	}
	if truncated {
		d.Notes = append(d.Notes, fmt.Sprintf("mangling: classified the first %d of %d symbol names", manglingMaxNames, total))
		d.skip("mangling-too-many-symbols", fmt.Sprintf("%d names, cap %d", total, manglingMaxNames))
	}
	for range names {
		d.parsed()
	}
	counts := manglingCounts(names)
	caps, note, below := manglingDecision(counts, len(names))
	if len(caps) == 0 {
		// A symbol name carrying no family prefix at all is no evidence, not an
		// empty result: say nothing, like the other post readers. A thin signal
		// is different — it is refused, and the count says why.
		seen := 0
		for _, n := range counts {
			seen += n
		}
		if seen == 0 {
			return
		}
		d.skip("mangling-under-threshold", below)
		return
	}
	d.Capabilities = append(d.Capabilities, caps...)
	d.Notes = append(d.Notes, note)
	// The names all come out of one string table, so that table is the only span
	// that can witness a family: two shapes are not two independent reads.
	nameStart, nameEnd := manglingNameSpan(path, d.Kind)
	for _, fam := range manglingFamilies {
		if counts[fam] < manglingMinWitness {
			continue
		}
		if nameEnd > nameStart {
			d.witness(Witness{Axis: "mangling", Class: "symtab", Value: fam, Start: nameStart, End: nameEnd})
		}
	}
}

// manglingNameSpan is the file range the family names were read from. Only ELF
// exposes it through the standard library; elsewhere the family stays unwitnessed
// rather than borrowing an invented offset.
func manglingNameSpan(path, kind string) (int64, int64) {
	if kind != "elf" {
		return 0, 0
	}
	f, err := elf.Open(path)
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	for _, name := range []string{".strtab", ".dynstr"} {
		if s := f.Section(name); s != nil && s.FileSize > 0 {
			return int64(s.Offset), int64(s.Offset) + int64(s.FileSize)
		}
	}
	return 0, 0
}

// manglingNames gathers candidate names: the host digest's imports first, then
// the symbol table read directly. Duplicates collapse; the cap is the work bound.
func manglingNames(path string, d *Digest) (names []string, truncated bool, total int, err error) {
	seen := make(map[string]bool, 1024)
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		total++
		if seen[s] {
			return
		}
		if len(names) >= manglingMaxNames {
			truncated = true
			return
		}
		seen[s] = true
		names = append(names, s)
	}
	// d.Imports is the only name list the native reader keeps; PE spells it
	// "symbol:DLL".
	for _, imp := range d.Imports {
		if i := strings.LastIndexByte(imp, ':'); i > 0 {
			imp = imp[:i]
		}
		add(imp)
	}
	switch d.Kind {
	case "macho":
		err = manglingMachO(path, add)
	case "elf":
		err = manglingELF(path, add)
	case "pe":
		err = manglingPE(path, add)
	}
	return names, truncated, total, err
}

func manglingMachO(path string, add func(string)) error {
	if fat, err := macho.OpenFat(path); err == nil {
		defer fat.Close()
		for _, a := range fat.Arches {
			manglingMachoFile(a.File, add)
		}
		return nil
	}
	f, err := macho.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	manglingMachoFile(f, add)
	return nil
}

func manglingMachoFile(f *macho.File, add func(string)) {
	if f.Symtab == nil {
		return
	}
	for _, s := range f.Symtab.Syms {
		add(s.Name)
	}
}

func manglingELF(path string, add func(string)) error {
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	// .dynsym survives strip -s on a dynamic binary; .symtab is the full table.
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			add(s.Name)
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			add(s.Name)
		}
	}
	return nil
}

func manglingPE(path string, add func(string)) error {
	f, err := pe.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, s := range f.Symbols {
		add(s.Name)
	}
	if imps, err := f.ImportedSymbols(); err == nil {
		for _, s := range imps {
			if i := strings.LastIndexByte(s, ':'); i > 0 {
				s = s[:i]
			}
			add(s)
		}
	}
	return nil
}

// manglingCounts attributes every name to at most one family.
func manglingCounts(names []string) map[string]int {
	counts := make(map[string]int, len(manglingFamilies))
	for _, n := range names {
		if fam, _ := manglingFamily(n); fam != "" {
			counts[fam]++
		}
	}
	return counts
}

// manglingDecision is the threshold rule, kept pure so the "two matches are not
// a finding" case is testable without a file.
func manglingDecision(counts map[string]int, total int) (caps []string, note, below string) {
	var parts []string
	for _, fam := range manglingFamilies {
		n := counts[fam]
		if n == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s=%d", fam, n))
		if n >= manglingMinWitness {
			caps = append(caps, fmt.Sprintf("mangling:%s=%d", fam, n))
		}
	}
	summary := strings.Join(parts, " ")
	if summary == "" {
		summary = "none"
	}
	if len(caps) > 0 {
		return caps, fmt.Sprintf("mangling: %s (of %d symbol names)", summary, total), ""
	}
	return nil, "", fmt.Sprintf("%s (of %d symbol names, minimum %d)", summary, total, manglingMinWitness)
}

// LTO leaves a `.llvm.<digits>` suffix on some names; it is not part of the
// mangling and the notes require stripping it before matching.
var manglingLLVMRe = regexp.MustCompile(`\.llvm\.[0-9]+$`)

// Rust legacy is the one family defined by its whole shape: the `17h<16 hex>`
// hash suffix. A bare `_ZN` is C++ (a rustc binary carries hundreds of them).
var manglingLegacyRe = regexp.MustCompile(`^_ZN.+17h[0-9a-f]{16}E$`)

var (
	// The package element is a Go package name, never a C identifier: no
	// underscore, no leading underscore, no dots. Receivers are parenthesized
	// (`runtime.(*mheap)`) or left off.
	manglingGoPathRe = regexp.MustCompile(`^(?:[A-Za-z0-9_.\-]+/)*[a-z][a-z0-9]*(?:\.\(\*?[A-Za-z_][A-Za-z0-9_]*\))?$`)
	manglingGoSymRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	manglingObjCRe   = regexp.MustCompile(`^[-+]\[[A-Za-z_][A-Za-z0-9_]*(?:\([A-Za-z_][A-Za-z0-9_]*\))? [.A-Za-z_][A-Za-z0-9_:.]*\]$`)
)

// manglingFamily returns the family and the shape that matched. Order is the
// narrowest rule first: Rust legacy outranks the Itanium prefix it shares, and a
// Mach-O leading underscore is normalized before either.
func manglingFamily(name string) (string, string) {
	// The anchored regex can only match a name that carries the literal infix,
	// so the scan is skipped for the overwhelmingly common case.
	n := name
	if strings.Contains(name, ".llvm.") {
		n = manglingLLVMRe.ReplaceAllString(name, "")
	}
	if n == "" {
		return "", ""
	}
	if strings.HasPrefix(n, "__Z") || strings.HasPrefix(n, "__R") {
		n = n[1:] // Mach-O prepends one underscore to every C symbol
	}
	// Same necessary condition as above: the legacy shape is anchored on `_ZN`.
	if strings.HasPrefix(n, "_ZN") && manglingLegacyRe.MatchString(n) {
		return "rust-legacy", "hash-suffix"
	}
	if shape := manglingV0Shape(n); shape != "" {
		return "rust-v0", shape
	}
	if shape := manglingMSVCShape(n); shape != "" {
		return "msvc", shape
	}
	if strings.HasPrefix(n, "_Z") {
		if shape := manglingItaniumShape(n[2:]); shape != "" {
			return "itanium", shape
		}
	}
	if shape := manglingGoShape(n); shape != "" {
		return "go", shape
	}
	if shape := manglingSwiftShape(n); shape != "" {
		return "swift", shape
	}
	// ObjC method syntax is anchored on the polarity character; every other
	// name skips the regex.
	if len(n) >= 4 && (n[0] == '-' || n[0] == '+') && manglingObjCRe.MatchString(n) {
		return "objc", "method"
	}
	return "", ""
}

// Itanium: `_Z` plus an encoding this parser recognizes. `_Z` alone, `_Zfoo`,
// and `_Z` with a bad tail are not evidence.
func manglingItaniumShape(rest string) string {
	if len(rest) < 2 {
		return ""
	}
	switch c := rest[0]; {
	case c == 'N':
		if manglingItaniumNested(rest[1:]) {
			return "nested"
		}
	case c == 'T':
		// h/v = thunks, V/I/S/T = vtable, typeinfo, type name, type table.
		if strings.IndexByte("hv", rest[1]) >= 0 {
			return "thunk"
		}
		if strings.IndexByte("VIST", rest[1]) >= 0 {
			return "table"
		}
	case c == 'S':
		// _ZSt4cout: a substitution (std:: and friends), not a name.
		if len(rest) >= 4 && strings.IndexByte("tsaioedphbc", rest[1]) >= 0 {
			return "std-substitution"
		}
	case c >= '0' && c <= '9':
		return "freestanding"
	case c == 'L' && len(rest) >= 4 && rest[1] >= '0' && rest[1] <= '9':
		return "internal-linkage" // _GLOBAL__sub_I_ style duplicates
	}
	if manglingItaniumOperator(rest) {
		return "operator"
	}
	return ""
}

// manglingItaniumNested checks only framing: qualifiers, then a length-prefixed
// component, a substitution or a local name, and a closing E. No name is read.
func manglingItaniumNested(body string) bool {
	body = strings.TrimLeft(body, "rVK")
	if body == "" {
		return false
	}
	switch {
	case body[0] >= '0' && body[0] <= '9':
	case body[0] == 'S', body[0] == 'Z':
	default:
		return false
	}
	return strings.IndexByte(body, 'E') > 0
}

var manglingItaniumOps = map[string]bool{
	"nw": true, "na": true, "dl": true, "da": true, "ps": true, "ng": true,
	"ad": true, "de": true, "co": true, "pl": true, "ml": true, "mi": true,
	"dv": true, "rm": true, "an": true, "or": true, "eo": true, "aS": true,
	"pL": true, "qu": true, "rq": true, "li": true,
}

func manglingItaniumOperator(rest string) bool {
	return len(rest) >= 2 && manglingItaniumOps[rest[:2]]
}

// MSVC: `?name@@signature`. `_Z` is never MSVC; `??2`/`??_7` are the special and
// vftable forms whose second '@' separator is not doubled.
func manglingMSVCShape(n string) string {
	if len(n) < 4 || n[0] != '?' {
		return ""
	}
	if strings.Contains(n[1:], "@@") {
		return "sig-separator"
	}
	if n[1] == '?' && len(n) >= 5 {
		return "special-name"
	}
	return ""
}

// Rust v0: `_R` then a path whose framing parses. A bare `_R` prefix is not a
// label; the name must contain a well-formed crate root and valid backrefs.
func manglingV0Shape(n string) string {
	if !strings.HasPrefix(n, "_R") {
		return ""
	}
	s := n[2:]
	if s == "" {
		return ""
	}
	if s[0] >= '0' && s[0] <= '9' { // optional encoding version
		s = s[1:]
		if s == "" {
			return ""
		}
	}
	if strings.IndexByte("CNMXIY", s[0]) < 0 {
		return ""
	}
	if !manglingV0Framing(s) {
		return ""
	}
	return "v0-path"
}

const manglingBase62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func manglingBase62Digit(c byte) int {
	if c == 0 {
		return -1
	}
	return strings.IndexByte(manglingBase62, c)
}

func manglingLowerHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

func manglingV0Char(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
		c == '_' || c == '.' || c == '$'
}

// manglingV0Framing walks the encodings without decoding them: crate roots must
// be `C<base62>_<len><name>`, backrefs must point backwards, escapes must be
// well formed, and the name must contain a crate root.
func manglingV0Framing(s string) bool {
	crate := false
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == 'C':
			end, ok := manglingV0Crate(s, i)
			if !ok {
				return false
			}
			crate = true
			i = end
		case c == 'B':
			end, ok := manglingV0Backref(s, i)
			if !ok {
				return false
			}
			i = end
		case c == 'u' && i+1 < len(s) && manglingLowerHex(s[i+1]):
			j := i + 1
			for j < len(s) && manglingLowerHex(s[j]) {
				j++
			}
			if j >= len(s) || s[j] != '_' {
				return false
			}
			i = j + 1
		case manglingV0Char(c):
			i++
		default:
			return false
		}
	}
	return crate && s[len(s)-1] != '_'
}

// manglingV0Crate parses `C <base62 disambiguator> _ <decimal length> <name>`.
func manglingV0Crate(s string, i int) (int, bool) {
	j := i + 1
	for j < len(s) && manglingBase62Digit(s[j]) >= 0 {
		j++
	}
	if j == i+1 || j >= len(s) || s[j] != '_' {
		return 0, false
	}
	j++
	k, n := j, 0
	for k < len(s) && s[k] >= '0' && s[k] <= '9' {
		n = n*10 + int(s[k]-'0')
		if n > len(s) {
			return 0, false
		}
		k++
	}
	if k == j || n == 0 || k+n > len(s) {
		return 0, false
	}
	return k + n, true
}

// manglingV0Backref parses `B<base62>_` and requires the target to be an earlier
// byte; a value past the cursor is malformed framing.
func manglingV0Backref(s string, i int) (int, bool) {
	j, v := i+1, 0
	for j < len(s) && manglingBase62Digit(s[j]) >= 0 {
		v = v*62 + manglingBase62Digit(s[j])
		j++
		if v > len(s)+2 {
			return 0, false
		}
	}
	if j == i+1 || j >= len(s) || s[j] != '_' || v == 0 || v > i+2 {
		return 0, false
	}
	return j + 1, true
}

// Go: `pkg.Func`, methods, slash paths, the linker's synthetic prefixes and the
// middle dot. All are names the Go linker itself emits; no other runtime uses
// `type:.eq.`, `go:` or `·`.
func manglingGoShape(n string) string {
	if strings.HasPrefix(n, "go:") {
		return "go-prefix"
	}
	if strings.HasPrefix(n, "type:.eq.") || strings.HasPrefix(n, "type:.hash.") {
		return "type-eq"
	}
	if strings.ContainsRune(n, '·') {
		return "middle-dot"
	}
	dot := strings.LastIndexByte(n, '.')
	if dot <= 0 || dot == len(n)-1 {
		return ""
	}
	pkg, sym := n[:dot], n[dot+1:]
	// Both regexes anchor their first byte (lowercase package lead, [A-Za-z_]
	// symbol lead), so two byte tests reject most names before the scan.
	last := strings.LastIndexByte(pkg, '/') + 1
	lead := sym[0]
	if pkg[last] < 'a' || pkg[last] > 'z' || !((lead >= 'A' && lead <= 'Z') || (lead >= 'a' && lead <= 'z') || lead == '_') {
		return ""
	}
	if !manglingGoPathRe.MatchString(pkg) || !manglingGoSymRe.MatchString(sym) {
		return ""
	}
	if strings.Contains(n[:dot], "/") {
		return "slash-path"
	}
	return "pkg-func"
}

// Swift: `$s` / `_$s` followed by a length-prefixed module name or a stdlib type
// prefix. The older `_T0` prefix is deliberately not claimed here.
func manglingSwiftShape(n string) string {
	if strings.HasPrefix(n, "_$s") {
		n = n[1:]
	}
	if !strings.HasPrefix(n, "$s") {
		return ""
	}
	body := n[2:]
	if len(body) < 2 {
		return ""
	}
	if body[0] >= '0' && body[0] <= '9' {
		return "swift-mangled"
	}
	if body[0] >= 'A' && body[0] <= 'Z' && body[1] >= 'a' && body[1] <= 'z' {
		return "swift-stdlib"
	}
	return ""
}
