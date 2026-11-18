package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Item 180. The lexer is the base every other JS item reads through: it tells
// code from comment/string/regex text, and the literal table is the string
// inventory the item promises (a bundle's literal strings name its endpoints,
// channels and flags). A V8 code cache is not source: it is refused here rather
// than reported as an empty application.

func init() {
	registerOp(op{
		name:  "analyze_javascript_application",
		route: "L",
		desc:  "lex a JS bundle (strings, templates, comments, regexes) into its import/export edges and literal string table",
		needs: true,
		run:   opAnalyzeJavascriptApplication,
	})
}

type jsApplication struct {
	Bytes     int      `json:"bytes"`
	Tokens    int      `json:"tokens"`
	Comments  int      `json:"comments"`
	Regexes   int      `json:"regex_literals"`
	Templates int      `json:"templates"`
	Imports   []jsEdge `json:"imports"`
	Exports   []string `json:"exports"`
	Strings   []string `json:"strings"`
	Truncated bool     `json:"truncated"`
}

func opAnalyzeJavascriptApplication(path string) (any, error) {
	// B9: the budget is inside the op, so a container larger than a script
	// cannot leave the caller waiting for its own timeout.
	return runOpDeadline(path, func() (any, error) { return analyzeJavascriptApplication(path) })
}

func analyzeJavascriptApplication(path string) (any, error) {
	if err := refuseCodeCache(path); err != nil {
		return nil, err
	}
	src, truncated, err := readWebTargetText(path)
	if err != nil {
		return nil, err
	}
	masked, st := lexJS([]byte(src))
	lines := newLineIndex(src)
	imports := jsEdgesIndexed(src, masked, lines)
	if imports == nil {
		imports = []jsEdge{}
	}
	// uniqSorted sorts; a pre-sort here only paid for the same ordering twice.
	exports := make([]string, 0)
	for _, e := range jsExportsIndexed(src, masked, lines) {
		exports = append(exports, e.Name)
	}
	strings := st.Strings
	if len(strings) > maxWebStrings {
		strings = strings[:maxWebStrings]
	}
	return jsApplication{
		Bytes:     len(src),
		Tokens:    st.Tokens,
		Comments:  st.Comments,
		Regexes:   st.Regexes,
		Templates: st.Templates,
		Imports:   imports,
		Exports:   uniqSorted(exports),
		Strings:   strings,
		Truncated: truncated,
	}, nil
}

const maxWebStrings = 256

// refuseCodeCache refuses the things that are not JavaScript source: a
// directory, and a V8 code cache (cached bytecode for one script, no source
// text in it).
func refuseCodeCache(path string) error {
	head := make([]byte, 4)
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if st.IsDir() {
		return fmt.Errorf("%s is a directory: pass one JS file", path)
	}
	n, err := f.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if int64(n) == 4 && nativeMagic(head) {
		return fmt.Errorf("%s is not JavaScript source: it is a native binary, and the JS lexer would read its bytes as source; use the native route", path)
	}
	if int64(n) == 4 && v8cacheMatch(head, st.Size()) {
		return fmt.Errorf("%s is a V8 code cache: it holds bytecode for one script and no source text, so no application map is recoverable from it (point lrecon at the file directly for its header facts)", path)
	}
	return nil
}

// nativeMagic reports an executable magic that is never JavaScript source.
func nativeMagic(h []byte) bool {
	if len(h) < 4 {
		return false
	}
	if (h[0] == 'M' && h[1] == 'Z') || (h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
		return true
	}
	switch [4]byte{h[0], h[1], h[2], h[3]} {
	case [4]byte{0xfe, 0xed, 0xfa, 0xce}, [4]byte{0xfe, 0xed, 0xfa, 0xcf},
		[4]byte{0xce, 0xfa, 0xed, 0xfe}, [4]byte{0xcf, 0xfa, 0xed, 0xfe},
		[4]byte{0xca, 0xfe, 0xba, 0xbe}, [4]byte{0xbe, 0xba, 0xfe, 0xca}:
		return true
	}
	return false
}

// jsExport is one named assignment: the shape comparison (item 185) and the
// runtime reconciliation (item 200) both join on these rows.
type jsExport struct {
	Name  string `json:"name"`
	Arity int    `json:"arity"`
	Line  int    `json:"line"`
}

var jsExportRes = []struct {
	re   *regexp.Regexp
	name int // submatch holding the name, 0 = fixed by the caller
}{
	{regexp.MustCompile(`\bexports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(([^)\n]*)\)`), 1},
	{regexp.MustCompile(`\bmodule\.exports\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*[\w$]*\s*)?\(([^)\n]*)\)`), 1},
	{regexp.MustCompile(`\bmodule\.exports\s*=\s*(?:async\s+)?function\s*([\w$]*)\s*\(([^)\n]*)\)`), 1},
	{regexp.MustCompile(`\bexport\s+(?:async\s+)?function\s+([\w$]+)\s*\(([^)\n]*)\)`), 1},
	{regexp.MustCompile(`\bexport\s+const\s+([\w$]+)\s*=\s*(?:async\s*)?(?:function\s*[\w$]*\s*)?\(([^)\n]*)\)`), 1},
}

// jsExports collects the assignment-shaped exports. The name is read off the
// pattern; the arity off the parameter list, counted at top level so a
// destructured parameter ({a, b}) stays one argument.
func jsExports(src string, masked []byte) []jsExport {
	return jsExportsIndexed(src, masked, newLineIndex(src))
}

func jsExportsIndexed(src string, masked []byte, lines lineIndex) []jsExport {
	var out []jsExport
	seen := map[string]bool{}
	for _, rule := range jsExportRes {
		for _, m := range rule.re.FindAllStringSubmatchIndex(src, -1) {
			if m[0] >= len(masked) || masked[m[0]] == ' ' {
				continue
			}
			name := "module.exports"
			if rule.name > 0 && m[2] >= 0 {
				name = src[m[2]:m[3]]
			}
			if name == "" {
				name = "module.exports"
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, jsExport{Name: name, Arity: paramArity(src[m[4]:m[5]]), Line: lines.at(m[0])})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// paramArity counts top-level commas plus one; an empty or comment-only list is
// arity 0. Rest and default values still count as one parameter.
func paramArity(params string) int {
	params = strings.TrimSpace(params)
	if params == "" {
		return 0
	}
	depth, n := 0, 1
	for i := 0; i < len(params); i++ {
		switch params[i] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		case ',':
			if depth == 0 {
				n++
			}
		}
	}
	return n
}
