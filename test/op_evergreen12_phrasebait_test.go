package main

// Evergreen12: the Go verdict comes from structure, never from vocabulary.
//
// Two targets carry the same sink words ("/bin/sh", "-c", "LRECON_ARGV_PATH").
// Decoy A is a syntactically valid Go file whose comments and constants are the
// skill docs' own high-signal tokens, with no call and no data path behind them;
// the tool must refuse it. Control B is a hand-written program where an
// environment value really becomes the argv of a child process and its output
// really reaches stdout; the tool must surface its Go build-info and the sink
// string in the image. Same words, different structure, different verdict.

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// evergreen12Sink is the argv[0] both fixtures name: the decoy as inert text,
// the control as the real child-process command.
const evergreen12Sink = "/bin/sh"

// evergreen12ControlSrc is the structural control: env -> argv -> child ->
// stdout. The sink's arguments are real values, not string decoration.
const evergreen12ControlSrc = `package main

import (
	"os"
	"os/exec"
)

func run() error {
	argv := os.Getenv("LRECON_ARGV_PATH")
	out, err := exec.Command("/bin/sh", "-c", argv).Output()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

func main() {
	_ = run()
}
`

// evergreen12Vocabulary harvests the skill docs' backticked identifiers at test
// time, so the decoy speaks the tool's own dialect instead of a list invented
// here. Fewer than 20 tokens means the harvest broke, not that the docs thinned.
func evergreen12Vocabulary(t *testing.T) []string {
	t.Helper()
	docs, err := filepath.Glob(filepath.Join("..", "skill", "references", "*.md"))
	if err != nil {
		t.Fatalf("glob skill references: %v", err)
	}
	docs = append(docs, filepath.Join("..", "skill", "SKILL.md"))
	re := regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_.]{3,})`")
	seen := make(map[string]bool)
	var words []string
	for _, doc := range docs {
		b, err := os.ReadFile(doc)
		if err != nil {
			t.Fatalf("read %s: %v", doc, err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				words = append(words, m[1])
			}
		}
	}
	sort.Strings(words)
	if len(words) < 20 {
		t.Fatalf("harvested %d skill tokens, want at least 20: the decoy would not bait anything", len(words))
	}
	return words
}

// evergreen12Decoy writes a parseable Go file: every harvested token in a
// comment, every sink word in a constant, and no function that calls anything.
func evergreen12Decoy(t *testing.T, words []string) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("package main\n\n// High-signal vocabulary, with no call, sink or data path behind it.\n")
	for i, w := range words {
		if i%8 == 0 {
			b.WriteString("// ")
		}
		b.WriteString(w)
		b.WriteString(" ")
		if i%8 == 7 {
			b.WriteString("\n")
		}
	}
	b.WriteString("\nconst (\n\tevergreen12Sink = ")
	b.WriteString(strconv.Quote(evergreen12Sink))
	b.WriteString("\n\tevergreen12Flag = \"-c\"\n\tevergreen12Arg  = \"LRECON_ARGV_PATH\"\n)\n\nvar evergreen12Words = []string{\n")
	for _, w := range words {
		b.WriteString("\t")
		b.WriteString(strconv.Quote(w))
		b.WriteString(",\n")
	}
	b.WriteString("}\n\nfunc main() {}\n")

	p := filepath.Join(t.TempDir(), "phrasebait.go")
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write decoy: %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), p, nil, 0); err != nil {
		t.Fatalf("decoy is not syntactically valid Go: %v", err)
	}
	return p
}

// evergreen12Build compiles the control for a fixed GOOS/GOARCH so the fixture
// is the same every run; a missing toolchain is a failure, not a quiet skip.
func evergreen12Build(t *testing.T, src string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("go toolchain unavailable, cannot build the structural control: %v", err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "main.go")
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatalf("write control: %v", err)
	}
	out := filepath.Join(dir, "control.elf")
	cmd := exec.Command("go", "build", "-o", out, p)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOFLAGS=", "GOWORK=off", "GO111MODULE=off")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build control: %v\n%s", err, b)
	}
	return out
}

// evergreen12Op decodes one op's JSON result, the same shape the CLI prints.
func evergreen12Op(t *testing.T, name, path string) map[string]any {
	t.Helper()
	res, err := runOp(name, path)
	if err != nil {
		t.Fatalf("%s(%s): %v", name, path, err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("%s(%s): result does not marshal: %v", name, path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s(%s): result is not a JSON object: %v", name, path, err)
	}
	return m
}

func evergreen12Field(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	s, ok := m[key].(string)
	if !ok {
		t.Fatalf("field %q is %T, want string (%v)", key, m[key], m)
	}
	return s
}

func TestEvergreen12PhraseBaitRejected(t *testing.T) {
	words := evergreen12Vocabulary(t)
	decoy := evergreen12Decoy(t, words)
	control := evergreen12Build(t, evergreen12ControlSrc)

	// Both targets name the same sink. Only one has something behind the names.
	decoyBytes, err := os.ReadFile(decoy)
	if err != nil {
		t.Fatalf("read decoy: %v", err)
	}
	for _, want := range []string{evergreen12Sink, "-c", "LRECON_ARGV_PATH"} {
		if !bytes.Contains(decoyBytes, []byte(want)) {
			t.Fatalf("decoy is missing the shared sink word %q", want)
		}
	}

	// Decoy A: valid Go text, the docs' whole vocabulary, zero structure.
	dd, err := Probe(decoy)
	if err != nil {
		t.Fatalf("Probe(decoy): %v", err)
	}
	if dd.Kind != "text" {
		t.Fatalf("decoy kind = %q, want text: vocabulary must not promote a source file", dd.Kind)
	}
	if dd.Toolchain != "" || dd.Mod != "" {
		t.Fatalf("decoy toolchain/mod = %q/%q, want empty: no build to report", dd.Toolchain, dd.Mod)
	}
	if dd.Names != "not_scanned" {
		t.Fatalf("decoy names = %q, want not_scanned", dd.Names)
	}
	dm := evergreen12Op(t, "inspect_go_binary", decoy)
	refusal, _ := dm["skipped"].(string)
	if !strings.Contains(refusal, "is not a native image") {
		t.Fatalf("decoy A verdict = %v, want the structural refusal (not a native image)", dm)
	}
	if _, ok := dm["toolchain"]; ok {
		t.Fatalf("decoy A carries a toolchain (%v) on a refusal", dm)
	}

	// Control B: a real image, a real sink, and no skill vocabulary at all.
	cd, err := Probe(control)
	if err != nil {
		t.Fatalf("Probe(control): %v", err)
	}
	if cd.Kind != "elf" {
		t.Fatalf("control kind = %q, want elf", cd.Kind)
	}
	m := evergreen12Op(t, "inspect_go_binary", control)
	if got := evergreen12Field(t, m, "kind"); got != "elf" {
		t.Fatalf("control inspect kind = %q, want elf", got)
	}
	if tc := evergreen12Field(t, m, "toolchain"); !strings.HasPrefix(tc, "go") {
		t.Fatalf("control toolchain = %q, want a go producer string", tc)
	}
	names := evergreen12Field(t, m, "names")
	if !strings.HasPrefix(names, "pclntab:") {
		t.Fatalf("control names = %q, want a pclntab count", names)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(names, "pclntab:"))
	if err != nil || n <= 0 {
		t.Fatalf("control names = %q, want a positive pclntab count", names)
	}

	// The control's sink is in the image, not just in its source.
	t.Setenv("LRECON_QUERY", evergreen12Sink)
	sm := evergreen12Op(t, "search_strings", control)
	matched, _ := sm["matched"].(float64)
	if matched < 1 {
		t.Fatalf("control search_strings matched = %v for %q, want at least 1", sm["matched"], evergreen12Sink)
	}
	matches, ok := sm["matches"].([]any)
	if !ok || len(matches) == 0 {
		t.Fatalf("control search_strings matches = %v, want at least one hit", sm["matches"])
	}
	hit, ok := matches[0].(map[string]any)
	if !ok {
		t.Fatalf("control search hit is %T, want an object", matches[0])
	}
	if off, _ := hit["file_offset"].(float64); off <= 0 {
		t.Fatalf("control search hit file_offset = %v, want a real image offset", hit["file_offset"])
	}
}
