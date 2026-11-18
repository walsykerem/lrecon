package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// version is the default the tool reports; release builds override it with
// -X main.version=$(git describe --tags --abbrev=0) (tools/build_all.sh).
var version = "1.0.0"

// Declines say what lrecon does not do, in words a reader can act on.
// They must not name a tool: the reader's toolchain is not ours.
const (
	websiteDecline = "website targets are out of scope: fetch the page yourself and point lrecon at the downloaded file"
	runtimeDecline = "live runtime targets are out of scope: lrecon reads static files only"
)

type listRow struct {
	Name  string `json:"name"`
	Route string `json:"route"`
	// Needs names what the item cannot run without: target, device, session or
	// arg. It is empty only for an item that answers with no input at all. The
	// external-tool table still publishes the old bool, so this holds either
	// shape.
	Needs any    `json:"needs"`
	Desc  string `json:"desc"`
}

func printListRows(rows []listRow, asJSON bool) {
	printListRowsCompact(rows, asJSON, false)
}

func printListRowsCompact(rows []listRow, asJSON, compact bool) {
	if asJSON {
		b, err := encodeJSON(rows, compact)
		if err != nil {
			refuse(err.Error())
		}
		fmt.Println(string(b))
		return
	}
	for _, r := range rows {
		fmt.Println(r.Name)
	}
}

func listRows(names []string, table map[string]op) []listRow {
	rows := make([]listRow, 0, len(names))
	for _, name := range names {
		o := table[name]
		rows = append(rows, listRow{o.name, o.route, opNeeds(o), o.desc})
	}
	return rows
}

// printExtRows is --list-ext-ops: the default is names only (~390 tokens),
// because that is what a reader needs to pick a call. --full adds route, needs
// and desc (~1800 tokens); --json adds the row shape (~3800 tokens).
func printExtRows(rows []listRow, asJSON, full bool) {
	if asJSON {
		printListRows(rows, true)
		return
	}
	for _, r := range rows {
		if !full {
			fmt.Println(r.Name)
			continue
		}
		fmt.Printf("%s\t%s\t%v\t%s\n", r.Name, r.Route, r.Needs, r.Desc)
	}
}

func listExtRows(names []string, table map[string]extOp) []listRow {
	rows := make([]listRow, 0, len(names))
	for _, name := range names {
		o := table[name]
		rows = append(rows, listRow{o.name, o.route, o.needs, o.desc})
	}
	return rows
}

func main() {
	installSignalReaper()
	fs := flag.NewFlagSet("lrecon", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	outFile := fs.String("o", "", "write the JSON digest to this file instead of stdout; a writing --op needs -o FILE|DIR, and --extract writes into -o DIR")
	versionFlag := fs.Bool("version", false, "print the version and exit")
	helpFlag := fs.Bool("help", false, "print the short usage; with --all, every flag")
	allFlag := fs.Bool("all", false, "with --help: print every flag")
	maxBytes := fs.Int("max-bytes", 4096, "truncate text output at this many bytes (must be > 0)")
	deep := fs.String("deep", "", "dump disassembly of one function/symbol (native targets)")
	diff := fs.String("diff", "", "print one-line changes from this digest (saved JSON or target) to <target>")
	extract := fs.String("extract", "", "write one member of a zip/apk/ipa/asar into the directory given by -o")
	extractAll := fs.String("extract-all", "", "write every member of a zip/apk/ipa/asar under this directory")
	explain := fs.String("explain", "", "explain one digest field: claim, byte offset, reason and rule_sha")
	opName := fs.String("op", "", "run one inventory item (see --list-ops); JSON on stdout")
	targetFlag := fs.String("target", "", "artifact path for a target-less call; same value as the positional target")
	listOps := fs.Bool("list-ops", false, "print every registered inventory item and exit")
	extOpName := fs.String("ext-op", "", "run one external-tool item (see --list-ext-ops); JSON on stdout")
	listExtOps := fs.Bool("list-ext-ops", false, "print every registered external-tool item and exit")
	planFlag := fs.Bool("plan", false, "one call: kind, the op to run next, its filled command and the envelope it answers with")
	nextFlag := fs.Bool("next", false, "print the next 2-3 commands for this target; the cheap form of --plan")
	compact := fs.Bool("compact", true, "compact JSON: no indentation, same data")
	countOnly := fs.Bool("count-only", false, "print only the record count (with --op or --list-ops)")
	top := fs.Int("top", 0, "keep only the first N records of --op or --list-ops (with --by: first N groups)")
	by := fs.String("by", "", "group records by this field and count each group")
	fields := fs.String("fields", "", "project each record to these comma-separated fields")
	coverage := fs.Bool("coverage", false, "add coverage {parsed,skipped,unknown} and partial to an --op answer")
	progress := fs.Bool("progress", false, "while an op runs, print one stage=<name> elapsed=<n>s line on stderr every 5s (off by default)")
	full := fs.Bool("full", false, "with --list-ext-ops: print route, needs and desc, not just names")
	// Live targets are a non-goal. The flags exist so the CLI can say so
	// instead of failing with "flag provided but not defined".
	pid := fs.Int("pid", -1, "declined: live runtime targets are out of scope")
	for _, name := range []string{"process", "runtime", "live", "attach"} {
		fs.Func(name, "declined: live runtime targets are out of scope", func(string) error { return nil })
	}
	fs.Usage = func() {
		// Under --json the envelope on stdout is the answer; usage text is for
		// people and would only repeat it on stderr.
		if refuseState.json {
			return
		}
		// The whole flag dump is ~465 tokens of context a reader pays for on
		// every --help. Four lines answer the common question; --help --all
		// still publishes every flag for the rare one.
		if *allFlag {
			// PrintDefaults writes to the flag set's output, which parseFlags
			// discards to keep the flag package's error line out of refusals.
			fs.SetOutput(os.Stderr)
			fmt.Fprintln(os.Stderr, "usage: lrecon <target> [flags]")
			// The target is a path, never NAME=value: `lrecon --json T=./bin` was
			// read as a file called "T=./bin" and failed with "no such file".
			fmt.Fprintln(os.Stderr, "note: a T=path or T=value form is not a positional target; pass the path itself")
			// An op takes its arguments from LRECON_* variables, and a name like
			// LRECON_ARCH was invisible in both help forms.
			fmt.Fprintln(os.Stderr, "note: op arguments are LRECON_* variables (LRECON_AT, LRECON_NAME, LRECON_ARCH, ...)")
			fs.PrintDefaults()
			return
		}
		fmt.Fprintln(os.Stderr, "usage: lrecon <target> [--json] [--version]")
		fmt.Fprintln(os.Stderr, "  --list-ops  names; --list-ext-ops: tools")
		fmt.Fprintln(os.Stderr, "  --op NAME  run one item; JSON out")
		fmt.Fprintln(os.Stderr, "  --help --all  all flags; --json: envelope")
	}
	args := os.Args[1:]
	// One read of the raw arguments: a refusal may happen before --json is
	// parsed, and it must still answer on stdout when the caller asked for it.
	refuseState.json = sawJSON(args)
	// The flag package keeps the last value of a repeated flag and forgets the
	// earlier ones, so the raw arguments are the only place a second --op is
	// still visible. The positional loop below rebuilds args, never this copy.
	rawArgs := args
	parseFlags(fs, args)
	// Go stops flag parsing at the first positional, but our usage is
	// `lrecon <target> [flags]`. Pull every positional out, re-parse the rest.
	var paths []string
	for fs.NArg() > 0 {
		paths = append(paths, fs.Arg(0))
		// Remove the positional the flag package stopped at, by index: matching
		// its text would also delete a flag value that happens to name a path.
		// The three-index slice keeps rawArgs' backing array untouched.
		i := len(args) - fs.NArg()
		args = append(args[:i:i], args[i+1:]...)
		parseFlags(fs, args)
	}
	if *helpFlag {
		// A help request is not a refusal: answer it even under --json, where
		// Usage() otherwise stays quiet because the envelope is the answer.
		refuseState.json = false
		fs.Usage()
		return
	}
	if *targetFlag != "" {
		paths = append(paths, *targetFlag)
	}
	// The refusal envelope names the target from here on: every refusal below
	// this point is about this file, and two files that refuse the same way
	// must not answer with the same bytes.
	if len(paths) > 0 {
		refuseState.target = paths[0]
	}
	if *versionFlag {
		fmt.Println("lrecon " + version)
		return
	}
	if name, value := swallowedFlag(fs); name != "" {
		refuseKind(kindNeedsArg, fmt.Sprintf("--%s needs a value, got %q", name, value))
	}
	// A byte budget of zero or less used to slip through and read as "no cut",
	// so the answer looked complete while the flag was silently dropped. The
	// default already means "no cut"; a budget has to be a positive count.
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-bytes" && *maxBytes <= 0 {
			// A named mode is a machine answer: this refusal lands before the
			// --op block sets refuseState.op, and without it the caller sees
			// rc=2 and an empty stdout (`--op read_bytes --max-bytes 0`).
			if !refuseState.json {
				refuseState.op = namedMode(rawArgs)
			}
			refuseKind(kindBadArg, fmt.Sprintf("--max-bytes %d: needs a positive byte count; omit the flag for the %s-byte default",
				*maxBytes, fs.Lookup("max-bytes").DefValue))
		}
	})
	// LRECON_LEN is a byte count, but the native env reader falls back to base 16
	// for text it cannot read as decimal ("abc" silently became 2748 bytes). A
	// value no op can read is a bad argument, not a default.
	if raw := strings.TrimSpace(os.Getenv("LRECON_LEN")); raw != "" && !isByteCount(raw) {
		refuseKind(kindBadArg, fmt.Sprintf("LRECON_LEN=%q is not a byte count: write a decimal number (or 0x…)", raw))
	}

	// A live target is not a file. Decline before anything tries to open one.
	live := *pid >= 0
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "process", "runtime", "live", "attach":
			live = true
		}
	})
	if live {
		decline(runtimeDecline)
	}
	// Two flags that answer different questions cannot be one call. lrecon used
	// to pick one of them and drop the other in silence, so the caller never
	// learned that half of the command line was ignored.
	if msg := cliConflict(fs, rawArgs); msg != "" {
		refuseKind(kindUsage, msg)
	}
	modes := opModes{compact: *compact, countOnly: *countOnly, top: *top, by: *by, fields: *fields, coverage: *coverage}
	if err := modeConflict(modes); err != nil {
		refuseKind(kindUsage, err.Error())
	}
	if modes.aggregate() && *opName == "" && !*listOps {
		refuseKind(kindUsage, "--count-only, --top, --by and --fields apply to --op or --list-ops")
	}
	if *coverage && *opName == "" {
		refuseKind(kindUsage, "--coverage applies to --op")
	}
	// Inventory items answer on their own: some need no file (tool versions),
	// so they run before the "one target" rules below.
	if *listOps {
		rows := listRows(opNames(), ops)
		if !modes.aggregate() {
			printListRowsCompact(rows, *asJSON, *compact)
			return
		}
		g, err := decodeNumbers(rows)
		if err != nil {
			refuseKind(kindInternal, err.Error())
		}
		if g, err = aggregate(g, modes); err != nil {
			refuseKind(kindUsage, err.Error())
		}
		b, err := encodeJSON(g, *compact)
		if err != nil {
			refuseKind(kindInternal, err.Error())
		}
		fmt.Println(string(b))
		return
	}
	// The external-tool items have their own list and their own table, for
	// the same reason: they are a different surface. Mixing them into --op
	// would change the published 229-item inventory.
	if *listExtOps {
		printExtRows(listExtRows(extOpNames(), extOps), *asJSON, *full)
		return
	}
	// An external-tool item runs before the target rules below: its target can
	// be a pid (lldb attach), a host:port (adb connect) or a file, and the
	// item itself decides what that string means.
	if *extOpName != "" {
		refuseState.op = *extOpName
		target := ""
		var extra []string
		if len(paths) > 0 {
			target = paths[0]
			extra = paths[1:]
		}
		opOutput = *outFile
		stop := startProgress(*progress, *extOpName)
		res, err := runExtOp(*extOpName, target, extra)
		stop()
		if err != nil {
			if ex, ok := errors.AsType[*extRefusal](err); ok {
				refuseKind(ex.kind, ex.msg)
			}
			refuse(err.Error())
		}
		if s, ok := res.(*skip); ok {
			refuse(s.Reason)
		}
		answer := capAnswer(map[string]any{"op": *extOpName, "target": target, "result": res})
		b, err := encodeJSON(answer, *compact)
		if err != nil {
			refuseKind(kindInternal, err.Error())
		}
		fmt.Println(string(b))
		maxBytesNote(fs, *maxBytes, len(b), "--ext-op")
		return
	}
	// Out-of-scope targets get a decline, not a filesystem error: the reader
	// asked for something lrecon does not do, and that is not a broken file.
	// Exit 2 means "could not answer", so stdout stays empty even under --json.
	// This runs before --op so a live target is declined instead of stat()ed.
	// Live targets are a non-goal for the digest path, but an explicit op may
	// take one (capture_process_scenario samples a pid); let the op validate it.
	if len(paths) > 0 {
		switch {
		// An op may take a URL as its *argument* rather than as the document to
		// read: resolve_adb_packages asks the device which app opens
		// https://example.com. The decline is about fetching pages, so a
		// selector op is exempt and its own code decides.
		case looksLikeWebsite(paths[0]) && !opTargetIsSelector(*opName):
			decline(websiteDecline)
		case looksLikePID(paths[0]):
			decline(runtimeDecline)
		// An --op target is a file or an op-specific selector, never a live
		// process name: frida ops take a pid or a process name on purpose, and
		// inspect_signal_decoders takes its query here. A bare query such as
		// "fsk" used to be declined as a process name before the op could read
		// it. An explicit pid: prefix is still declined.
		case *opName == "" && looksLikeProcessName(paths[0]):
			decline(runtimeDecline)
		}
	}
	// An explicit empty value used to read as an absent flag: `--extract ""`
	// printed a digest as if the extraction had succeeded.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "diff", "extract", "extract-all", "explain":
			if f.Value.String() == "" {
				refuse("--" + f.Name + " needs a value")
			}
		}
	})
	// One document per call: these modes print text, so --json cannot answer,
	// except --explain: a machine caller asking for one field's attribution
	// gets the same attribution as JSON (item 21), not a usage refusal.
	if *asJSON && (*diff != "" || *extract != "" || *extractAll != "" || *deep != "" || *nextFlag) {
		decline("--json cannot be combined with --diff, --extract, --extract-all, --deep or --next")
	}
	// -o is the digest file, and --extract-all names its own tree, so the other
	// text modes cannot also own it.
	if *outFile != "" && (*diff != "" || *extractAll != "" || *explain != "" || *deep != "" || *planFlag || *nextFlag) {
		decline("-o cannot be combined with --diff, --extract-all, --explain, --deep, --plan or --next")
	}
	// Inventory items answer on their own; they run before the one-target rule.
	if *opName != "" {
		// The envelope names the op even when the op is what went wrong.
		refuseState.op = *opName
		target := ""
		if len(paths) > 1 {
			refuseKind(kindUsage, fmt.Sprintf("--op takes one target, got %d", len(paths)))
		}
		if len(paths) == 1 {
			target = paths[0]
		}
		// A writing op has no default destination: without -o nothing is
		// written beside the target, and the caller learns why before the op
		// runs. -o on a read-only op is refused for the same reason: it would
		// be silently dropped while the caller waits for a file.
		opOutput = *outFile
		if err := checkOpOutput(*opName, *outFile); err != nil {
			if argErr, ok := errors.AsType[*opArgError](err); ok {
				refuseKind(argErr.kind, argErr.msg)
			}
			refuse(err.Error())
		}
		stop := startProgress(*progress, *opName)
		res, err := runOp(*opName, target)
		stop()
		if err != nil {
			refuse(err.Error())
		}
		// A bare skip is a refusal with a reason, not a result: exit 2, no JSON.
		if s, ok := res.(*skip); ok {
			refuse(s.Reason)
		}
		answer := map[string]any{"op": *opName, "target": target, "result": res}
		// An inferred target is an answer the caller can act on: name it, and say
		// how sure the inference was, instead of silently answering for another file.
		if assumed.Path != "" {
			answer["target"] = assumed.Path
			answer["assumed_target"] = assumed.Path
			answer["confidence"] = assumed.Confidence
		}
		if modes.aggregate() {
			g, err := decodeNumbers(answer)
			if err != nil {
				refuseKind(kindInternal, err.Error())
			}
			if g, err = aggregate(g, modes); err != nil {
				refuseKind(kindUsage, err.Error())
			}
			answer, _ = g.(map[string]any)
		}
		// Envelope first, cap second: capping before the envelope would let the
		// envelope push the answer past the byte ceiling it promised.
		if modes.coverage {
			answer = withCoverage(answer).(map[string]any)
		}
		answer = capAnswer(answer)
		b, err := encodeJSON(answer, *compact)
		if err != nil {
			refuseKind(kindInternal, err.Error())
		}
		fmt.Println(string(b))
		maxBytesNote(fs, *maxBytes, len(b), "--op")
		return
	}
	if len(paths) == 0 {
		// A machine caller gets the envelope; the usage text is for people.
		if refuseState.json {
			refuseKind(kindUsage, "no target: lrecon needs one file to read")
		}
		fs.Usage()
		os.Exit(2)
	}
	// One target per call: a dropped second target looks like success (exit 0, one digest).
	if len(paths) > 1 {
		q := make([]string, len(paths))
		for i, p := range paths {
			q[i] = "\"" + p + "\""
		}
		refuseKind(kindUsage, fmt.Sprintf("%d targets given, expected 1; loop instead: for t in %s; do lrecon \"$t\"; done",
			len(paths), strings.Join(q, " ")))
	}
	path := paths[0]
	// JSON is a machine contract: the default budget must never cut it mid-document.
	// Only an explicit --max-bytes may truncate it.
	limit := *maxBytes
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-bytes" {
			explicit = true
		}
	})
	if (*asJSON || *outFile != "") && !explicit {
		limit = 0
	}
	// --max-bytes is a text budget for the digest. Extraction has its own cap
	// (LRECON_BUNDLE_CAP_BYTES), so a byte budget here used to be read as if it
	// bounded the extracted member: it never did.
	if explicit && (*extract != "" || *extractAll != "") {
		refuseKind(kindBadArg, "--max-bytes does not apply to --extract or --extract-all; the extraction cap is LRECON_BUNDLE_CAP_BYTES")
	}

	d, err := Probe(path)
	if err != nil {
		refuse(err.Error())
	}
	// --plan and --next answer from the digest alone: no op runs, so the call
	// cannot cost what the op it recommends costs.
	if *planFlag || *nextFlag {
		p := buildPlan(d, path)
		if *nextFlag {
			printNext(p)
			return
		}
		printPlan(p)
		return
	}
	if *explain != "" {
		out, err := ExplainField(d, *explain)
		if err != nil {
			// An unknown field name is a bad argument, not a usage error:
			// the caller named a field the digest does not carry (item 21).
			refuseKind(kindBadArg, err.Error())
		}
		if *asJSON {
			b, err := json.MarshalIndent(map[string]any{"field": *explain, "explain": out}, "", "  ")
			if err != nil {
				refuseKind(kindInternal, err.Error())
			}
			fmt.Println(string(b))
			return
		}
		fmt.Print(truncate(out, limit))
		return
	}
	if *diff != "" {
		old, err := loadDigest(*diff)
		if err != nil {
			refuse(err.Error())
		}
		lines := DiffDigests(old, d)
		fmt.Print(truncate(strings.Join(lines, "\n")+"\n", limit))
		if len(lines) > 0 {
			os.Exit(1)
		}
		return
	}
	if *deep != "" {
		out, err := DeepScan(path, *deep)
		if err != nil {
			// An unknown symbol is a refusal like any other: rc=2, reason on
			// stderr. A "no symbol table entry" skip that exited 0 read as
			// success.
			if !refuseState.json {
				refuseState.op = "deep"
			}
			refuse(err.Error())
		}
		fmt.Print(out)
		return
	}
	if *extractAll != "" {
		if err := ExtractAll(path, *extractAll, &d); err != nil {
			refuse(err.Error())
		}
		fmt.Print(digestTextOrBody(d, limit))
		return
	}
	if *extract != "" {
		// --extract used to write into the process working directory, which put
		// a member beside whatever the caller happened to be standing in. -o DIR
		// is the destination now; without it the member is not written at all.
		if strings.TrimSpace(*outFile) == "" {
			if !refuseState.json {
				refuseState.op = "extract"
			}
			refuseKind(kindNeedsArg, "--extract writes one member and needs -o DIR; without it nothing is written")
		}
		opOutput = *outFile
		dir, err := exportDirDest("extract", path)
		if err != nil {
			refuse(err.Error())
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			refuse(err.Error())
		}
		if err := ExtractPayloadTo(path, *extract, dir, &d); err != nil {
			refuse(err.Error())
		}
		fmt.Print(digestTextOrBody(d, limit))
		return
	}
	if *asJSON || *outFile != "" {
		b, err := encodeJSON(d, *compact)
		if err != nil {
			refuse(err.Error())
		}
		if *outFile != "" {
			if err := writeDigestFile(*outFile, path, string(b)+"\n"); err != nil {
				refuse(err.Error())
			}
			maxBytesNote(fs, limit, len(b), "-o")
			return
		}
		fmt.Println(string(b))
		if limit > 0 && len(b) > limit {
			fmt.Fprintf(os.Stderr, "lrecon: --max-bytes %d does not apply to --json (%d bytes); drop the flag for machine output\n", limit, len(b))
		}
		return
	}
	fmt.Print(digestTextOrBody(d, limit))
}

// loadDigest accepts a saved `--json` digest first, so `lrecon --diff old.json T`
// compares against the saved fields instead of sniffing the file as text. A
// saved digest from another contract version is refused: its keys may mean
// something else, and a wrong comparison is worse than no answer.
// writeDigestFile writes the JSON digest to dest. An existing directory is a
// destination, not a filename: each call gets its own <target>.json, and a
// name already taken by an earlier call gets a -1, -2 suffix instead of
// overwriting it. A non-directory dest keeps the single-file behavior.
func writeDigestFile(dest, target, out string) error {
	fi, err := os.Stat(dest)
	if err != nil || !fi.IsDir() {
		// The digest describes the target; an -o that resolves to the same file
		// (a symlink or a hardlink, not just an equal string) rewrites the
		// artifact it just read.
		if src, serr := os.Stat(target); err == nil && serr == nil && os.SameFile(fi, src) {
			return fmt.Errorf("-o %s is not a usable destination: it is the same file as %s, so the digest would overwrite the artifact", dest, target)
		}
		return os.WriteFile(dest, []byte(out), 0o644)
	}
	base := strings.TrimSuffix(filepath.Base(target), filepath.Ext(target))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "digest"
	}
	for i := range 1000 {
		name := base + ".json"
		if i > 0 {
			name = fmt.Sprintf("%s-%d.json", base, i)
		}
		f, err := os.OpenFile(filepath.Join(dest, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, err := f.WriteString(out); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	return fmt.Errorf("%s: 1000 digest names tried, all taken; use -o FILE", dest)
}

func loadDigest(path string) (Digest, error) {
	b, err := readCapped(path, maxMetaRead)
	if err != nil {
		return Probe(path)
	}
	body := bytes.TrimSpace(b)
	if len(body) == 0 || body[0] != '{' {
		return Probe(path)
	}
	// A JSON body is meant to be a saved digest. Falling back to Probe when it
	// does not decode answers for the file's bytes instead of the saved answer,
	// so a corrupt baseline reads as "no differences".
	var d Digest
	if err := json.Unmarshal(body, &d); err != nil {
		return d, fmt.Errorf("%s looks like saved digest but does not decode: %w", path, err)
	}
	if d.Kind == "" {
		return d, fmt.Errorf("%s looks like saved digest but does not decode: no kind", path)
	}
	if d.ContractVersion != contractVersion {
		return d, fmt.Errorf("%s is contract_version %d, want %d: regenerate it with this lrecon",
			path, d.ContractVersion, contractVersion)
	}
	return d, nil
}

// truncate cuts at the last whole line that fits, so the digest never ends mid-value,
// and says so: a cut digest read as complete is a wrong answer, not a small one.
func truncate(s string, limit int) string {
	cut, wasCut := cutUTF8(s, limit)
	if !wasCut {
		return s
	}
	if i := strings.LastIndexByte(cut, '\n'); i >= 0 {
		cut = cut[:i+1]
	} else {
		// No whole line fits: one cut line still beats an empty body, which read
		// as "nothing to report" for a file with content.
		if limit > 1 {
			cut, _ = cutUTF8(s, limit-1)
		} else {
			cut = ""
		}
		cut += "\n"
	}
	return cut + fmt.Sprintf("note: truncated at %d of %d bytes; raise --max-bytes for more\n", len(cut), len(s))
}

// cutUTF8 is the one byte cut in lrecon: a budget never buys half a rune,
// because the cut string is printed or embedded in JSON and mojibake is not a
// smaller answer. ok is false when s already fits.
func cutUTF8(s string, limit int) (string, bool) {
	if limit <= 0 || len(s) <= limit {
		return s, false
	}
	for limit > 0 && !utf8.RuneStart(s[limit]) {
		limit--
	}
	return s[:limit], true
}

// maxBytesNote says the byte budget was ignored: a machine answer is one whole
// JSON on stdout and is never cut. The flag only earns a note when the caller
// gave it and the answer is bigger than it.
func maxBytesNote(fs *flag.FlagSet, limit, n int, mode string) {
	if limit <= 0 || n <= limit {
		return
	}
	explicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-bytes" {
			explicit = true
		}
	})
	if !explicit {
		return
	}
	fmt.Fprintf(os.Stderr, "lrecon: --max-bytes %d does not apply to %s (%d bytes); drop the flag for machine output\n", limit, mode, n)
}

// digestTextOrBody keeps the evidence line when the budget can hold it and the
// truncation note; a budget smaller than that used to answer with the note and an
// empty body, which reads as "nothing to report" for a file with content. There
// the budget goes to the body and truncate's note says the rest was cut.
func digestTextOrBody(d Digest, limit int) string {
	ev, err := evidenceLine(d)
	if err != nil {
		return d.Text()
	}
	if limit <= 0 || limit >= len(ev)+budgetNoteReserve+1 {
		return digestTextWith(d, ev, limit)
	}
	return truncate(d.Text(), limit)
}

// isByteCount accepts the two spellings the native env reader accepts, decimal
// and 0x-hex, and rejects the bare-hex fallback it also accepts ("1f").
func isByteCount(s string) bool {
	digits, base := s, 10
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		digits, base = s[2:], 16
	}
	_, err := strconv.ParseUint(digits, base, 64)
	return err == nil
}

// looksLikeWebsite reports whether the target is a network address. lrecon
// reads static files, so a URL is out of scope, not a missing file.
func looksLikeWebsite(t string) bool {
	if strings.HasPrefix(t, "www.") {
		return true
	}
	i := strings.Index(t, "://")
	if i <= 0 {
		return false
	}
	for j := range i {
		c := t[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
		case j > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// looksLikePID reports a live-process target: pid:1234 or pid=1234.
func looksLikePID(t string) bool {
	return strings.HasPrefix(t, "pid:") || strings.HasPrefix(t, "pid=")
}

// looksLikeProcessName reports a target that is not on disk and has no path
// part and no extension: a process name, not a mistyped file.
func looksLikeProcessName(t string) bool {
	if t == "" || strings.ContainsAny(t, `/\`) || filepath.Ext(t) != "" {
		return false
	}
	_, err := os.Stat(t)
	return os.IsNotExist(err)
}

// namedMode reads the raw arguments for the machine mode they ask for: --op
// and --ext-op name an item, --extract/--extract-all/--deep are named modes
// whose answer is the stdout document. The flag package judges a bad flag
// before the mode block runs, so without this a `--op X --max-bytes 0` refusal
// would exit 2 with a reason only on stderr.
func namedMode(args []string) string {
	mode := ""
	for i := range len(args) {
		a := args[i]
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		switch name {
		case "op", "ext-op":
			if !hasValue && i+1 < len(args) {
				value, hasValue = args[i+1], true
			}
			if hasValue && value != "" && !strings.HasPrefix(value, "-") {
				return value
			}
		case "deep":
			mode = "deep"
		case "extract":
			mode = "extract"
		case "extract-all":
			mode = "extract_all"
		}
	}
	return mode
}

// parseFlags keeps flag errors on the refusal path. -h printed usage already.
func parseFlags(fs *flag.FlagSet, args []string) {
	usage := fs.Usage
	// A bad flag gets one line and a hint, not the usage dump: the flag package
	// calls Usage itself on error, so it is stubbed out for the parse.
	fs.Usage = func() {}
	fs.SetOutput(io.Discard)
	err := fs.Parse(args)
	fs.Usage = usage
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// -h asked for usage; its own print was stubbed, so answer here.
			refuseState.json = false
			fs.Usage()
			os.Exit(0)
		}
		msg := err.Error()
		if !refuseState.json {
			msg += "\nipucu: lrecon --help"
		}
		refuse(msg)
	}
}

// cliConflict names the flags that cannot be one call. Every answer lrecon
// gives is one question, so a command line carrying two of them is refused
// instead of answered with one and quietly dropping the other.
func cliConflict(fs *flag.FlagSet, raw []string) string {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	// Every flag below answers a different question. lrecon used to answer with
	// one and drop the rest in silence (--deep and --op ran the op, --explain
	// and --diff ran the explain), so the caller never learned that half of the
	// command line was ignored.
	var modes []string
	for _, name := range []string{"op", "ext-op", "list-ops", "list-ext-ops", "explain", "diff", "deep", "extract", "extract-all", "plan", "next"} {
		if set[name] {
			modes = append(modes, "--"+name)
		}
	}
	if len(modes) > 1 {
		return strings.Join(modes, " and ") + " cannot be combined: one call answers one question"
	}
	// A repeated flag answers with its last value and drops the earlier ones in
	// silence, so a script cannot tell that the work it asked for never ran.
	for _, name := range []string{"op", "ext-op", "diff", "explain", "deep", "extract", "extract-all", "plan", "next"} {
		if n := flagCount(raw, name); n > 1 {
			return fmt.Sprintf("--%s given %d times: one call answers one question", name, n)
		}
	}
	if set["pid"] {
		if n, err := strconv.Atoi(fs.Lookup("pid").Value.String()); err == nil && n < 0 {
			return fmt.Sprintf("--pid %d: a pid is 0 or more; drop the flag for the static path", n)
		}
	}
	return ""
}

// startProgress is --progress: one `stage=<name> elapsed=<n>s` line on stderr
// every 5 s while an op runs, so a long search and a hung process look
// different at the terminal. Off by default, nothing for an op that finishes
// inside the first tick, and stdout is never touched (the envelope is the
// answer). The returned stop waits for the ticker so no line lands after the
// answer.
func startProgress(on bool, stage string) func() {
	if !on {
		return func() {}
	}
	start := time.Now()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				fmt.Fprintf(os.Stderr, "stage=%s elapsed=%ds\n", stage, int(time.Since(start).Seconds()))
			}
		}
	}()
	return func() { close(done); wg.Wait() }
}

// flagCount counts a flag in the raw arguments. The flag package keeps the
// last value of a repeated flag and forgets the earlier ones.
func flagCount(args []string, name string) int {
	n := 0
	for _, a := range args {
		if a == "--" {
			break
		}
		if len(a) < 2 || a[0] != '-' {
			continue
		}
		k, _, _ := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if k == name {
			n++
		}
	}
	return n
}
