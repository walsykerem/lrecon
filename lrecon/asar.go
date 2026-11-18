package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// owned by agent B: asar header tree, capabilities from file paths

const (
	maxAsarHeader      = 64 << 20  // header JSON cap; Studio.app's is 5.0 MB
	maxAsarFiles       = 4096      // member paths kept for capability inference
	maxAsarPkgJSON     = 64 << 10  // package.json body cap
	maxAsarPreload     = 256 << 10 // preload body cap
	maxBridgeNames     = 8         // bridge names reported per preload
	maxUnpackedEntries = 20000     // walk cap for the sibling .unpacked dir
	maxIPCScanFile     = 1 << 20   // packed script bytes read per file
	maxIPCScanTotal    = 16 << 20  // packed script bytes read per archive
	maxIPCChannels     = 128       // channel names reported
	maxSourceMaps      = 64        // source map references reported
)

// electronRuntime are the payload files whose presence marks a stock Electron
// runtime (the fuses live in the Electron binary itself, not in the asar).
var electronRuntime = map[string]bool{
	"icudtl.dat":              true,
	"v8_context_snapshot.bin": true,
	"snapshot_blob.bin":       true,
}

var bridgeRe = regexp.MustCompile(`exposeInMainWorld\(\s*(?:"([^"]{1,128})"|'([^']{1,128})'|` + "`" + `([^` + "`" + `]{1,128})` + "`" + `)`)

// asarNode is one header entry. asar v3+ writes "offset" as a decimal string;
// older archives omit it, and then only the tree is available (no body reads).
type asarNode struct {
	Files    map[string]*asarNode `json:"files"`
	Size     int64                `json:"size"`
	Offset   string               `json:"offset"`
	Link     string               `json:"link"`
	Unpacked bool                 `json:"unpacked"`
}

type asarScan struct {
	files    int
	links    int
	unpacked int
	runtime  map[string]bool
	caps     map[string]bool
	paths    []string
	base     int64    // body base: offsets in the header are relative to it
	limit    int64    // file size: offset+size past it is a header lie
	overruns []string // first maxAsarOverruns members declared past EOF
	overrunN int      // all members declared past EOF: header lies are counted, not listed
}

const maxAsarOverruns = 8 // a hostile header must not write 10k notes

// inspectAsar reads only the 16-byte header plus the JSON tree: no file body is
// read except bounded slices of the root package.json and the preload entry.
func inspectAsar(path string, d *Digest) {
	d.Format = "asar"
	f, err := os.Open(path)
	if err != nil {
		d.Notes = append(d.Notes, "asar: open: "+err.Error())
		return
	}
	defer f.Close()

	var hdr [16]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		d.Notes = append(d.Notes, "asar: truncated header: "+err.Error())
		return
	}
	jsonLen := int64(binary.LittleEndian.Uint32(hdr[12:16]))
	if jsonLen <= 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("asar: implausible header JSON length %d", jsonLen))
		return
	}
	// Bodies start after the pickle (which pads the JSON), not at 16+jsonLen:
	// measured 5008256 vs 5008253 on Studio.app, 553908 vs 553907 on Porting Kit.
	base := int64(8) + int64(binary.LittleEndian.Uint32(hdr[4:8]))
	if base < 16+jsonLen || base > 16+jsonLen+16 {
		base = (16 + jsonLen + 3) &^ 3
	}
	raw, ok := allocCeil(d, "asar", jsonLen, "asar-too-big")
	if !ok {
		return
	}
	if _, err := io.ReadFull(f, raw); err != nil {
		d.Notes = append(d.Notes, "asar: truncated header JSON: "+err.Error())
		return
	}
	var root asarNode
	if err := json.Unmarshal(raw, &root); err != nil {
		d.Notes = append(d.Notes, "asar: malformed header JSON: "+err.Error())
		return
	}

	s := asarScan{runtime: map[string]bool{}, caps: map[string]bool{}, base: base, limit: d.FileSize}
	s.walk(&root, "")
	for _, o := range s.overruns[:min(len(s.overruns), maxAsarOverruns)] {
		d.Notes = append(d.Notes, "asar: member "+o)
	}
	if s.overrunN > maxAsarOverruns {
		d.Notes = append(d.Notes, fmt.Sprintf("asar: +%d more member overruns not listed",
			s.overrunN-maxAsarOverruns))
	}
	d.AsarFiles = s.files
	if s.links > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("links: %d", s.links))
	}
	if s.unpacked > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("unpacked files: %d (bodies outside archive)", s.unpacked))
		s.caps["asar-unpacked"] = true
	}
	if len(s.runtime) > 0 {
		d.Notes = append(d.Notes, "electron runtime files: "+strings.Join(sortedKeys(s.runtime), ", "))
		// No "fuses" capability here: fuses live in the Electron binary
		// itself (wire sentinel outside the asar), not in these payload
		// files. Claiming them would fabricate a capability no reader
		// verified — inspect_electron_fuses answers bad_arg on asar for
		// exactly this reason (fix40 item 107).
	}
	if mods := topLevelModules(&root); mods > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("node_modules: %d packages", mods))
	}

	readAsarMain(f, base, &root, d)
	readAsarPreload(f, base, &root, d, &s)
	scanAsarScripts(f, base, &root, d)
	countUnpackedNative(path, d, &s)

	// Nothing conditional fired: still name the artifacts that each answer a
	// different question, so an asar digest always carries a next step.
	if len(d.ElectronIPC) == 0 && len(d.SourceMaps) == 0 {
		deepNote(d, "read the asar member paths next: the preload script, main entry, renderer bundles and unpacked native modules each answer a different question")
	}

	for _, c := range sortedKeys(s.caps) {
		if !containsStr(d.Capabilities, c) {
			d.Capabilities = append(d.Capabilities, c)
		}
	}
	AddUpdaterCapsFrom(d, s.paths)
	d.Notes = append(d.Notes, "header-only; one member at a time via --extract PATH")
}

func (s *asarScan) walk(n *asarNode, prefix string) {
	for name, child := range n.Files {
		if child == nil {
			continue
		}
		p := prefix + name
		if child.Files != nil {
			s.walk(child, p+"/")
			continue
		}
		if child.Link != "" {
			s.links++
			continue
		}
		// A body declared past EOF is a header lie: name it once and leave it out
		// of the file count instead of counting a member that cannot be read.
		if !child.Unpacked && s.limit > 0 && child.Size > 0 {
			if off, err := strconv.ParseInt(child.Offset, 10, 64); err == nil && off >= 0 {
				if end := s.base + off + child.Size; end > s.limit {
					s.overrunN++
					if len(s.overruns) < maxAsarOverruns {
						s.overruns = append(s.overruns, fmt.Sprintf(
							"%s offset+size %d exceeds file %d by %d, not counted",
							p, end, s.limit, end-s.limit))
					}
					continue
				}
			}
		}
		s.files++
		if len(s.paths) < maxAsarFiles {
			s.paths = append(s.paths, p)
		}
		if child.Unpacked {
			s.unpacked++
		}
		if electronRuntime[name] {
			s.runtime[name] = true
		}
		s.capFor(p)
	}
}

// capFor judges by path only; bodies are never opened.
func (s *asarScan) capFor(p string) {
	low := strings.ToLower(p)
	switch {
	case strings.HasSuffix(low, ".node"):
		s.caps["native-modules"] = true
	case strings.HasSuffix(low, ".wasm"):
		s.caps["wasm"] = true
	case strings.HasSuffix(low, ".sqlite"), strings.HasSuffix(low, ".db"):
		s.caps["sqlite"] = true
	}
	// any package segment named electron counts, incl. scoped: @sentry/electron
	if strings.Contains(low, "/electron/") {
		s.caps["electron"] = true
	}
	if strings.Contains(low, "squirrel") || strings.Contains(low, "autoupdater") || strings.Contains(low, "update") {
		s.caps["updater"] = true
	}
}

// topLevelModules counts node_modules/<name>/package.json, including @scope/name.
func topLevelModules(root *asarNode) int {
	nm := root.Files["node_modules"]
	if nm == nil {
		return 0
	}
	count := 0
	for name, child := range nm.Files {
		if child == nil || child.Files == nil {
			continue
		}
		if strings.HasPrefix(name, "@") {
			for _, scoped := range child.Files {
				if scoped != nil && scoped.Files["package.json"] != nil {
					count++
				}
			}
			continue
		}
		if child.Files["package.json"] != nil {
			count++
		}
	}
	return count
}

// countUnpackedNative inventories the app.asar.unpacked sibling: native addons
// live there because .node bodies cannot be loaded from inside the archive.
func countUnpackedNative(asarPath string, d *Digest, s *asarScan) {
	dir := asarPath + ".unpacked"
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return
	}
	var addons, files int
	_ = filepath.WalkDir(dir, func(_ string, e fs.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return nil
		}
		files++
		if strings.HasSuffix(strings.ToLower(e.Name()), ".node") {
			addons++
		}
		if files >= maxUnpackedEntries {
			// shortcut: counts saturate on huge trees; raise the cap if that ever shows up.
			return fs.SkipAll
		}
		return nil
	})
	d.UnpackedNode = addons
	d.Notes = append(d.Notes, fmt.Sprintf("app.asar.unpacked: %d native addons, %d files", addons, files))
	if addons > 0 {
		s.caps["asar-unpacked-native"] = true
	}
}

// readAsarMain pulls only the root package.json body, bounded by maxAsarPkgJSON.
func readAsarMain(f *os.File, base int64, root *asarNode, d *Digest) {
	n := root.Files["package.json"]
	if n == nil {
		d.Notes = append(d.Notes, "no root package.json in header")
		return
	}
	buf, ok := readAsarBody(f, base, n, maxAsarPkgJSON, "package.json", d)
	if !ok {
		return
	}
	var pkg struct {
		Main             string            `json:"main"`
		Name             string            `json:"name"`
		ProductName      string            `json:"productName"`
		Version          string            `json:"version"`
		DevDependencies  map[string]string `json:"devDependencies"`
		Dependencies     map[string]string `json:"dependencies"`
		NodeIntegration  *bool             `json:"nodeIntegration"`
		ContextIsolation *bool             `json:"contextIsolation"`
		Sandbox          *bool             `json:"sandbox"`
		Exports          json.RawMessage   `json:"exports"`
	}
	if err := json.Unmarshal(buf, &pkg); err != nil {
		d.Notes = append(d.Notes, "package.json not valid JSON: "+err.Error())
		return
	}
	// Declared dependencies name the updater even when node_modules is not vendored.
	declared := make([]string, 0, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for name := range pkg.Dependencies {
		declared = append(declared, name)
	}
	for name := range pkg.DevDependencies {
		declared = append(declared, name)
	}
	AddUpdaterCapsFrom(d, declared)
	d.AsarProduct = pkg.ProductName
	if d.AsarProduct == "" {
		d.AsarProduct = pkg.Name
	}
	d.AsarVersion = pkg.Version
	d.ElectronVer = pkg.DevDependencies["electron"]
	if d.ElectronVer == "" {
		d.ElectronVer = pkg.Dependencies["electron"]
	}
	d.Notes = append(d.Notes, "isolation: "+isolationNotes(pkg.NodeIntegration, pkg.ContextIsolation, pkg.Sandbox))
	if pkg.Main != "" {
		d.AsarMain = pkg.Main
		if rel, node := resolveMain(root, pkg.Main); node != nil {
			d.Notes = append(d.Notes, fmt.Sprintf("main entry: %s (%d bytes)", rel, node.Size))
		} else {
			d.Notes = append(d.Notes, fmt.Sprintf("main entry: %s missing from tree", rel))
		}
		return
	}
	if len(pkg.Exports) > 0 {
		d.Notes = append(d.Notes, "no main; package.json has exports")
	}
}

// resolveMain maps package.json "main" to a header entry, trying the usual
// implicit paths (.js, index.js) without touching any body.
func resolveMain(root *asarNode, main string) (string, *asarNode) {
	rel := strings.TrimPrefix(strings.TrimPrefix(main, "./"), "/")
	for _, cand := range []string{rel, rel + ".js", rel + "/index.js"} {
		if n := lookupNode(root, cand); n != nil && n.Files == nil {
			return cand, n
		}
	}
	return rel, nil
}

// isolationNotes reports only the flags actually present: package.json is the
// wrong place for them, so absent means unknown, not a default.
func isolationNotes(nodeIntegration, contextIsolation, sandbox *bool) string {
	flag := func(label string, v *bool) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%s=%t ", label, *v)
	}
	out := flag("nodeIntegration", nodeIntegration) + flag("contextIsolation", contextIsolation) + flag("sandbox", sandbox)
	if out == "" {
		return "unknown (nodeIntegration/contextIsolation/sandbox absent from package.json)"
	}
	return strings.TrimSpace(out) + " (from package.json; runtime may override)"
}

// readAsarPreload picks the shallowest non-node_modules preload entry, reads at
// most maxAsarPreload of its body, and names every exposeInMainWorld context.
func readAsarPreload(f *os.File, base int64, root *asarNode, d *Digest, s *asarScan) {
	rel, n := findPreload(root)
	if n == nil {
		d.Notes = append(d.Notes, "preload entry: none found in header")
		return
	}
	buf, ok := readAsarBody(f, base, n, maxAsarPreload, rel, d)
	if !ok || len(buf) == 0 {
		d.Notes = append(d.Notes, "preload body empty: "+rel)
		return
	}
	calls := strings.Count(string(buf), "exposeInMainWorld(")
	var names []string
	for _, m := range bridgeRe.FindAllSubmatch(buf, -1) {
		name := string(m[1]) + string(m[2]) + string(m[3])
		if name == "" || containsStr(names, name) {
			continue
		}
		if len(names) == maxBridgeNames {
			d.Notes = append(d.Notes, fmt.Sprintf("preload bridges capped at %d names", maxBridgeNames))
			break
		}
		names = append(names, name)
	}
	d.Notes = append(d.Notes, fmt.Sprintf("preload: %s (%d exposeInMainWorld, %d named)", rel, calls, len(names)))
	for _, name := range names {
		s.caps["preload-bridge:"+name] = true
	}
}

// findPreload prefers root-level preloads over vendor copies: Studio.app has
// dist/preload/preload.js and a dozen node_modules/*/preload.js decoys.
func findPreload(root *asarNode) (string, *asarNode) {
	var best string
	var bestNode *asarNode
	var walk func(n *asarNode, prefix string)
	walk = func(n *asarNode, prefix string) {
		for name, child := range n.Files {
			if child == nil {
				continue
			}
			p := prefix + name
			if child.Files != nil {
				walk(child, p+"/")
				continue
			}
			if child.Link != "" || !isPreloadName(name) {
				continue
			}
			if bestNode == nil || preloadRank(p) < preloadRank(best) ||
				(preloadRank(p) == preloadRank(best) && p < best) {
				best, bestNode = p, child
			}
		}
	}
	walk(root, "")
	return best, bestNode
}

func isPreloadName(name string) bool {
	low := strings.ToLower(name)
	if !strings.HasPrefix(low, "preload.") {
		return false
	}
	switch path.Ext(low) {
	case ".js", ".cjs", ".mjs":
		return true
	}
	return false
}

// preloadRank: vendor copies last, then shallower paths first.
func preloadRank(p string) int {
	rank := strings.Count(p, "/")
	if strings.HasPrefix(p, "node_modules/") {
		rank += 32
	}
	return rank
}

// readAsarBody reads one header entry's body, bounded and offset-checked; a
// zero-size entry returns no bytes instead of touching the file.
func readAsarBody(f *os.File, base int64, n *asarNode, limit int64, label string, d *Digest) ([]byte, bool) {
	off, err := strconv.ParseInt(n.Offset, 10, 64)
	if n.Offset == "" || err != nil || off < 0 {
		// ponytail: pre-v3 archives store no offsets; a tree-order walk would be needed. Upgrade if such targets show up.
		d.Notes = append(d.Notes, label+": no offset in header")
		return nil, false
	}
	size := n.Size
	if size <= 0 {
		return nil, true
	}
	if size > limit {
		size = limit
		d.Notes = append(d.Notes, fmt.Sprintf("%s truncated at %d KB", label, limit>>10))
	}
	// A body is not the header: it is already clamped to the extract caps, so it
	// gets its own ceiling instead of the 64 MiB header one.
	buf, ok := allocCeil(d, "asar-body", size, "asar-too-big")
	if !ok {
		return nil, false
	}
	if _, err := f.ReadAt(buf, base+off); err != nil {
		d.Notes = append(d.Notes, label+" body unreadable: "+err.Error())
		return nil, false
	}
	return buf, true
}

func lookupNode(root *asarNode, rel string) *asarNode {
	n := root
	for part := range strings.SplitSeq(rel, "/") {
		if n == nil {
			return nil
		}
		n = n.Files[part]
	}
	return n
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- Electron IPC channels and source maps ---

// ipcLit matches one quoted channel argument: "ch", 'ch' or `ch`.
const ipcLit = `(?:"([^"\n]{1,200})"|'([^'\n]{1,200})'|` + "`" + `([^` + "`" + `\n]{1,200})` + "`" + `)`

var (
	// ipcCallRe matches the Electron IPC APIs with a literal channel argument.
	ipcCallRe = regexp.MustCompile(`(?:ipcRenderer|ipcMain|webContents)\s*\.\s*(?:invokeSync|invoke|sendSync|send|handleOnce|handle|on|once)\s*\(\s*` + ipcLit)
	// sourceMapRe / sourceMapBlockRe match the source map trailer of a bundle.
	sourceMapRe      = regexp.MustCompile(`//[#@][ \t]*sourceMappingURL=([^\s'"]+)`)
	sourceMapBlockRe = regexp.MustCompile(`/\*[#@][ \t]*sourceMappingURL=([^\s*]+)`)
)

// asarMember is one packed file in the header tree.
type asarMember struct {
	rel  string
	node *asarNode
}

// asarScriptMembers lists the packed files in scan order: app code first,
// vendor copies last, path order inside each group.
func asarScriptMembers(root *asarNode) []asarMember {
	var out []asarMember
	var walk func(n *asarNode, prefix string)
	walk = func(n *asarNode, prefix string) {
		for name, child := range n.Files {
			if child == nil {
				continue
			}
			p := prefix + name
			if child.Files != nil {
				walk(child, p+"/")
				continue
			}
			if child.Link != "" {
				continue
			}
			out = append(out, asarMember{rel: p, node: child})
		}
	}
	walk(root, "")
	sort.Slice(out, func(i, j int) bool {
		vi := strings.Contains(out[i].rel, "node_modules/")
		vj := strings.Contains(out[j].rel, "node_modules/")
		if vi != vj {
			return !vi
		}
		return out[i].rel < out[j].rel
	})
	return out
}

// isScriptPath reports whether a packed file is JavaScript or TypeScript.
func isScriptPath(rel string) bool {
	low := strings.ToLower(rel)
	for _, ext := range []string{".js", ".cjs", ".mjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"} {
		if strings.HasSuffix(low, ext) {
			return true
		}
	}
	return false
}

// readAsarSlice reads one header entry's body without touching the digest: the
// script scan reads many members and must not add a note per file.
func readAsarSlice(f *os.File, base int64, n *asarNode, limit int64) ([]byte, bool) {
	off, err := strconv.ParseInt(n.Offset, 10, 64)
	if n.Offset == "" || err != nil || off < 0 {
		return nil, false
	}
	size := n.Size
	if size <= 0 {
		return nil, false
	}
	if size > limit {
		size = limit
	}
	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, base+off); err != nil {
		return nil, false
	}
	return buf, true
}

// readAsarTail reads the last limit bytes of a packed file. A big bundle puts
// its source map trailer at the end, past the head slice the scan reads.
func readAsarTail(f *os.File, base int64, n *asarNode, limit int64) ([]byte, bool) {
	off, err := strconv.ParseInt(n.Offset, 10, 64)
	if n.Offset == "" || err != nil || off < 0 || int64(n.Size) <= limit {
		return nil, false
	}
	buf := make([]byte, limit)
	if _, err := f.ReadAt(buf, base+off+int64(n.Size)-limit); err != nil {
		return nil, false
	}
	return buf, true
}

// collectIPCChannels picks the literal channel names out of one script body.
func collectIPCChannels(body []byte, out map[string]bool) {
	for _, m := range ipcCallRe.FindAllSubmatch(body, -1) {
		for _, g := range m[1:] {
			if len(g) == 0 {
				continue
			}
			ch := string(g)
			if strings.Contains(ch, "${") {
				continue // template literal, not a literal channel
			}
			out[ch] = true
		}
	}
}

// collectSourceMaps picks the source map trailer of one script body. script is
// the member path the ref sits in, so a relative ref can be resolved against it.
func collectSourceMaps(body []byte, script string, packed, out map[string]bool) {
	for _, re := range []*regexp.Regexp{sourceMapRe, sourceMapBlockRe} {
		for _, m := range re.FindAllSubmatch(body, -1) {
			ref := string(m[1])
			if ref == "" || strings.HasPrefix(ref, "data:") {
				continue
			}
			out[sourceMapEntry(script, ref, packed)] = true
		}
	}
}

// sourceMapEntry marks a trailer that resolves to no packed map: the reader
// would otherwise spend an extract call on a file the archive does not hold.
func sourceMapEntry(script, ref string, packed map[string]bool) string {
	if strings.Contains(ref, "://") || strings.HasPrefix(ref, "../") || strings.HasPrefix(ref, "//") {
		return ref // remote or escaping ref: no local member to check
	}
	if packed[path.Clean(ref)] || packed[path.Clean(path.Join(path.Dir(script), ref))] {
		return ref
	}
	return ref + " (missing)"
}

// scanAsarScripts collects the IPC channel names and the source map references
// of the packed scripts. Bodies are read in bounded slices (1 MiB per file,
// 16 MiB per archive) and the output is sorted, so the digest is stable.
func scanAsarScripts(f *os.File, base int64, root *asarNode, d *Digest) {
	ipc := map[string]bool{}
	maps := map[string]bool{}
	members := asarScriptMembers(root)
	packed := map[string]bool{}
	for _, m := range members {
		if strings.HasSuffix(strings.ToLower(m.rel), ".js.map") {
			rel := path.Clean(m.rel)
			packed[rel] = true
			maps[rel] = true
		}
	}
	budget := int64(maxIPCScanTotal)
	for _, m := range members {
		if !isScriptPath(m.rel) || budget <= 0 {
			continue
		}
		body, ok := readAsarSlice(f, base, m.node, maxIPCScanFile)
		if !ok {
			continue
		}
		if int64(len(body)) > budget {
			body = body[:budget]
		}
		budget -= int64(len(body))
		if !looksText(body) {
			continue
		}
		collectIPCChannels(body, ipc)
		collectSourceMaps(body, m.rel, packed, maps)
		if tail, ok := readAsarTail(f, base, m.node, maxIPCScanFile); ok {
			if int64(len(tail)) > budget {
				tail = tail[:budget]
			}
			budget -= int64(len(tail))
			collectSourceMaps(tail, m.rel, packed, maps)
		}
	}

	if len(ipc) > 0 {
		names := sortedKeys(ipc)
		if len(names) > maxIPCChannels {
			names = names[:maxIPCChannels]
			d.Notes = append(d.Notes, fmt.Sprintf("electron ipc: %d channels found, %d reported", len(ipc), maxIPCChannels))
		}
		d.ElectronIPC = names
		deepNote(d, "electron ipc channels: "+listSample(names, 12)+
			"; trace every renderer->main channel through the preload bridge and its main-process handler to recover the request/response contract")
		deepNote(d, "electron main-process messages travel as length-prefixed json frames; decode a frame to recover the payload fields behind a channel")
	}
	if len(maps) > 0 {
		names := sortedKeys(maps)
		if len(names) > maxSourceMaps {
			names = names[:maxSourceMaps]
			d.Notes = append(d.Notes, fmt.Sprintf("source maps: %d references found, %d reported", len(maps), maxSourceMaps))
		}
		d.SourceMaps = names
		deepNote(d, "source map references: "+listSample(names, 8)+
			"; original sources may be recoverable from the map file, the generated file alone hides the original paths and names")
	}
}

// listSample renders at most n names for a note and counts the remainder.
func listSample(names []string, n int) string {
	if len(names) <= n {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(names[:n], ", "), len(names)-n)
}

func containsStr(list []string, s string) bool {
	return slices.Contains(list, s)
}
