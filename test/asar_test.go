package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// writeAsarArchive builds a real asar layout: 16-byte preamble, JSON header,
// packed bodies in sorted-path order, offsets relative to the body base.
func writeAsarArchive(t *testing.T, dir, name string, files map[string][]byte) string {
	t.Helper()
	paths := make([]string, 0, len(files))
	total := 0
	for p, b := range files {
		paths = append(paths, p)
		total += len(b)
	}
	sort.Strings(paths)
	body := make([]byte, 0, total)
	offs := make(map[string]int, len(paths))
	for _, p := range paths {
		offs[p] = len(body)
		body = append(body, files[p]...)
	}

	type node struct {
		Files  map[string]*node `json:"files,omitempty"`
		Size   int              `json:"size,omitempty"`
		Offset string           `json:"offset,omitempty"`
	}
	root := &node{Files: map[string]*node{}}
	for _, p := range paths {
		parts := strings.Split(p, "/")
		cur := root
		for _, part := range parts[:len(parts)-1] {
			if cur.Files[part] == nil {
				cur.Files[part] = &node{Files: map[string]*node{}}
			}
			cur = cur.Files[part]
		}
		cur.Files[parts[len(parts)-1]] = &node{Size: len(files[p]), Offset: strconv.Itoa(offs[p])}
	}
	hdr, err := json.Marshal(root)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}

	buf := make([]byte, 16, 16+len(hdr)+len(body))
	binary.LittleEndian.PutUint32(buf[0:4], 4)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(8+len(hdr)))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(4+len(hdr)))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(hdr)))
	buf = append(buf, hdr...)
	buf = append(buf, body...)

	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, buf, 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

func probeAsar(t *testing.T, files map[string][]byte) Digest {
	t.Helper()
	p := writeAsarArchive(t, t.TempDir(), "app.asar", files)
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "asar" {
		t.Fatalf("kind = %q, want asar", d.Kind)
	}
	return d
}

func TestAsarHeaderOnlyFields(t *testing.T) {
	pkg := `{"name":"studio-dev","productName":"Studio","version":"1.7.2",` +
		`"main":"dist/main.js","devDependencies":{"electron":"^33.2.1"}}`
	preload := "const { contextBridge } = require('electron')\n" +
		"contextBridge.exposeInMainWorld('studio', {})\n" +
		"contextBridge.exposeInMainWorld(\"api2\", {})\n" +
		"exposeInMainWorld(`third`, {})\n"
	files := map[string][]byte{
		"package.json":                   []byte(pkg),
		"dist/main.js":                   []byte("require('./preload/preload.js')\n"),
		"dist/preload/preload.js":        []byte(preload),
		"node_modules/semver/preload.js": []byte("contextBridge.exposeInMainWorld('decoy', {})\n"),
		"icudtl.dat":                     make([]byte, 8),
		"empty.js":                       {},
	}
	d := probeAsar(t, files)

	if d.AsarFiles != len(files) {
		t.Fatalf("asar_files = %d, want %d", d.AsarFiles, len(files))
	}
	if d.AsarMain != "dist/main.js" {
		t.Fatalf("asar_main = %q, want dist/main.js", d.AsarMain)
	}
	if d.AsarProduct != "Studio" || d.AsarVersion != "1.7.2" {
		t.Fatalf("product/version = %q/%q", d.AsarProduct, d.AsarVersion)
	}
	if d.ElectronVer != "^33.2.1" {
		t.Fatalf("electron = %q, want ^33.2.1 from devDependencies", d.ElectronVer)
	}
	// fuses live in the Electron binary, not in the asar payload: a
	// runtime file alone must NOT claim the "fuses" capability
	// (inspect_electron_fuses answers bad_arg on the archive).
	if containsStr(d.Capabilities, "fuses") {
		t.Fatalf("capability %q claimed from runtime files: %v", "fuses", d.Capabilities)
	}
	for _, want := range []string{"preload-bridge:studio", "preload-bridge:api2", "preload-bridge:third"} {
		if !containsStr(d.Capabilities, want) {
			t.Fatalf("capability %q missing from %v", want, d.Capabilities)
		}
	}
	if containsStr(d.Capabilities, "preload-bridge:decoy") {
		t.Fatalf("node_modules preload.js won the preload pick: %v", d.Capabilities)
	}
	if !notesContain(d, "main entry: dist/main.js") {
		t.Fatalf("main entry note missing: %v", d.Notes)
	}
	if !notesContain(d, "isolation: unknown") {
		t.Fatalf("isolation note missing: %v", d.Notes)
	}
	text := d.Text()
	if !strings.Contains(text, "asar_product: Studio\n") || !strings.Contains(text, "electron: ^33.2.1\n") {
		t.Fatalf("text missing product/electron lines:\n%s", text)
	}
}

func TestAsarUnpackedNativeAddons(t *testing.T) {
	dir := t.TempDir()
	p := writeAsarArchive(t, dir, "app.asar", map[string][]byte{
		"package.json": []byte(`{"main":"index.js"}`),
		"index.js":     []byte("x=1\n"),
	})
	for _, rel := range []string{"a/build/Release/a.node", "b/x.node", "c/README.txt"} {
		full := filepath.Join(p+".unpacked", filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("native"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.UnpackedNode != 2 {
		t.Fatalf("asar_unpacked_native = %d, want 2", d.UnpackedNode)
	}
	if !containsStr(d.Capabilities, "asar-unpacked-native") {
		t.Fatalf("capability asar-unpacked-native missing: %v", d.Capabilities)
	}
	if !strings.Contains(d.Text(), "asar_unpacked_native: 2\n") {
		t.Fatalf("text missing unpacked line:\n%s", d.Text())
	}
}

// A zero-byte body must be reported, not read: no panic, no bogus JSON error
// crash-path, and no bridge names invented from an empty preload.
func TestAsarZeroByteBodies(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"package.json": {},
		"preload.js":   {},
		"index.js":     []byte("x=1\n"),
	})
	if d.AsarFiles != 3 {
		t.Fatalf("asar_files = %d, want 3", d.AsarFiles)
	}
	if !notesContain(d, "preload body empty") {
		t.Fatalf("empty preload note missing: %v", d.Notes)
	}
	for _, c := range d.Capabilities {
		if strings.HasPrefix(c, "preload-bridge:") {
			t.Fatalf("bridge capability %q from empty body", c)
		}
	}
	if d.AsarMain != "" {
		t.Fatalf("asar_main = %q, want empty for zero-byte package.json", d.AsarMain)
	}
}

// A header entry pointing past EOF must not panic or read outside the file.
func TestAsarBogusOffset(t *testing.T) {
	dir := t.TempDir()
	p := writeAsarArchive(t, dir, "app.asar", map[string][]byte{"index.js": []byte("x=1\n")})
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	bad := strings.Replace(string(b), `"offset":"0"`, `"offset":"99999999"`, 1)
	if err := os.WriteFile(p, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := Probe(p)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if d.Kind != "asar" {
		t.Fatalf("kind = %q, want asar", d.Kind)
	}
}

// A trailer with no matching member is marked, so --extract is not spent on a
// file the archive does not hold.
func TestSourceMapMissingMember(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"package.json": []byte(`{"name":"app","main":"dist/a.js"}`),
		"dist/a.js":    []byte("console.log(1)\n//# sourceMappingURL=a.js.map\n"),
	})
	if !containsStr(d.SourceMaps, "a.js.map (missing)") {
		t.Fatalf("missing marker absent from %v", d.SourceMaps)
	}
}

func TestSourceMapPresentMemberNotMarked(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"package.json":  []byte(`{"name":"app","main":"dist/a.js"}`),
		"dist/a.js":     []byte("console.log(1)\n//# sourceMappingURL=a.js.map\n"),
		"dist/a.js.map": []byte(`{"version":3,"sources":["src/a.ts"]}`),
	})
	for _, m := range d.SourceMaps {
		if strings.Contains(m, "(missing)") {
			t.Fatalf("present map marked missing: %v", d.SourceMaps)
		}
	}
	if !containsStr(d.SourceMaps, "a.js.map") {
		t.Fatalf("reference absent from %v", d.SourceMaps)
	}
}

func notesContain(d Digest, want string) bool {
	for _, n := range d.Notes {
		if strings.Contains(n, want) {
			return true
		}
	}
	return false
}

// The IPC channel names are literal strings in the packed JavaScript, so the
// renderer->main contract is listable without running the app.
func TestElectronChannelScan(t *testing.T) {
	js := "const {ipcRenderer, ipcMain} = require('electron')\n" +
		"ipcRenderer.invoke('do-thing', null)\n" +
		"ipcRenderer.send(\"other-thing\")\n" +
		"ipcMain.handle('third-thing')\n" +
		"ipcMain.on(\"fourth-thing\")\n" +
		"webContents.send(`fifth-thing`)\n" +
		"ipcRenderer.invokeSync('sixth-thing')\n"
	d := probeAsar(t, map[string][]byte{
		"package.json": []byte(`{"name":"app","main":"main.js"}`),
		"main.js":      []byte(js),
	})
	for _, want := range []string{"do-thing", "other-thing", "third-thing", "fourth-thing", "fifth-thing", "sixth-thing"} {
		if !containsStr(d.ElectronIPC, want) {
			t.Fatalf("channel %q missing from %v", want, d.ElectronIPC)
		}
	}
	if len(d.ElectronIPC) != 6 {
		t.Fatalf("electron_ipc = %v, want 6 channels", d.ElectronIPC)
	}
	if !notesContain(d, "electron ipc channels:") {
		t.Fatalf("ipc note missing: %v", d.Notes)
	}
	if !notesContain(d, "length-prefixed json frames") {
		t.Fatalf("framing note missing: %v", d.Notes)
	}
	emAssertNoToolNames(t, d)
}

// The source map trailer and the packed map file are both reported, so the
// original sources stay recoverable.
func TestElectronSourceRefScan(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"package.json":     []byte(`{"name":"app","main":"dist/main.js"}`),
		"dist/main.js":     []byte("console.log(1)\n//# sourceMappingURL=main.js.map\n"),
		"dist/main.js.map": []byte(`{"version":3,"sources":["src/main.ts"]}`),
	})
	if !containsStr(d.SourceMaps, "main.js.map") {
		t.Fatalf("map trailer missing from %v", d.SourceMaps)
	}
	if !containsStr(d.SourceMaps, "dist/main.js.map") {
		t.Fatalf("packed map file missing from %v", d.SourceMaps)
	}
	if !notesContain(d, "source map references:") {
		t.Fatalf("source map note missing: %v", d.Notes)
	}
	if !notesContain(d, "original sources may be recoverable") {
		t.Fatalf("source map recoverability note missing: %v", d.Notes)
	}
	emAssertNoToolNames(t, d)
}

// Updater frameworks are named by the member paths inside the archive, not by
// package.json deps: the path is the only place the package name exists.
func TestAsarUpdaterMemberNames(t *testing.T) {
	d := probeAsar(t, map[string][]byte{
		"package.json": []byte(`{"name":"app","main":"main.js"}`),
		"main.js":      []byte("require('electron-updater')\n"),
		"node_modules/electron-updater/package.json": []byte(`{"name":"electron-updater"}`),
	})
	if !containsStr(d.Capabilities, "updater:electron-updater") {
		t.Fatalf("named updater capability missing: %v", d.Capabilities)
	}
}

// writeRawAsar writes an asar whose member sizes/offsets are taken verbatim, so
// a test can declare a member that runs past the end of the file.
func writeRawAsar(t *testing.T, hdr, body string) string {
	t.Helper()
	buf := make([]byte, 16)
	binary.LittleEndian.PutUint32(buf[0:4], 4)
	binary.LittleEndian.PutUint32(buf[4:8], uint32(8+len(hdr)))
	binary.LittleEndian.PutUint32(buf[8:12], uint32(4+len(hdr)))
	binary.LittleEndian.PutUint32(buf[12:16], uint32(len(hdr)))
	buf = append(buf, hdr...)
	buf = append(buf, body...)
	return writeTemp(t, "raw.asar", buf)
}

// TestAsarOverrunMemberNotCounted: a member whose offset+size lands past EOF is
// named in a note and left out of asar_files instead of silently counted.
func TestAsarOverrunMemberNotCounted(t *testing.T) {
	cases := []struct {
		name  string
		hdr   string
		body  string
		files int
		want  string
	}{
		{
			name:  "overrun",
			hdr:   `{"files":{"a.txt":{"size":4,"offset":"0"},"ghost.bin":{"size":64,"offset":"1048576"}}}`,
			body:  "aaaa",
			files: 1,
			want:  "asar: member ghost.bin offset+size",
		},
		{
			name:  "fits",
			hdr:   `{"files":{"a.txt":{"size":4,"offset":"0"},"ghost.bin":{"size":4,"offset":"4"}}}`,
			body:  "aaaabbbb",
			files: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := probeFixture(t, writeRawAsar(t, tc.hdr, tc.body))
			if d.AsarFiles != tc.files {
				t.Fatalf("asar_files = %d, want %d (notes %v)", d.AsarFiles, tc.files, d.Notes)
			}
			if tc.want != "" && !notesContain(d, tc.want) {
				t.Fatalf("notes = %v, want %q", d.Notes, tc.want)
			}
			if tc.want == "" && notesContain(d, "exceeds file") {
				t.Fatalf("notes = %v, unexpected overrun", d.Notes)
			}
		})
	}
}

// A body shorter than its header size is a truncated archive, not a file of
// zero padding: extraction must fail instead of writing invented bytes.
func TestAsarShortBodyRefused(t *testing.T) {
	data := []byte("0123456789abcdef0123456789abcdef")
	p := writeAsarArchive(t, t.TempDir(), "short.asar", map[string][]byte{"a.txt": data})
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := os.Truncate(p, fi.Size()-int64(len(data))+8); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	out := t.TempDir()
	var d Digest
	err = ExtractPayloadTo(p, "a.txt", out, &d)
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("err = %v, want an unreadable-body refusal", err)
	}
	if _, err := os.Stat(filepath.Join(out, "a.txt")); err == nil {
		t.Fatal("truncated body was written to disk")
	}
}
