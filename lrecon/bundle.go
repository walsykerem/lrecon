package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// inspectBundle answers the only question a directory target raises: which
// artifact inside it should the agent open. macOS .app layout only; other
// directories stay opaque (walk them with ls/find).
func inspectBundle(dir string, d *Digest) {
	d.Kind = "app"
	base := strings.TrimSuffix(filepath.Base(dir), ".app")

	if asar := filepath.Join(dir, "Contents", "Resources", "app.asar"); isFile(asar) {
		d.Notes = append(d.Notes, "app bundle: asar at "+asar)
		inspectAsar(asar, d)
		// The .app is what the reader opens, so it owns format; asar keeps every
		// field it filled and only loses the format claim.
		if d.AsarFiles > 0 || d.AsarMain != "" {
			d.Format = "electron"
		}
		deepNote(d, ".app is a wrapper, not the artifact: the asar or binary inside it is; the wrapper only tells you which one to open")
		return
	}
	if exe := filepath.Join(dir, "Contents", "MacOS", base); isFile(exe) {
		d.Notes = append(d.Notes, "app bundle: binary at "+exe)
		d.Kind, d.Format = nativeKind(exe)
		inspectNative(exe, d)
		deepNote(d, ".app is a wrapper, not the artifact: the Mach-O in Contents/MacOS is; the wrapper only tells you which one to open")
		return
	}
	// The executable name is not always the bundle stem: Visual Studio Code.app
	// keeps Contents/MacOS/Code, and only the plist names it.
	if name := bundleExecutable(dir); name != "" {
		exe := filepath.Join(dir, "Contents", "MacOS", name)
		if isFile(exe) {
			d.Notes = append(d.Notes, "app bundle: binary at "+exe)
			d.Kind, d.Format = nativeKind(exe)
			inspectNative(exe, d)
			deepNote(d, ".app is a wrapper, not the artifact: the Mach-O in Contents/MacOS is; the wrapper only tells you which one to open")
			return
		}
	}
	d.Kind, d.Format = "directory", "directory"
	deepNote(d, "a directory is not a bundle: list it and pick one artifact inside before asking what it is")
}

func isFile(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// nativeKind sniffs just enough magic for inspectNative's internal switch.
// It also answers the format question there: machoDigest needs "fat" to pick
// OpenFat, and every .app here is a Universal binary in practice.
func nativeKind(p string) (kind, format string) {
	f, err := os.Open(p)
	if err != nil {
		return "unknown", ""
	}
	defer f.Close()
	var h [4]byte
	if _, err := f.Read(h[:]); err != nil {
		return "unknown", ""
	}
	switch {
	case isFatMachO(h[:]):
		return "macho", "fat"
	case isMachO(h[:]):
		return "macho", "thin"
	case string(h[:]) == "\x7fELF":
		return "elf", ""
	case string(h[:2]) == "MZ":
		return "pe", ""
	}
	return "unknown", ""
}

var xmlBundleExec = regexp.MustCompile(`(?s)<key>\s*CFBundleExecutable\s*</key>\s*<string>([^<]{1,200})</string>`)

// bundleExecutable reads CFBundleExecutable from Contents/Info.plist. The
// executable name is not always the bundle stem (Visual Studio Code.app keeps
// Contents/MacOS/Code), so the plist is the only reliable source.
func bundleExecutable(dir string) string {
	b, err := os.ReadFile(filepath.Join(dir, "Contents", "Info.plist"))
	if err != nil || len(b) == 0 {
		return ""
	}
	var name string
	if bytes.HasPrefix(b, []byte("bplist00")) {
		p, err := openBplist(b)
		if err != nil {
			return ""
		}
		keys, vals, ok, err := p.entry(p.top)
		if err != nil || !ok {
			return ""
		}
		for i, k := range keys {
			if s, _ := p.str(k); s == "CFBundleExecutable" {
				name, _ = p.str(vals[i])
				break
			}
		}
	} else if m := xmlBundleExec.FindSubmatch(b); len(m) == 2 {
		name = string(m[1])
	}
	name = strings.TrimSpace(name)
	// A plist is untrusted input for a path join: only a bare file name is used.
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\`) {
		return ""
	}
	return name
}
