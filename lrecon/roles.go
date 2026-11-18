package main

import (
	"fmt"
	"sort"
	"strings"
)

// roleRules maps a lowercase substring of a dep/dylib/import name to a short role.
// First match wins, so put narrow patterns before broad ones.
var roleRules = []struct{ pat, role string }{
	{"libcrypto", "crypto"},
	{"ssl", "crypto"},
	{"sqlite", "storage"},
	{"napi_", "node-addon"},
	{"ptrace", "debugger"},
	{"task_for_pid", "debugger"},
	{"socket", "network"},
	{"connect", "network"},
	{"sec_", "codesign"},
	{"sectrust", "codesign"},
	{"seckey", "codesign"},
	{"seccode", "codesign"},
	{"security", "codesign"},
	{"frida", "instrumentation"},
	{"inject", "instrumentation"},
	{"curl", "http"},
	{"zlib", "compression"},
	{"libz", "compression"},
	{"ffmpeg", "media"},
	{"libav", "media"},
	{"cups", "printing"},
	{"carbon", "ui"},
	{"appkit", "ui"},
}

// RoleOf answers "what is this linked thing for?" with one short label, "" if unknown.
func RoleOf(name string) string {
	n := strings.ToLower(name)
	for _, r := range roleRules {
		if strings.Contains(n, r.pat) {
			return r.role
		}
	}
	return ""
}

// updaterRules maps a lowercase substring to the framework name used in capabilities.
// shortcut: "tuf" alone matches too much (future, tufa), it needs a path-ish neighbour.
var updaterRules = []struct{ pat, name string }{
	{"squirrel", "Squirrel"},
	{"sparkle", "Sparkle"},
	{"electron-updater", "electron-updater"},
	{"autoupdater", "autoUpdater"},
	{"go-tuf", "tuf"},
	{"theupdateframework", "tuf"},
	{"tuf/", "tuf"},
}

// AddUpdaterCaps records every updater framework seen in deps, dylibs, imports or notes.
func AddUpdaterCaps(d *Digest) {
	hay := make([]string, 0, len(d.Deps)+len(d.Dylibs)+len(d.Imports)+len(d.Notes))
	for _, dep := range d.Deps {
		hay = append(hay, dep.Path)
	}
	hay = append(hay, d.Dylibs...)
	hay = append(hay, d.Imports...)
	hay = append(hay, d.Notes...)
	AddUpdaterCapsFrom(d, hay)
}

// AddUpdaterCapsFrom records every updater framework named by one haystack.
// Readers that keep their paths outside deps and notes (asar members, asar
// package.json dependencies) pass those paths here instead of synthesizing deps.
func AddUpdaterCapsFrom(d *Digest, names []string) {
	for _, h := range names {
		low := strings.ToLower(h)
		if tufModule(low) {
			addCap(d, "updater:tuf")
		}
		for _, r := range updaterRules {
			if !strings.Contains(low, r.pat) {
				continue
			}
			addCap(d, "updater:"+r.name)
		}
	}
	sort.Strings(d.Capabilities)
}

func addCap(d *Digest, c string) {
	if !containsStr(d.Capabilities, c) {
		d.Capabilities = append(d.Capabilities, c)
	}
}

// tufModule matches tuf only as a module path segment. The full path is checked
// here, before any caller strips it to a basename, so "tuf/..." and ".../tuf"
// both count while "future" and "tufa" stay out.
func tufModule(low string) bool {
	for {
		seg := low
		if i := strings.IndexByte(low, '/'); i >= 0 {
			seg, low = low[:i], low[i+1:]
		} else {
			low = ""
		}
		if seg == "tuf" || seg == "go-tuf" {
			return true
		}
		if low == "" {
			return false
		}
	}
}

// DiffDigests renders one line per difference: kind/format/deps/toolchain/caps/files first
// (the historical order), then the target identity — sha256, size, gitoid — and the fields a
// version bump actually moves: minos, uuid, go mod, mobile package/sdk/permissions, electron,
// asar_*, flutter hash, exports, slices, dylibs, imports, rpaths, hardening, ipc, source maps,
// rust crates.
// Missing them made `--diff` answer "no differences" for two different binaries.
func DiffDigests(a, b Digest) []string {
	var out []string
	if a.Kind != b.Kind {
		out = append(out, fmt.Sprintf("kind %s -> %s", orDash(a.Kind), orDash(b.Kind)))
	}
	av, bv := depMap(a), depMap(b)
	for _, p := range unionKeys(av, bv) {
		x, aok := av[p]
		y, bok := bv[p]
		switch {
		case !aok:
			out = append(out, fmt.Sprintf("+dep %s %s", p, y))
		case !bok:
			out = append(out, fmt.Sprintf("-dep %s %s", p, x))
		case x != y:
			out = append(out, fmt.Sprintf("~dep %s %s -> %s", p, x, y))
		}
	}
	if a.Toolchain != b.Toolchain {
		out = append(out, fmt.Sprintf("toolchain %s -> %s", orDash(a.Toolchain), orDash(b.Toolchain)))
	}
	for _, c := range onlyIn(b.Capabilities, a.Capabilities) {
		out = append(out, "+capability "+c)
	}
	for _, c := range onlyIn(a.Capabilities, b.Capabilities) {
		out = append(out, "-capability "+c)
	}
	if a.AsarFiles != b.AsarFiles {
		out = append(out, fmt.Sprintf("files %d -> %d", a.AsarFiles, b.AsarFiles))
	}
	if a.UnpackedNode != b.UnpackedNode {
		out = append(out, fmt.Sprintf("asar_unpacked_native %d -> %d", a.UnpackedNode, b.UnpackedNode))
	}
	for _, f := range []struct{ name, x, y string }{
		{"sha256", a.Target.FileSHA256, b.Target.FileSHA256},
		{"size", fmt.Sprintf("%d", a.Target.Size), fmt.Sprintf("%d", b.Target.Size)},
		{"gitoid", a.Target.GitOID, b.Target.GitOID},
		{"format", a.Format, b.Format},
		{"minos", a.MinOS, b.MinOS},
		{"uuid", a.UUID, b.UUID},
		{"soname", a.Soname, b.Soname},
		{"build_id", a.BuildID, b.BuildID},
		{"subsystem", a.Subsystem, b.Subsystem},
		{"pdb", a.PDB, b.PDB},
		{"mod", a.Mod, b.Mod},
		{"mobile_package", a.MobilePkg, b.MobilePkg},
		{"mobile_sdk", a.MobileSDK, b.MobileSDK},
		{"electron", a.ElectronVer, b.ElectronVer},
		{"asar_main", a.AsarMain, b.AsarMain},
		{"asar_product", a.AsarProduct, b.AsarProduct},
		{"asar_version", a.AsarVersion, b.AsarVersion},
		{"flutter_hash", a.FlutterHash, b.FlutterHash},
		{"symbols", a.Symbols, b.Symbols},
	} {
		if f.x != f.y {
			out = append(out, fmt.Sprintf("%s %s -> %s", f.name, orDash(f.x), orDash(f.y)))
		}
	}
	if a.Slices != b.Slices {
		out = append(out, fmt.Sprintf("slices %d -> %d", a.Slices, b.Slices))
	}
	if a.Exports != b.Exports {
		out = append(out, fmt.Sprintf("exports %d -> %d", a.Exports, b.Exports))
	}
	for _, l := range []struct {
		name string
		x, y []string
	}{
		{"slice", a.SliceInfo, b.SliceInfo},
		{"dylib", a.Dylibs, b.Dylibs},
		{"import", a.Imports, b.Imports},
		{"rpath", a.Rpaths, b.Rpaths},
		{"hardening", a.Hardening, b.Hardening},
		{"electron_ipc", a.ElectronIPC, b.ElectronIPC},
		{"source_map", a.SourceMaps, b.SourceMaps},
		{"rust_crate", a.RustCrates, b.RustCrates},
		{"mobile_permission", a.MobilePerms, b.MobilePerms},
	} {
		for _, v := range onlyIn(l.y, l.x) {
			out = append(out, "+"+l.name+" "+v)
		}
		for _, v := range onlyIn(l.x, l.y) {
			out = append(out, "-"+l.name+" "+v)
		}
	}
	return out
}

func depMap(d Digest) map[string]string {
	m := make(map[string]string, len(d.Deps))
	for _, dep := range d.Deps {
		m[dep.Path] = dep.Version
	}
	return m
}

func unionKeys(a, b map[string]string) []string {
	keys := make([]string, 0, len(a)+len(b))
	for k := range a {
		keys = append(keys, k)
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// onlyIn returns the sorted values of x that y lacks.
func onlyIn(x, y []string) []string {
	seen := make(map[string]bool, len(y))
	for _, s := range y {
		seen[s] = true
	}
	var out []string
	for _, s := range x {
		if !seen[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
