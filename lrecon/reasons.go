package main

import (
	"fmt"
	"strings"
)

// reasonRegistry is the one owner of the skip vocabulary: a field and the
// closed set of reasons a reader for it may emit. A reason outside the set is a
// bug in the reader, never a finding, so it is refused instead of rewritten.
var reasonRegistry = map[string]map[string]bool{
	"asar":         reasonSet("asar-too-big"),
	"buildinfo":    reasonSet("buildinfo-absent", "buildinfo-header-truncated"),
	"bun":          reasonSet("bun-trailer-missing", "bun-trailer-unverified"),
	"cpython":      reasonSet("cpython 3.13"),
	"deno":         reasonSet("deno-compile", "deno-trailer-unverified"),
	"deno-compile": reasonSet("deno-compile", "deno-trailer-unverified", "pkgjs-too-large"),
	"dex": reasonSet("dex-bad-endian", "dex-bad-header-size", "dex-bad-map", "dex-bad-string",
		"dex-checksum-mismatch", "dex-oob-section", "dex-too-many-ids",
		"dex-truncated-class", "dex-truncated-header", "dex-unsupported-magic"),
	"dotnet":            reasonSet("dotnet-singlefile"),
	"dotnet-singlefile": reasonSet(append(append([]string{}, dotnetsfReasons...), managedReasons...)...),
	"dotnetsf":          reasonSet("dotnetsf-header-invalid", "dotnetsf-marker-missing", "dotnetsf-truncated", "dotnetsf-version-unverified"),
	"ecma335":           reasonSet("ecma335-container-singlefile", "ecma335-metadata-invalid", "ecma335-table-unverified", "ecma335-truncated"),
	"fa":                reasonSet("fa-broken"),
	"klib":              reasonSet("klib-linkdata-missing", "klib-manifest-missing", "klib-protobuf-invalid", "klib-too-many-entries", "klib-version-unverified"),
	"mangling":          reasonSet("mangling-no-symbols", "mangling-symbolic-unreadable", "mangling-too-many-symbols", "mangling-under-threshold"),
	"node-sea":          reasonSet("pkgjs-too-large", "sea-blob-invalid", "sea-blob-magic", "sea-blob-missing", "sea-fuse", "sea-note-unverified"),
	"opcache":           reasonSet("opcache-header-unverified", "opcache-truncated"),
	"php-opcache":       reasonSet("opcache-header-unverified", "opcache-truncated"),
	"pcap":              reasonSet("pcap-too-big"),
	"pe":                reasonSet("pe-too-big"),
	"phar": reasonSet("phar-api-version-unverified", "phar-manifest-invalid", "phar-signature-length-mismatch",
		"phar-tar-based", "phar-too-large", "phar-whole-file-compressed", "phar-zip-based"),
	"pkg":     reasonSet("pkg-layout-invalid", "pkg-payload-missing", "pkg-vfs-invalid", "pkgjs-too-large"),
	"pkgjs":   reasonSet("pkgjs-too-large"),
	"pyc":     reasonSet("pyc-flags-unsupported", "pyc-marshal-too-deep", "pyc-marshal-truncated", "pyc-not-code", "pyc-too-big", "pyc-version-unverified"),
	"rust":    reasonSet("rust"),
	"sea":     reasonSet("sea-blob-invalid", "sea-blob-magic", "sea-blob-missing", "sea-fuse", "sea-note-unverified"),
	"sigpack": reasonSet("sigpack-at-unsupported", "sigpack-schema", "sigpack-truncated", "sigpack-weak-atom"),
	"swift": reasonSet("swift-relative-offset-out-of-range", "swift-section-size-misaligned",
		"swift-section-unreadable", "swift-slice-unreadable", "swift-typeref-walk-skipped", "swift-version-unverified"),
	"v8cache":  reasonSet("v8cache-header-unverified", "v8cache-size-mismatch", "v8cache-too-big", "v8cache-truncated"),
	"v8-cache": reasonSet("v8cache-header-unverified", "v8cache-size-mismatch", "v8cache-too-big", "v8cache-truncated"),
}

func reasonSet(rs ...string) map[string]bool {
	m := make(map[string]bool, len(rs))
	for _, r := range rs {
		m[r] = true
	}
	return m
}

// fieldOf names the reader a reason belongs to, for refusal messages.
func fieldOf(reason string) string {
	if i := strings.IndexAny(reason, "-:"); i > 0 {
		return reason[:i]
	}
	return reason
}

func registeredReason(reason string) bool {
	for _, set := range reasonRegistry {
		if set[reason] {
			return true
		}
	}
	return false
}

// activeReasonsFor builds the per-reader subset from its declaration. A literal
// the registry does not own is a programmer error, so it panics rather than
// letting a wrong vocabulary into the output.
func activeReasonsFor(format string, reasons []string) map[string]bool {
	m := make(map[string]bool, len(reasons))
	for _, r := range reasons {
		if !registeredReason(r) {
			panic("reader " + format + " declares unregistered reason " + r)
		}
		m[r] = true
	}
	return m
}

// checkReasons refuses a digest that carries a reason the registry does not
// know. The raw reason stays in the output so the bug is visible.
func (d *Digest) checkReasons() error {
	bad := append([]string(nil), d.reasonErrs...)
	seen := map[string]bool{}
	for _, s := range d.Skipped {
		if !registeredReason(s.Reason) && !seen[s.Reason] {
			seen[s.Reason] = true
			bad = append(bad, fmt.Sprintf("reason %q not in registry (field %s)", s.Reason, fieldOf(s.Reason)))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("%s", strings.Join(bad, "; "))
	}
	return nil
}
