package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Kotlin .klib: a zip whose default/manifest is a java .properties file, whose
// default/linkdata/*.knm are protobuf-lite PackageFragment messages and whose
// default/ir/* are a different container that this reader does not open.
// There is no shared strings table: every fragment carries its own, so names
// never need a second file.

const (
	klibMaxEntries  = 4096
	klibMaxKnm      = 256
	klibMaxKnmSize  = 8 << 20
	klibMaxManifest = 64 << 10
	klibMaxImports  = 128
	klibMaxQnChain  = 32
)

// klibMetadataMajors are the metadata_version majors whose PackageFragment
// field map is known: strings=1, qualified_names=2, package=3, class=4, plus
// the klib extensions is_empty=172, fq_name=173 (plain string) and class_name=174
// (packed int32 ids into the fragment's own StringTable).
var klibMetadataMajors = map[int]bool{1: true, 2: true}

func init() {
	register(reader{
		format: "klib",
		reasons: []string{
			"klib-version-unverified",
			"klib-manifest-missing",
			"klib-linkdata-missing",
			"klib-protobuf-invalid",
			"klib-too-many-entries",
		},
		post:    true,
		match:   klibMatch,
		inspect: inspectKlib,
	})
}

// klibMatch is the cheap prefilter: the zip magic. The name suffix cannot be
// tested here (match only sees the head), so inspectKlib requires .klib, which
// also keeps a .knm from ever matching: it is protobuf, not a zip.
func klibMatch(head []byte, _ int64) bool {
	return bytes.HasPrefix(head, []byte("PK\x03\x04"))
}

func inspectKlib(path string, d *Digest) {
	name := base(path)
	if !strings.HasSuffix(name, ".klib") {
		return
	}
	zr, err := zip.OpenReader(path)
	if err != nil {
		return // the zip reader already reported the open failure
	}
	defer zr.Close()
	if len(zr.File) > klibMaxEntries {
		d.skip("klib-too-many-entries", fmt.Sprintf("%d entries", len(zr.File)))
		return
	}
	d.Format = "klib"

	var manifest *zip.File
	var knms []*zip.File
	for _, f := range zr.File {
		switch {
		case f.Name == "default/manifest":
			manifest = f
		case strings.HasPrefix(f.Name, "default/linkdata/") && strings.HasSuffix(f.Name, ".knm"):
			knms = append(knms, f)
		}
	}
	if manifest == nil {
		d.skip("klib-manifest-missing", "no default/manifest")
		return
	}
	props := klibProperties(manifest)
	abi, meta, comp := props["abi_version"], props["metadata_version"], props["compiler_version"]
	if comp != "" {
		d.Toolchain = "kotlin " + comp
	}
	if abi == "" || meta == "" {
		d.skip("klib-manifest-missing", "manifest lacks abi_version or metadata_version")
		return
	}
	if major, ok := klibMajor(meta); !ok || !klibMetadataMajors[major] {
		d.skip("klib-version-unverified", "metadata_version="+meta)
		return
	}
	if len(knms) == 0 {
		d.skip("klib-linkdata-missing", "no default/linkdata/*.knm")
		return
	}
	d.Capabilities = append(d.Capabilities,
		fmt.Sprintf("klib:entries=%d", len(zr.File)),
		"klib:abi="+abi,
		"klib:metadata="+meta,
	)
	if len(knms) > klibMaxKnm {
		d.Notes = append(d.Notes, fmt.Sprintf("klib: %d of %d .knm read", klibMaxKnm, len(knms)))
		knms = knms[:klibMaxKnm]
	}

	seen := make(map[string]bool, klibMaxImports)
	for _, f := range knms {
		b, err := readZipMember(f, klibMaxKnmSize)
		if err != nil {
			d.unparsed()
			d.skip("klib-protobuf-invalid", f.Name+": "+err.Error())
			continue
		}
		names, err := knmNames(b)
		if err != nil {
			d.unparsed()
			d.skip("klib-protobuf-invalid", f.Name+": "+err.Error())
			continue
		}
		d.parsed()
		for _, n := range names {
			if len(d.Imports) >= klibMaxImports {
				break
			}
			if n != "" && !seen[n] {
				seen[n] = true
				d.Imports = append(d.Imports, n)
			}
		}
	}
	sort.Strings(d.Imports)
	deepNote(d, "read every .knm in default/linkdata for the full declaration list, then default/ir for the bodies: fragments are ordered by package id, not by module order")
}

// knmNames decodes one PackageFragment: the package fq_name and the class names
// whose ids point into that fragment's StringTable. A fragment written before
// the klib extensions existed falls back to the qualified name table.
func knmNames(b []byte) ([]string, error) {
	var (
		strs    []string
		qns     [][2]int32 // parent id, short_name id
		pkg     string
		classes []int32
	)
	err := pbWalk(b, func(num, wire int, v uint64, body []byte) error {
		switch num {
		case 1: // StringTable: repeated string string = 1
			return pbWalk(body, func(n, w int, _ uint64, s []byte) error {
				if n == 1 && w == 2 {
					strs = append(strs, string(s))
				}
				return nil
			})
		case 2: // QualifiedNameTable: repeated QualifiedName qualified_name = 1
			return pbWalk(body, func(n, w int, _ uint64, q []byte) error {
				if n != 1 || w != 2 {
					return nil
				}
				qn := [2]int32{-1, -1}
				err := pbWalk(q, func(f, fw int, fv uint64, _ []byte) error {
					switch f {
					case 1:
						qn[0] = int32(fv)
					case 2:
						qn[1] = int32(fv)
					}
					return nil
				})
				qns = append(qns, qn)
				return err
			})
		case 173:
			pkg = string(body)
		case 174:
			switch wire {
			case 0:
				classes = append(classes, int32(v))
			case 2:
				ids, err := pbInts(body)
				if err != nil {
					return err
				}
				classes = append(classes, ids...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	var names []string
	if pkg != "" {
		names = append(names, pkg)
	}
	for _, id := range classes {
		if id < 0 || int(id) >= len(strs) {
			return nil, fmt.Errorf("class_name id %d outside %d strings", id, len(strs))
		}
		names = append(names, strs[int(id)])
	}
	if pkg == "" && len(classes) == 0 {
		names = append(names, qnNames(qns, strs)...)
	}
	return names, nil
}

// qnNames rebuilds dotted names from the qualified name table: every entry is
// short_name plus a parent id (-1 at the root). A cycle is impossible in real
// metadata, so the hop cap is a guard, not a parser rule.
func qnNames(qns [][2]int32, strs []string) []string {
	var out []string
	for i := range qns {
		var parts []string
		at, hops := i, 0
		for at >= 0 && at < len(qns) && hops < klibMaxQnChain {
			short := qns[at][1]
			if short < 0 || int(short) >= len(strs) {
				break
			}
			parts = append(parts, strs[short])
			next := qns[at][0]
			if next == int32(at) {
				break
			}
			at, hops = int(next), hops+1
		}
		for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
			parts[l], parts[r] = parts[r], parts[l]
		}
		if len(parts) > 0 {
			out = append(out, strings.Join(parts, "."))
		}
	}
	return out
}

// klibProperties reads the manifest's key=value pairs.
// shortcut: only '=' is a separator and the java escapes/continuations are not
// expanded; klib writes plain key=value lines, so upgrade if a real manifest needs them.
func klibProperties(f *zip.File) map[string]string {
	rc, err := f.Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	b, _ := io.ReadAll(io.LimitReader(rc, klibMaxManifest))
	props := make(map[string]string)
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok {
			props[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return props
}

func readZipMember(f *zip.File, max int64) ([]byte, error) {
	if f.UncompressedSize64 > uint64(max) {
		return nil, fmt.Errorf("%d bytes over the %d cap", f.UncompressedSize64, max)
	}
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, max))
}

// klibMajor reads the leading component of a dotted version.
func klibMajor(v string) (int, bool) {
	maj, _, _ := strings.Cut(v, ".")
	n, err := strconv.Atoi(strings.TrimSpace(maj))
	return n, err == nil && n >= 0
}
