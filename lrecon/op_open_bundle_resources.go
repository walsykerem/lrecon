package main

// final.md 151 (item 39): open_bundle_resources.
//
// A shipped macOS .car is a BOMStore container: a block table, a variable table
// naming the trees, and per-tree nodes whose (value block, key block) pairs hold
// ISTC rendition headers. The RENDITIONS and FACETKEYS trees are decoded here,
// so the answer is real names, formats, compression markers, offsets and sizes —
// not a byte scan for four-letter tags.

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

const metaBMaxEntries = 5000

func init() {
	registerOp(op{
		name:  "open_bundle_resources",
		route: "L",
		needs: true,
		desc:  "decode a BOMStore .car bundle: RENDITIONS/FACETKEYS trees into an asset name/type/compression/offset/size table with total bytes",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			if bytes.HasPrefix(b, []byte("BOMStore")) {
				return metaBCar(path, b)
			}
			if bytes.HasPrefix(b, []byte("CARV")) {
				return metaBCarv(path, b)
			}
			return nil, fmt.Errorf("%s is not a bundle resource archive: magic %q, want BOMStore or CARV", path, firstBytes(b, 8))
		},
	})
}

type metaBCarEntry struct {
	Asset       string `json:"asset,omitempty"`
	Rendition   string `json:"rendition,omitempty"`
	Type        string `json:"type"`
	Compression string `json:"compression"`
	Offset      uint32 `json:"offset"`
	Size        uint32 `json:"size"`
	Width       uint32 `json:"width"`
	Height      uint32 `json:"height"`
	Scale       uint32 `json:"scale"`
}

func metaBCar(path string, b []byte) (any, error) {
	if len(b) < 32 {
		return nil, fmt.Errorf("%s: BOM header truncated at %d bytes", path, len(b))
	}
	idxOff, idxLen := int(u32be(b, 16)), int(u32be(b, 20))
	varOff, varLen := int(u32be(b, 24)), int(u32be(b, 28))
	if !dexIn(len(b), idxOff, idxLen, 1) || !dexIn(len(b), varOff, varLen, 1) {
		return nil, fmt.Errorf("%s: BOM index[%#x+%d] / vars[%#x+%d] run past the %d-byte file", path, idxOff, idxLen, varOff, varLen, len(b))
	}
	// The index's own count is authoritative: real bundles keep a larger
	// slot table than the header's "blocks in use" figure.
	declared := int(u32be(b, idxOff))
	if declared > (idxLen-4)/8 {
		return nil, fmt.Errorf("%s: BOM index holds %d block slots, header says %d", path, (idxLen-4)/8, declared)
	}
	blocks := make([][2]int, declared)
	for i := range blocks {
		blocks[i] = [2]int{int(u32be(b, idxOff+4+8*i)), int(u32be(b, idxOff+8+8*i))}
	}
	block := func(id uint32) ([]byte, error) {
		if int(id) >= len(blocks) || blocks[id][1] == 0 {
			return nil, fmt.Errorf("%s: block %d is outside the %d-block index", path, id, len(blocks))
		}
		off, n := blocks[id][0], blocks[id][1]
		if !dexIn(len(b), off, n, 1) {
			return nil, fmt.Errorf("%s: block %d [%#x+%d] runs past the file", path, id, off, n)
		}
		return b[off : off+n], nil
	}

	vars := map[string]uint32{}
	nVars := int(u32be(b, varOff))
	p := varOff + 4
	for i := range nVars {
		if p+5 > varOff+varLen {
			return nil, fmt.Errorf("%s: BOM vars truncated at entry %d", path, i)
		}
		id := u32be(b, p)
		l := int(b[p+4])
		if p+5+l > varOff+varLen {
			return nil, fmt.Errorf("%s: BOM var %d name truncated", path, i)
		}
		vars[string(b[p+5:p+5+l])] = id
		p += 5 + l
	}
	for _, want := range []string{"RENDITIONS", "FACETKEYS", "CARHEADER"} {
		if _, ok := vars[want]; !ok {
			return nil, fmt.Errorf("%s: BOM vars name no %s tree (have %s)", path, want, strings.Join(varsSorted(vars), ", "))
		}
	}

	assets := map[string]string{} // identifier bytes -> asset name
	facetID, err := metaBTree(block, vars["FACETKEYS"])
	if err != nil {
		return nil, fmt.Errorf("%s: FACETKEYS: %v", path, err)
	}
	var assetNames []string
	for _, e := range facetID {
		val, err := block(e.value)
		if err != nil {
			return nil, fmt.Errorf("%s: FACETKEYS: %v", path, err)
		}
		key, err := block(e.key)
		if err != nil {
			return nil, fmt.Errorf("%s: FACETKEYS: %v", path, err)
		}
		name := strings.TrimRight(string(key), "\x00")
		if !printable(name) {
			return nil, fmt.Errorf("%s: FACETKEYS key is not a name: % x", path, key)
		}
		assetNames = append(assetNames, name)
		if len(val) >= 2 {
			assets[string(val[len(val)-2:])] = name
		}
	}
	sort.Strings(assetNames)

	rend, err := metaBTree(block, vars["RENDITIONS"])
	if err != nil {
		return nil, fmt.Errorf("%s: RENDITIONS: %v", path, err)
	}
	res := struct {
		Container      string          `json:"container"`
		Version        uint32          `json:"version"`
		Blocks         int             `json:"blocks"`
		Vars           []string        `json:"vars"`
		StorageVersion uint32          `json:"storage_version,omitempty"`
		MainVersion    string          `json:"main_version,omitempty"`
		Assets         []string        `json:"assets"`
		Entries        []metaBCarEntry `json:"entries"`
		TotalBytes     uint64          `json:"total_bytes"`
	}{Container: "BOMStore", Version: u32be(b, 8), Blocks: declared, Vars: varsSorted(vars), Assets: assetNames}

	// CARHEADER is the one little-endian block in the container: coreuiVersion,
	// storageVersion, timestamp, renditionCount, then mainVersionString.
	if hdr, err := block(vars["CARHEADER"]); err == nil && len(hdr) >= 0x14 {
		res.StorageVersion = u32le(hdr, 8)
		if n, ok := cstr(hdr, 0x14); ok {
			res.MainVersion = n
		}
	}

	for _, e := range rend {
		val, err := block(e.value)
		if err != nil {
			return nil, fmt.Errorf("%s: RENDITIONS: %v", path, err)
		}
		key, err := block(e.key)
		if err != nil {
			return nil, fmt.Errorf("%s: RENDITIONS: %v", path, err)
		}
		row, err := metaBISTC(val, key, assets)
		if err != nil {
			return nil, fmt.Errorf("%s: RENDITIONS: %v", path, err)
		}
		row.Offset, row.Size = uint32(blocks[e.value][0]), uint32(blocks[e.value][1])
		res.Entries = append(res.Entries, row)
		res.TotalBytes += uint64(row.Size)
		if len(res.Entries) >= metaBMaxEntries {
			break
		}
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("%s: RENDITIONS tree holds no rendition blocks", path)
	}
	return res, nil
}

type metaBPair struct{ value, key uint32 }

// metaBTree walks one BOM tree from its root node and returns every leaf pair.
// Branch nodes name child blocks instead of pairs, and `forward` links leaves.
func metaBTree(block func(uint32) ([]byte, error), root uint32) ([]metaBPair, error) {
	seen := map[uint32]bool{}
	var walk func(id uint32) error
	var out []metaBPair
	walk = func(id uint32) error {
		if seen[id] {
			return fmt.Errorf("tree revisits block %d", id)
		}
		seen[id] = true
		tree, err := block(id)
		if err != nil {
			return err
		}
		if len(tree) < 21 || string(tree[:4]) != "tree" {
			return fmt.Errorf("block %d is not a BOM tree (%q)", id, firstBytes(tree, 4))
		}
		child := u32be(tree, 8)
		if child == 0 {
			return fmt.Errorf("tree %d has no root node", id)
		}
		for range 64 {
			node, err := block(child)
			if err != nil {
				return err
			}
			if len(node) < 12 {
				return fmt.Errorf("node %d truncated", child)
			}
			leaf, count := u16be(node, 0), int(u16be(node, 2))
			if !dexIn(len(node), 12, count, 8) {
				return fmt.Errorf("node %d declares %d entries past its %d bytes", child, count, len(node))
			}
			if leaf == 0 {
				for i := range count {
					if err := walk(u32be(node, 12+4*i)); err != nil {
						return err
					}
				}
			} else {
				for i := range count {
					out = append(out, metaBPair{value: u32be(node, 12+8*i), key: u32be(node, 16+8*i)})
				}
			}
			next := u32be(node, 4)
			if next == 0 {
				return nil
			}
			child = next
		}
		return fmt.Errorf("node chain past block %d is longer than 64 leaves", child)
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return out, nil
}

// metaBISTC decodes one ISTC rendition header. The key block identifies which
// facet the rendition belongs to; payload markers name the compression.
func metaBISTC(val, key []byte, assets map[string]string) (metaBCarEntry, error) {
	if len(val) < 0x28 {
		return metaBCarEntry{}, fmt.Errorf("rendition block is %d bytes, ISTC header needs %#x", len(val), 0x28)
	}
	if string(val[:4]) != "ISTC" {
		return metaBCarEntry{}, fmt.Errorf("rendition block starts %q, not ISTC", firstBytes(val, 4))
	}
	row := metaBCarEntry{
		// ISTC follows CARHEADER's byte order: the numeric header is little-endian.
		Type:   "image",
		Width:  u32le(val, 0x0c),
		Height: u32le(val, 0x10),
		Scale:  u32le(val, 0x14),
	}
	if n, ok := cstr(val, 0x28); ok {
		row.Rendition = n
	}
	if pf := string(val[0x18:0x1c]); strings.Contains(pf, "FDP") || strings.Contains(pf, "PDF") {
		row.Type = "pdf"
	}
	// The name attribute is the only key token a facet can be joined on; a key
	// shorter than 6 bytes carries none.
	if len(key) >= 6 {
		row.Asset = assets[string(key[4:6])]
	}
	switch {
	case row.Type == "pdf" || bytes.Contains(val[:min(len(val), 0x1000)], []byte("%PDF-")):
		row.Compression = "uncompressed"
	case bytes.Contains(val[:min(len(val), 0x1000)], []byte("bvx2")):
		row.Compression = "lzfse"
	case bytes.Contains(val[:min(len(val), 0x1000)], []byte("ZZZZPackedAsset-")):
		row.Compression = "packed"
	default:
		// No marker this reader can prove: say so instead of calling it stored.
		row.Compression = "unknown"
	}
	return row, nil
}

// metaBCarv lists a CARV container's chunks. The chunk framing is read; a REND
// chunk's payload layout is not a published format, so it is reported as one
// chunk with its bytes rather than guessed into fake entries.
func metaBCarv(path string, b []byte) (any, error) {
	type chunk struct {
		Tag    string `json:"tag"`
		Offset uint32 `json:"offset"`
		Size   uint32 `json:"size"`
	}
	res := struct {
		Container string  `json:"container"`
		Chunks    []chunk `json:"chunks"`
	}{Container: "CARV"}
	for p := 4; p+8 <= len(b); {
		tag := string(b[p : p+4])
		if !printable(tag) {
			return nil, fmt.Errorf("%s: CARV chunk tag at %#x is not printable: % x", path, p, b[p:p+4])
		}
		n := int(u32be(b, p+4))
		if !dexIn(len(b), p+8, n, 1) {
			return nil, fmt.Errorf("%s: CARV chunk %q at %#x declares %d bytes past the %d-byte file", path, tag, p, n, len(b))
		}
		res.Chunks = append(res.Chunks, chunk{tag, uint32(p), uint32(n)})
		p += 8 + n
	}
	if len(res.Chunks) == 0 {
		return nil, fmt.Errorf("%s: CARV header carries no chunk (file is %d bytes)", path, len(b))
	}
	return res, nil
}

func varsSorted(vars map[string]uint32) []string {
	out := make([]string, 0, len(vars))
	for k := range vars {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return s != ""
}

func firstBytes(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	return string(b)
}
