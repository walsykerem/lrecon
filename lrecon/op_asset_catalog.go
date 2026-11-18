package main

// final: inspect_asset_catalog. A shipped Apple asset catalog is a BOMStore
// container: a big-endian header, an index of (address, length) block slots, a
// var table naming the blocks it cares about, and blocks that describe
// themselves with a four-byte magic — "RATC" CARHEADER, "tree" index, "ISTC"
// rendition header, "tmfk" key format. Every field below is read from those
// tables; values the layout does not pin down are left out instead of guessed.

import (
	"fmt"
	"strings"
)

type assetCatalogRange struct {
	Offset uint32 `json:"offset"`
	Length uint32 `json:"length"`
}

// assetCatalogBlock is one var-table entry and the slot it points at.
type assetCatalogBlock struct {
	Name   string `json:"name"`
	ID     uint32 `json:"id"`
	Offset uint32 `json:"offset"`
	Size   uint32 `json:"size"`
	Magic  string `json:"magic,omitempty"`
}

type assetCatalogTree struct {
	Name  string `json:"name"`
	Pairs int    `json:"pairs"`
}

type assetCatalogDigest struct {
	Container      string              `json:"container"`
	Version        uint32              `json:"version"`
	BlocksDeclared uint32              `json:"blocks_declared"`
	IndexSlots     int                 `json:"index_slots"`
	BlocksUsed     int                 `json:"blocks_used"`
	Index          assetCatalogRange   `json:"index"`
	Vars           assetCatalogRange   `json:"vars"`
	NamedBlocks    []assetCatalogBlock `json:"named_blocks"`
	CatalogVersion uint32              `json:"coreui_version,omitempty"`
	StorageVersion uint32              `json:"storage_version,omitempty"`
	MainVersion    string              `json:"main_version,omitempty"`
	KeyFormatIDs   []uint32            `json:"key_format_ids,omitempty"`
	Trees          []assetCatalogTree  `json:"trees"`
	Renditions     int                 `json:"renditions"`
	RenditionBytes uint64              `json:"rendition_bytes"`
	BlockPrefixes  map[string]int      `json:"block_prefixes"`
}

func assetCatalog(path string, b []byte) (assetCatalogDigest, error) {
	var res assetCatalogDigest
	if len(b) < 32 {
		return res, fmt.Errorf("%s: BOM header truncated at %d bytes", path, len(b))
	}
	idxOff, idxLen := int(u32be(b, 16)), int(u32be(b, 20))
	varOff, varLen := int(u32be(b, 24)), int(u32be(b, 28))
	if !dexIn(len(b), idxOff, idxLen, 1) || !dexIn(len(b), varOff, varLen, 1) {
		return res, fmt.Errorf("%s: BOM index[%#x+%d] / vars[%#x+%d] run past the %d-byte file", path, idxOff, idxLen, varOff, varLen, len(b))
	}
	if idxLen < 4 || varLen < 4 {
		return res, fmt.Errorf("%s: BOM index and vars must each hold a count (index %d bytes, vars %d bytes)", path, idxLen, varLen)
	}
	// The index's own count is authoritative: the slot table is sized ahead of
	// the blocks in use, and the header's numberOfBlocks tracks only the used
	// ones (a shipped catalog has 256 slots and 218 used blocks).
	slots := int(u32be(b, idxOff))
	if 4+8*slots > idxLen {
		return res, fmt.Errorf("%s: BOM index holds %d block slots, index length is %d bytes", path, slots, idxLen)
	}
	blocks := make([][2]int, slots)
	for i := range blocks {
		blocks[i] = [2]int{int(u32be(b, idxOff+4+8*i)), int(u32be(b, idxOff+8+8*i))}
		if blocks[i][1] > 0 {
			res.BlocksUsed++
		}
	}
	block := func(id uint32) ([]byte, error) {
		if int(id) >= len(blocks) || blocks[id][1] == 0 {
			return nil, fmt.Errorf("%s: block %d is outside the %d-slot index", path, id, len(blocks))
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
			return res, fmt.Errorf("%s: BOM vars truncated at entry %d", path, i)
		}
		id, l := u32be(b, p), int(b[p+4])
		if p+5+l > varOff+varLen {
			return res, fmt.Errorf("%s: BOM var %d name truncated", path, i)
		}
		vars[string(b[p+5:p+5+l])] = id
		p += 5 + l
	}
	if _, ok := vars["RENDITIONS"]; !ok {
		return res, fmt.Errorf("%s: BOM vars name no RENDITIONS tree (have %s)", path, strings.Join(varsSorted(vars), ", "))
	}

	res.Container = "BOMStore"
	res.Version = u32be(b, 8)
	res.BlocksDeclared = u32be(b, 12)
	res.IndexSlots = slots
	res.Index = assetCatalogRange{Offset: uint32(idxOff), Length: uint32(idxLen)}
	res.Vars = assetCatalogRange{Offset: uint32(varOff), Length: uint32(varLen)}
	res.BlockPrefixes = map[string]int{}

	for i := range blocks {
		n := blocks[i][1]
		if n == 0 {
			continue
		}
		off := blocks[i][0]
		if !dexIn(len(b), off, n, 1) {
			return res, fmt.Errorf("%s: block %d [%#x+%d] runs past the file", path, i, off, n)
		}
		res.BlockPrefixes[blockMagic(b[off:off+min(n, 4)])]++
	}

	for _, name := range varsSorted(vars) {
		blk, err := block(vars[name])
		if err != nil {
			return res, fmt.Errorf("%s: %s: %w", path, name, err)
		}
		off, n := blocks[vars[name]][0], blocks[vars[name]][1]
		res.NamedBlocks = append(res.NamedBlocks, assetCatalogBlock{
			Name: name, ID: vars[name], Offset: uint32(off), Size: uint32(n), Magic: blockMagic(blk),
		})
	}

	if id, ok := vars["CARHEADER"]; ok {
		hdr, err := block(id)
		if err != nil {
			return res, fmt.Errorf("%s: CARHEADER: %w", path, err)
		}
		if len(hdr) < 0x14 || string(hdr[:4]) != "RATC" {
			return res, fmt.Errorf("%s: CARHEADER block starts %q, not the 0x14-byte RATC header", path, firstBytes(hdr, 4))
		}
		// CARHEADER is the one little-endian block in the container.
		res.CatalogVersion = u32le(hdr, 4)
		res.StorageVersion = u32le(hdr, 8)
		if v, ok := cstr(hdr, 0x14); ok {
			res.MainVersion = v
		}
	}

	if id, ok := vars["KEYFORMAT"]; ok {
		kf, err := block(id)
		if err != nil {
			return res, fmt.Errorf("%s: KEYFORMAT: %w", path, err)
		}
		if len(kf) < 12 || string(kf[:4]) != "tmfk" {
			return res, fmt.Errorf("%s: KEYFORMAT block starts %q, not the tmfk table", path, firstBytes(kf, 4))
		}
		// The tmfk table is little-endian like CARHEADER: count, then that many
		// key ids. The ids are numeric; the format publishes no names for them.
		n := int(u32le(kf, 8))
		if !dexIn(len(kf), 12, n, 4) {
			return res, fmt.Errorf("%s: KEYFORMAT declares %d key ids in %d bytes", path, n, len(kf))
		}
		for i := range n {
			res.KeyFormatIDs = append(res.KeyFormatIDs, u32le(kf, 12+4*i))
		}
	}

	for _, name := range []string{"RENDITIONS", "FACETKEYS", "APPEARANCEKEYS", "BITMAPKEYS"} {
		id, ok := vars[name]
		if !ok {
			continue
		}
		pairs, err := metaBTree(block, id)
		if err != nil {
			return res, fmt.Errorf("%s: %s: %w", path, name, err)
		}
		res.Trees = append(res.Trees, assetCatalogTree{Name: name, Pairs: len(pairs)})
		if name != "RENDITIONS" {
			continue
		}
		res.Renditions = len(pairs)
		for _, e := range pairs {
			if int(e.value) >= len(blocks) || blocks[e.value][1] <= 0 {
				return res, fmt.Errorf("%s: RENDITIONS: rendition block %d is outside the %d-slot index", path, e.value, len(blocks))
			}
			res.RenditionBytes += uint64(blocks[e.value][1])
		}
	}
	return res, nil
}

// blockMagic names a block by the four bytes it starts with. Blocks that start
// with binary data (tree nodes, payloads) carry no magic, so they count as
// "other" rather than being given a made-up tag.
// shortcut: the index entry is only (address, length), so the first four bytes
// stand in for the tag and binary blocks collapse into "other"; upgrade if a
// catalog version pins a real per-block tag field.
func blockMagic(b []byte) string {
	if len(b) < 4 || !printable(string(b[:4])) {
		return "other"
	}
	return string(b[:4])
}
