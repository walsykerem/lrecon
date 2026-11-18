package main

import (
	"bytes"
	"fmt"
)

func init() {
	registerOp(op{
		name:  "inspect_devicetree",
		route: "L",
		needs: true,
		desc:  "walk an FDT (d00dfeed) struct block: node tree, compatible/model and property counts",
		run: func(path string) (any, error) {
			b, err := opRead(path, 16<<20)
			if err != nil {
				return nil, err
			}
			if len(b) < 36 || u32be(b, 0) != 0xd00dfeed {
				return nil, fmt.Errorf("%s is not a flattened device tree", path)
			}
			version := u32be(b, 20)
			// v17 added sizeStruct at offset 36; v16 and older stop at
			// 36 bytes, so their header must not be required to reach 40.
			hdr := 40
			if version < 17 {
				hdr = 36
			}
			if len(b) < hdr {
				return nil, fmt.Errorf("%s is not the size its header declares: version %d needs a %d-byte header, file holds %d", path, version, hdr, len(b))
			}
			totalsize := int(u32be(b, 4))
			if totalsize > len(b) || totalsize < hdr {
				return nil, fmt.Errorf("%s is not the size its header declares: header says %d bytes, file holds %d", path, totalsize, len(b))
			}
			offStruct := int(u32be(b, 8))
			offStrings := int(u32be(b, 12))
			sizeStrings := int(u32be(b, 32))
			sizeStruct := 0
			if hdr == 40 {
				sizeStruct = int(u32be(b, 36))
			} else {
				// A v16 header carries no struct size: the block runs to
				// the end of the blob.
				sizeStruct = totalsize - offStruct
			}
			// Both blocks follow the header; an offset inside it would have
			// the walk read header bytes as tokens, which is what the
			// firmware validator already refuses.
			if offStruct < hdr || offStrings < hdr ||
				offStruct+sizeStruct > totalsize || offStrings+sizeStrings > totalsize {
				return nil, fmt.Errorf("%s is not a well-formed device tree: struct/strings blocks lie outside it", path)
			}
			nodes, props, depth, maxDepth := 0, 0, 0, 0
			compatible := ""
			model := ""
			raw := b[offStruct : offStruct+sizeStruct]
			strs := b[offStrings : offStrings+sizeStrings]
			ended := false
			for off := 0; off+4 <= len(raw); {
				tok := u32be(raw, off)
				off += 4
				switch tok {
				case 1: // FDT_BEGIN_NODE
					// The node name is not reported; only its terminator matters
					// for finding the next token.
					end := off
					for end < len(raw) && raw[end] != 0 {
						end++
					}
					off = align4(end + 1)
					depth++
					if depth > maxDepth {
						maxDepth = depth
					}
					nodes++
				case 2: // FDT_END_NODE
					if depth == 0 {
						return nil, fmt.Errorf("%s is not a well-formed device tree: FDT_END_NODE at %#x closes no node", path, off-4)
					}
					depth--
				case 3: // FDT_PROP
					if off+8 > len(raw) {
						return nil, fmt.Errorf("%s is not a well-formed device tree: property header runs past the struct block", path)
					}
					lenVal := int(u32be(raw, off))
					nameOff := int(u32be(raw, off+4))
					off += 8
					// Both fields are 32-bit unsigned: on a 32-bit int they can
					// arrive negative, and off+lenVal would then slice backwards.
					if lenVal < 0 || off+lenVal > len(raw) {
						return nil, fmt.Errorf("%s is not a well-formed device tree: property value runs past the struct block", path)
					}
					if nameOff < 0 || nameOff >= len(strs) {
						return nil, fmt.Errorf("%s is not a well-formed device tree: property name offset %d is outside the %d-byte strings block", path, nameOff, len(strs))
					}
					nameRaw := strs[nameOff:]
					if i := bytes.IndexByte(nameRaw, 0); i >= 0 {
						nameRaw = nameRaw[:i]
					}
					name := string(nameRaw)
					val := raw[off : off+lenVal]
					off = align4(off + lenVal)
					props++
					if depth == 1 {
						switch name {
						case "compatible":
							compatible = nulStr(val)
						case "model":
							model = nulStr(val)
						}
					}
				case 4: // FDT_NOP
				case 9: // FDT_END
					off = len(raw)
					ended = true
				default:
					return nil, fmt.Errorf("%s: unknown FDT token %#x at %#x", path, tok, off-4)
				}
			}
			if !ended {
				return nil, fmt.Errorf("%s is not a well-formed device tree: the struct block never reaches FDT_END", path)
			}
			if depth != 0 {
				return nil, fmt.Errorf("%s is not a well-formed device tree: %d nodes left open at FDT_END", path, depth)
			}
			if nodes == 0 {
				return nil, fmt.Errorf("%s is not a device tree with nodes: the struct block holds none", path)
			}
			return struct {
				Version    uint32 `json:"version"`
				TotalBytes int    `json:"total_bytes"`
				Nodes      int    `json:"nodes"`
				MaxDepth   int    `json:"max_depth"`
				Properties int    `json:"properties"`
				Model      string `json:"model,omitempty"`
				Compatible string `json:"compatible,omitempty"`
			}{version, totalsize, nodes, maxDepth, props, model, compatible}, nil
		},
	})
}
