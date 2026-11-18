package main

import (
	"bytes"
	"fmt"
)

// gpuFatbinMagic is the little-endian magic that opens an NV fatbin blob.
const gpuFatbinMagic = 0xBA55ED50

func init() {
	registerOp(op{
		name:  "inspect_gpu_code_objects",
		route: "L",
		needs: true,
		desc:  "NV fatbin header (0xBA55ED50) inside an ELF note or a bare .fatbin: every PTX/CUBIN entry with its target",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			at := bytes.Index(b, []byte{0x50, 0xED, 0x55, 0xBA})
			if at < 0 {
				return skipf("%s carries no NV fatbin (no 0xBA55ED50 header)", path), nil
			}
			if at+16 > len(b) {
				return nil, fmt.Errorf("%s is not a complete fatbin: the wrapper header is cut", path)
			}
			version := u16le(b, at+4)
			headerSize := int(u16le(b, at+6))
			// fat_size is u64: converting a wild value to int can wrap negative
			// and slip past a plain len() comparison, so bound it as u64 first.
			fatSize64 := u64le(b, at+8)
			if fatSize64 > uint64(len(b)-at) {
				return nil, fmt.Errorf("%s fatbin at %#x declares %d bytes, file holds %d", path, at, fatSize64, len(b)-at)
			}
			fatSize := int(fatSize64)
			if headerSize < 16 || headerSize > fatSize {
				return nil, fmt.Errorf("%s is not a complete fatbin: header is %d bytes, blob is %d", path, headerSize, fatSize)
			}
			type entry struct {
				Kind   string `json:"kind"`
				Arch   string `json:"arch,omitempty"`
				Bytes  int    `json:"payload_bytes"`
				Offset int    `json:"offset"`
			}
			res := struct {
				Version uint16  `json:"wrapper_version"`
				Header  int     `json:"header_bytes"`
				Total   int     `json:"total_bytes"`
				Entries []entry `json:"entries"`
				PTX     int     `json:"ptx"`
				CUBIN   int     `json:"cubin"`
			}{Version: version, Header: headerSize, Total: fatSize}
			// Each TLV: kind u32, version u16, headerSize u16, paddedPayload u64.
			for off := at + headerSize; off+16 <= at+fatSize; {
				kind := u32le(b, off)
				if kind == 0 {
					break
				}
				hsize := int(u16le(b, off+6))
				// payload is u64: adding it as int can wrap past MaxInt64 and
				// turn a wild length into a negative slice bound, so the bound
				// is taken in u64 against the bytes left in the blob.
				payload64 := u64le(b, off+8)
				rem := at + fatSize - off - hsize
				if hsize < 16 || rem < 0 || payload64 > uint64(rem) {
					return nil, fmt.Errorf("%s is not a complete fatbin: entry at %#x declares %d bytes past the blob", path, off, payload64)
				}
				payload := int(payload64)
				name := fmt.Sprintf("unknown-%d", kind)
				switch kind {
				case 1:
					name = "ptx"
					res.PTX++
				case 2:
					name = "cubin"
					res.CUBIN++
				}
				e := entry{Kind: name, Bytes: payload, Offset: off}
				if kind == 2 && payload > 0x40 {
					// ELF64 CUBIN keeps its target in e_machine at 0x12.
					e.Arch = cubinArch(b[off+hsize : off+hsize+payload])
				}
				res.Entries = append(res.Entries, e)
				off += hsize + payload
			}
			if len(res.Entries) == 0 {
				return skipf("%s fatbin carries no PTX or CUBIN entry", path), nil
			}
			return res, nil
		},
	})
}

// cubinArch maps the e_machine of an embedded ELF64 CUBIN to the SM family.
func cubinArch(b []byte) string {
	if len(b) < 0x40 || !bytes.Equal(b[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return ""
	}
	switch u16le(b, 0x12) {
	case 190:
		return "sm_70+"
	case 192:
		return "sm_75+"
	case 193:
		return "sm_80+"
	case 194:
		return "sm_86+"
	case 200:
		return "sm_89+"
	case 201:
		return "sm_90+"
	}
	return fmt.Sprintf("elf-machine-%d", u16le(b, 0x12))
}
