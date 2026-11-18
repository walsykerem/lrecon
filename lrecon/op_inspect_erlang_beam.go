package main

import (
	"fmt"
	"os"
)

func init() {
	registerOp(op{
		name:  "inspect_erlang_beam",
		route: "L",
		needs: true,
		desc:  "BEAM IFF container: every chunk id/size, the Atom table and compiler version",
		run: func(path string) (any, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			head := make([]byte, beamHeaderLen)
			if n, _ := f.ReadAt(head, 0); n < beamHeaderLen || string(head[:4]) != "FOR1" || string(head[8:12]) != "BEAM" {
				return nil, fmt.Errorf("%s is not a BEAM file", path)
			}
			total := int64(u32be(head[4:], 0)) + 8
			// The IFF size is the only container bound, so a truncated file
			// would otherwise be walked past its end and still answer with
			// chunk offsets that do not exist.
			if st, serr := f.Stat(); serr != nil {
				return nil, serr
			} else if total > st.Size() {
				return nil, fmt.Errorf("%s declares %d bytes, file holds %d", path, total, st.Size())
			}
			type chunk struct {
				ID    string `json:"id"`
				Bytes int64  `json:"bytes"`
				Off   int64  `json:"offset"`
			}
			res := struct {
				Total    int64    `json:"total_bytes"`
				Chunks   []chunk  `json:"chunks"`
				Atoms    int      `json:"atoms"`
				AtomList []string `json:"atom_sample,omitempty"`
				Compiler string   `json:"compiler,omitempty"`
			}{Total: total}
			var atomChunk []byte
			sawAtom := false
			atoms := 0
			for off := int64(beamHeaderLen); off+beamChunkLen <= total; {
				hdr := make([]byte, beamChunkLen)
				if n, _ := f.ReadAt(hdr, off); n < beamChunkLen {
					break
				}
				id := string(hdr[:4])
				size := int64(u32be(hdr[4:], 0))
				body := off + beamChunkLen
				if body+size > total {
					return nil, fmt.Errorf("%s is not a complete BEAM container: chunk %q at %#x declares %d bytes past the end", path, id, off, size)
				}
				res.Chunks = append(res.Chunks, chunk{ID: id, Bytes: size, Off: off})
				switch id {
				case "Atom", "AtU8":
					sawAtom = true
					atomChunk = make([]byte, size)
					if n, _ := f.ReadAt(atomChunk, body); int64(n) < size {
						atomChunk = nil
					}
				case "CInf":
					b := make([]byte, size)
					if n, _ := f.ReadAt(b, body); int64(n) == size {
						res.Compiler = nulStr(b)
					}
				}
				// IFF pads chunks to a 4-byte boundary; the pad is not part of
				// the declared size, so the next header starts after it.
				off = int64(align4(int(body + size)))
			}
			if len(res.Chunks) == 0 {
				return nil, fmt.Errorf("%s is not a BEAM container: no chunks follow the header", path)
			}
			// Atom chunk: u32 BE count, then count × (u8 length + bytes).
			if len(atomChunk) >= 4 {
				declared := int(u32be(atomChunk, 0))
				p := 4
				for i := 0; i < declared && p < len(atomChunk); i++ {
					n := int(atomChunk[p])
					p++
					if p+n > len(atomChunk) {
						break
					}
					atoms++
					if len(res.AtomList) < 40 {
						res.AtomList = append(res.AtomList, string(atomChunk[p:p+n]))
					}
					p += n
				}
			}
			res.Atoms = atoms
			if atoms == 0 {
				if sawAtom {
					return skipf("%s Atom chunk carries no readable atom", path), nil
				}
				return skipf("%s has no Atom chunk", path), nil
			}
			return res, nil
		},
	})
}
