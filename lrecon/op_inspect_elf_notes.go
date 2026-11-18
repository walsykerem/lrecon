package main

import (
	"debug/elf"
	"encoding/hex"
	"fmt"
	"os"
)

func init() {
	registerOp(op{
		name:  "inspect_elf_notes",
		route: "L",
		needs: true,
		desc:  "every SHT_NOTE/PT_NOTE record: owner, type and decoded payload (GNU build-id, ABI tag, Go build id)",
		run: func(path string) (any, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			ef, err := elf.NewFile(f)
			if err != nil {
				return nil, fmt.Errorf("%s is not ELF: %w", path, err)
			}
			notes, ok := elfNoteRecords(path)
			if !ok || len(notes) == 0 {
				return skipf("%s has no PT_NOTE segment or SHT_NOTE section", path), nil
			}
			type note struct {
				Owner string `json:"owner"`
				Type  uint32 `json:"type"`
				Bytes int    `json:"bytes"`
				Value string `json:"value,omitempty"`
			}
			res := struct {
				Machine string   `json:"machine"`
				Notes   []note   `json:"notes"`
				BuildID string   `json:"build_id,omitempty"`
				Owners  []string `json:"owners"`
			}{Machine: ef.Machine.String()}
			for _, n := range notes {
				// parseNotes already trimmed the NUL padding off the name.
				owner := n.name
				e := note{Owner: owner, Type: n.typ, Bytes: len(n.desc)}
				switch {
				case owner == "GNU" && n.typ == 3: // NT_GNU_BUILD_ID
					e.Value = hex.EncodeToString(n.desc)
					if res.BuildID == "" {
						res.BuildID = e.Value
					}
				case owner == "Go":
					e.Value = string(bytes0(n.desc))
				case n.typ == 1 && printableASCII(bytes0(n.desc)):
					e.Value = string(bytes0(n.desc))
				}
				res.Notes = append(res.Notes, e)
				res.Owners = append(res.Owners, owner)
			}
			res.Owners = uniqSorted(res.Owners)
			return res, nil
		},
	})
}

// bytes0 trims trailing NULs so printableASCII can judge a note payload.
func bytes0(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == 0 {
		b = b[:len(b)-1]
	}
	return b
}
