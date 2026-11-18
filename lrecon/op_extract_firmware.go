package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	registerOp(op{
		name:  "extract_firmware",
		route: "L",
		needs: true,
		desc:  "carve each firmware image out of a flash dump into -o DIR; nothing is written beside the dump",
		run: func(path string) (any, error) {
			b, err := opRead(path, maxFirmwareScan)
			if err != nil {
				return nil, err
			}
			hits, capped := firmwareHits(b)
			if len(hits) == 0 {
				return skipf("%s carries no recognisable firmware container", path), nil
			}
			dir, err := exportDirDest("extract_firmware", path)
			if err != nil {
				return nil, err
			}
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, err
			}
			type part struct {
				Name   string `json:"name"`
				Offset int    `json:"offset"`
				Bytes  int    `json:"bytes"`
				File   string `json:"file"`
			}
			res := struct {
				Dir    string `json:"dir"`
				Parts  []part `json:"parts"`
				Capped bool   `json:"capped"`
			}{Dir: dir, Capped: capped}
			for i, h := range hits {
				end := len(b)
				if i+1 < len(hits) {
					end = hits[i+1].off
				}
				end = min(align4(end), len(b))
				name := fmt.Sprintf("%02d-%s.bin", i, h.name)
				name = filepath.Base(name)
				if err := os.WriteFile(filepath.Join(dir, name), b[h.off:end], 0o644); err != nil {
					return nil, err
				}
				res.Parts = append(res.Parts, part{Name: h.name, Offset: h.off, Bytes: end - h.off, File: name})
			}
			return res, nil
		},
	})
}
