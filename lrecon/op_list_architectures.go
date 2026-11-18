package main

import (
	"debug/macho"
	"fmt"
)

type listArchitecturesRow struct {
	Arch       string `json:"arch"`
	CPUSubtype uint32 `json:"cpu_subtype"`
	Offset     int64  `json:"offset"`
	Size       int64  `json:"size"`
	Align      uint32 `json:"align"`
}

func init() {
	registerOp(op{
		name:  "list_architectures",
		route: "L",
		needs: true,
		desc:  "Mach-O slices with architecture, cpu subtype, file offset, size and alignment for thin and universal images",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "macho" {
				return skipf("%s: kind %s is not Mach-O; list_architectures lists Mach-O slices only", path, d.Kind), nil
			}
			rows := []listArchitecturesRow{}
			if d.Format == "fat" {
				ff, err := macho.OpenFat(path)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", path, err)
				}
				defer ff.Close()
				for _, a := range ff.Arches {
					rows = append(rows, listArchitecturesRow{
						Arch: machoArch(a.Cpu), CPUSubtype: a.SubCpu,
						Offset: int64(a.Offset), Size: int64(a.Size), Align: a.Align,
					})
				}
			} else {
				mf, err := macho.Open(path)
				if err != nil {
					return nil, fmt.Errorf("%s: %v", path, err)
				}
				defer mf.Close()
				rows = append(rows, listArchitecturesRow{
					Arch: machoArch(mf.Cpu), CPUSubtype: mf.SubCpu,
					Offset: 0, Size: d.FileSize, Align: thinAlign(mf),
				})
			}
			return struct {
				Format        string                 `json:"format"`
				Slices        int                    `json:"slices"`
				Architectures []listArchitecturesRow `json:"architectures"`
			}{Format: d.Format, Slices: len(rows), Architectures: rows}, nil
		},
	})
}

// thinAlign answers the alignment question a fat slice header answers, for a
// single-architecture file where no slice header exists: the largest section
// alignment exponent in the image. A thin row therefore carries a real,
// measured number instead of dropping the field and leaving thin and fat rows
// with two different shapes.
func thinAlign(f *macho.File) uint32 {
	var max uint32
	for _, sec := range f.Sections {
		if sec.Align > max {
			max = sec.Align
		}
	}
	return max
}
