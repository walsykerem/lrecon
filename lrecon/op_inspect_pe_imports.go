package main

import (
	"debug/pe"
	"fmt"
	"strings"
)

// Windows import tables can be long; the op reports the total and only this
// many rows so one hostile image cannot flood the JSON.
const inspectPEImportRowCap = 512

type inspectPEImportRow struct {
	Module string `json:"module"`
	Symbol string `json:"symbol"`
}

func init() {
	registerOp(op{
		name:  "inspect_pe_imports",
		route: "L",
		needs: true,
		desc:  "PE standard import table: imported DLL names and named or ordinal functions (no delay-load or bound IAT)",
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind != "pe" && d.Kind != "pe-dotnet" {
				return skipf("%s: kind %s is not PE; inspect_pe_imports reads Windows PE import tables only", path, d.Kind), nil
			}
			f, err := pe.Open(path)
			if err != nil {
				return nil, fmt.Errorf("%s: %v", path, err)
			}
			defer f.Close()
			syms, err := f.ImportedSymbols()
			if err != nil {
				return nil, fmt.Errorf("%s imports: %v", path, err)
			}
			rows := make([]inspectPEImportRow, 0, min(len(syms), inspectPEImportRowCap))
			var libs []string
			for _, s := range syms {
				name, lib, _ := strings.Cut(s, ":")
				if lib != "" {
					libs = append(libs, lib)
				}
				if len(rows) < inspectPEImportRowCap {
					rows = append(rows, inspectPEImportRow{Module: lib, Symbol: name})
				}
			}
			// debug/pe leaves ImportedLibraries empty on some linkers even when
			// the symbols name their DLL, so the symbols are the first source.
			if len(libs) == 0 {
				if l, lerr := f.ImportedLibraries(); lerr == nil {
					libs = l
				}
			}
			libs = uniqued(libs)
			if libs == nil {
				libs = []string{}
			}
			return struct {
				DLLs    []string             `json:"dlls"`
				Imports []inspectPEImportRow `json:"imports"`
				Total   int                  `json:"total"`
				Shown   int                  `json:"shown"`
			}{DLLs: libs, Imports: rows, Total: len(syms), Shown: len(rows)}, nil
		},
	})
}
