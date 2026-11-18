package main

import (
	"debug/macho"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// final.md 43: trace_dylib_resolution.
func init() {
	registerOp(op{
		name:  "trace_dylib_resolution",
		route: "L",
		desc:  "every LC_LOAD_DYLIB/weak/reexport/upward plus LC_ID_DYLIB, resolved through @loader_path/@executable_path/@rpath in dyld order",
		needs: true,
		run:   runTraceDylibResolution,
	})
}

type netcDylib struct {
	InstallName string   `json:"install_name"`
	Kind        string   `json:"command"`
	Candidates  []string `json:"candidates"`
	Resolved    string   `json:"resolved,omitempty"`
	Exists      bool     `json:"exists"`
}

type netcDylibSlice struct {
	Arch    string      `json:"arch"`
	Rpaths  []string    `json:"rpaths"`
	Dylibs  []netcDylib `json:"dylibs"`
	Missing int         `json:"missing"`
	Present int         `json:"present"`
}

func runTraceDylibResolution(path string) (any, error) {
	// Size and type are checked without reading the file: the Mach-O reader
	// below is the only consumer of the bytes.
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if st.Size() > opMaxFile {
		return nil, fmt.Errorf("%s is %d bytes, over the %d-byte cap", path, st.Size(), opMaxFile)
	}
	// @executable_path is the directory of the executable itself, never the
	// caller's working directory: make the target absolute before deriving it.
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	exeDir := filepath.Dir(abs)
	files, arches, err := netcMachOSlices(path)
	if err != nil {
		return nil, err
	}
	var out []netcDylibSlice
	sharedCacheNote := ""
	for i, mf := range files {
		cmds, err := netcMachOLoadCommands(mf)
		if err != nil {
			return nil, fmt.Errorf("%s:%s: %v", path, arches[i], err)
		}
		rpaths := []string{}
		for _, c := range cmds {
			if c.Kind == "rpath" {
				rpaths = append(rpaths, c.Path)
			}
		}
		s := netcDylibSlice{Arch: arches[i], Rpaths: rpaths, Dylibs: []netcDylib{}}
		loaderDir := exeDir // the image is the file that holds the command
		for _, c := range cmds {
			if c.Kind == "rpath" {
				continue
			}
			d := netcDylib{InstallName: c.Path, Kind: c.Kind, Candidates: netcDylibCandidates(c.Path, exeDir, loaderDir, rpaths)}
			d.Resolved = netcFirstExisting(d.Candidates)
			d.Exists = d.Resolved != ""
			// LC_ID_DYLIB names this image itself; it is not a dependency and
			// must not be counted as a missing load.
			if c.Kind == "id" {
				s.Dylibs = append(s.Dylibs, d)
				continue
			}
			if d.Exists {
				s.Present++
			} else {
				s.Missing++
				if strings.HasPrefix(d.InstallName, "/usr/lib/") || strings.HasPrefix(d.InstallName, "/System/Library/") {
					sharedCacheNote = "a missing /usr/lib or /System/Library path is normally served from the dyld shared cache, so exists=false does not mean it fails to load"
				}
			}
			s.Dylibs = append(s.Dylibs, d)
		}
		out = append(out, s)
	}
	res := map[string]any{
		"path":           path,
		"executable_dir": exeDir,
		"slices":         out,
	}
	if sharedCacheNote != "" {
		res["note"] = sharedCacheNote
	}
	return res, nil
}

// netcMachOSlices opens the thin or fat Mach-O at path and returns its debug
// slices with the arch names and the fat offsets they were read from.
func netcMachOSlices(path string) ([]*macho.File, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if ff, ferr := macho.NewFatFile(f); ferr == nil && len(ff.Arches) > 0 {
		var files []*macho.File
		var arches []string
		for _, a := range ff.Arches {
			files = append(files, a.File)
			arches = append(arches, machoArch(a.Cpu))
		}
		return files, arches, nil
	}
	mf, terr := macho.NewFile(f)
	if terr != nil {
		return nil, nil, fmt.Errorf("%s is not Mach-O: %v", path, terr)
	}
	return []*macho.File{mf}, []string{machoArch(mf.Cpu)}, nil
}
