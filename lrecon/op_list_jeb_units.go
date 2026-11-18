package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// 38. list_jeb_units — JEB has no static interface, so the unit list is read
// straight from the DEX tables: class_defs_size 0x60 / class_defs_off 0x64, one
// 32-byte class_def_item each, class_idx -> type_ids -> string_ids, then the
// class_data_item ULEB chain for the methods.
func init() {
	registerOp(op{
		name:  "list_jeb_units",
		route: "L",
		desc:  "class and method names from a project dir's classes*.dex (class_defs -> type_ids -> string_ids, then class_data_item); replaces JEB's unit list (final.md y5, item 38)",
		needs: true,
		run:   opListJebUnits,
	})
}

// jebdUnit is one class: Methods carry a code item, Abstract has code_off 0
// (abstract or native). The two channels JEB mixes stay apart, as do units and
// errors.
type jebdUnit struct {
	Class    string   `json:"class"`
	Methods  []string `json:"methods"`
	Abstract []string `json:"abstract,omitempty"`
}

type jebdUnits struct {
	Target string     `json:"target"`
	Dex    []string   `json:"dex"`
	Units  []jebdUnit `json:"units"`
	Errors []string   `json:"errors,omitempty"`
	Note   string     `json:"note,omitempty"`
}

// jebdImage is one dex the target carries: a classes*.dex on disk, or the same
// entry read out of an APK/AAB, which is the artifact a caller actually holds.
type jebdImage struct {
	Label string
	Bytes []byte
}

// jebdImages resolves a target to its dex images: every .dex inside an
// APK/AAB zip, every classes*.dex in a decoded project dir, or one plain .dex.
// The zip is read here rather than refused: a decoded project is optional, the
// APK is not (final.md y5).
func jebdImages(path string) ([]jebdImage, error) {
	if zr, err := zip.OpenReader(path); err == nil {
		defer zr.Close()
		var imgs []jebdImage
		for _, f := range zr.File {
			if !strings.HasSuffix(strings.ToLower(f.Name), ".dex") {
				continue
			}
			if b, ok := readEntry(f, opMaxFile); ok && len(b) >= dexHeaderSize && isDex(b) {
				imgs = append(imgs, jebdImage{Label: path + "!" + f.Name, Bytes: b})
			}
		}
		if len(imgs) == 0 {
			return nil, fmt.Errorf("%s carries no classes*.dex", path)
		}
		return imgs, nil
	}
	files, err := jebdDexFiles(path)
	if err != nil {
		return nil, err
	}
	imgs := make([]jebdImage, 0, len(files))
	for _, p := range files {
		b, err := opRead(p, opMaxFile)
		if err != nil {
			return nil, err
		}
		imgs = append(imgs, jebdImage{Label: p, Bytes: b})
	}
	return imgs, nil
}

func opListJebUnits(target string) (any, error) {
	imgs, err := jebdImages(target)
	if err != nil {
		return nil, err
	}
	res := jebdUnits{Target: target, Dex: []string{}, Units: []jebdUnit{}}
	parsed := 0 // images that got past the header and dexOpen: the ones with no parse to blame
	for _, img := range imgs {
		if len(img.Bytes) < dexHeaderSize || !isDex(img.Bytes) {
			res.Errors = append(res.Errors, img.Label+": not a DEX image")
			continue
		}
		units, errs := jebdUnitsOf(img.Bytes)
		if units != nil {
			parsed++
		}
		res.Dex = append(res.Dex, img.Label)
		res.Units = append(res.Units, units...)
		for _, e := range errs {
			res.Errors = append(res.Errors, img.Label+": "+e)
		}
	}
	// Every image failed to parse: zero units and nothing to list is a refusal,
	// not an empty success with an errors list a caller has to inspect. One
	// readable image is enough to keep the result; its per-file errors stay.
	if parsed == 0 {
		return nil, fmt.Errorf("%s is not a readable DEX image: %s", target, strings.Join(res.Errors, "; "))
	}
	if len(res.Units) == 0 && len(res.Errors) == 0 {
		res.Note = "the dex declares no class_defs, so there are no units to list"
	}
	return res, nil
}

// jebdDexFiles maps a target to its dex files: a plain .dex path as given, or
// the classes*.dex entries of a project dir in dex order (classes.dex first).
func jebdDexFiles(path string) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return []string{path}, nil
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	type numbered struct {
		n int
		p string
	}
	var found []numbered
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, "classes") || !strings.HasSuffix(name, ".dex") {
			continue
		}
		n := 1 // classes.dex
		if mid := strings.TrimSuffix(strings.TrimPrefix(name, "classes"), ".dex"); mid != "" {
			if n, err = strconv.Atoi(mid); err != nil || n < 2 {
				continue
			}
		}
		found = append(found, numbered{n, filepath.Join(path, name)})
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%s is a project dir with no classes*.dex; a decoded project carries the APK's classes.dex (final.md y5)", path)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].n < found[j].n })
	paths := make([]string, len(found))
	for i, f := range found {
		paths[i] = f.p
	}
	return paths, nil
}

// jebdUnitsOf walks class_defs in file order. A per-class problem is recorded
// in errs and the walk continues; only a broken header stops it.
func jebdUnitsOf(b []byte) ([]jebdUnit, []string) {
	var errs []string
	r, err := dexOpen(b, nil)
	if err != nil {
		return nil, []string{err.Error()}
	}
	// dexOpen bounds type_ids and class_defs; the other two tables the deref
	// chain walks are checked here so a crafted file cannot read out of bounds.
	if !dexIn(len(b), r.strOff, r.strSize, 4) {
		return nil, []string{fmt.Sprintf("string_ids %d@%d are past the file", r.strSize, r.strOff)}
	}
	if !dexIn(len(b), r.metOff, r.metSize, 8) {
		return nil, []string{fmt.Sprintf("method_ids %d@%d are past the file", r.metSize, r.metOff)}
	}
	n := int(u32le(b, 0x60))
	units := make([]jebdUnit, 0, n)
	for i := range n {
		at := r.clsOff + 32*i
		desc, ok := dexTypeName(r, u32le(b, at))
		if !ok {
			errs = append(errs, fmt.Sprintf("class_def %d: descriptor type %d does not resolve", i, u32le(b, at)))
			continue
		}
		u := jebdUnit{Class: desc, Methods: []string{}}
		if off := int(u32le(b, at+24)); off != 0 { // class_data_off; +28 is static_values_off
			// dexClassData walks the members once; naming them here saves the
			// copy the old jebdClassData helper made of the whole slice.
			_, methods, err := dexClassData(r, off)
			if err != nil {
				errs = append(errs, fmt.Sprintf("%s: %v", desc, err))
				units = append(units, u)
				continue
			}
			for _, m := range methods {
				name, ok := r.methodName(m.Idx)
				if !ok {
					errs = append(errs, fmt.Sprintf("%s: method_idx %d does not resolve", desc, m.Idx))
					continue
				}
				if m.CodeOff == 0 { // no code item: abstract or native
					u.Abstract = append(u.Abstract, name)
					continue
				}
				u.Methods = append(u.Methods, name)
			}
		}
		units = append(units, u)
	}
	return units, errs
}
