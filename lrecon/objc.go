package main

import (
	"debug/macho"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Objective-C metadata is four section-name-dispatched blobs, so this reader
// runs after the Mach-O reader claimed the file and never changes Kind. Only the
// NUL-separated name blocks and the classlist pointer count are read: no struct
// decode, no selector->class join, so nothing here claims a class hierarchy.
const (
	objcNoSections = "no-objc-sections"
	objcTruncated  = "objc-truncated"
	objcNameCap    = "objc-name-cap"

	// objcMaxNames bounds the blocks read from one name section. A larger
	// section is reported as capped instead of silently truncated.
	objcMaxNames = 1024
)

// objcSections is the read order; classlist is a pointer array, not names.
// The classname pool is shared with protocols, so its entries are reported as
// section names (`objc:classname=`) and never claimed to be classes: clang
// stores `@protocol Drawable` there too.
var objcSections = []struct{ name, singular, plural string }{
	{"__objc_classname", "classname", "classnames"},
	{"__objc_methname", "method", "methnames"},
	{"__objc_methtype", "type", "methtypes"},
	{"__objc_classlist", "", "classlist"},
}

func init() {
	reasonRegistry["objc"] = reasonSet(objcNoSections, objcTruncated, objcNameCap)
	register(reader{
		format:  "objc",
		post:    true,
		reasons: []string{objcNoSections, objcTruncated, objcNameCap},
		match: func(head []byte, size int64) bool {
			return isMachO(head) || fatMachOOK(head, size)
		},
		inspect: inspectObjC,
	})
}

func inspectObjC(path string, d *Digest) {
	fh, err := os.Open(path)
	if err != nil {
		return
	}
	defer fh.Close()
	var files []*macho.File
	if ff, err := macho.NewFatFile(fh); err == nil {
		defer ff.Close()
		for _, a := range ff.Arches {
			files = append(files, a.File)
		}
	} else if f, err := macho.NewFile(fh); err == nil {
		files = append(files, f)
	} else {
		return
	}
	reportObjC(files, d)
}

// reportObjC unions the name blocks over the slices of a fat file. A slice that
// matches no target section contributes nothing, so a universal binary reports
// the same names as its thin counterpart.
func reportObjC(files []*macho.File, d *Digest) {
	names := map[string]map[string]bool{}
	present := map[string]bool{}
	read := map[string]bool{}
	evidence := false
	classlist := 0
	capped := false
	for _, f := range files {
		evidence = evidence || objcEvidence(f)
		word := 8
		if f.Magic == macho.Magic32 {
			word = 4
		}
		for _, spec := range objcSections {
			sec := f.Section(spec.name)
			if sec == nil {
				continue
			}
			present[spec.name] = true
			b, err := sec.Data()
			if err != nil {
				d.skip(objcTruncated, spec.name+" declares "+strconv.FormatUint(sec.Size, 10)+" B, file is shorter")
				continue
			}
			d.scanned(int64(len(b)))
			read[spec.name] = true
			if spec.plural == "classlist" {
				if len(b)%word != 0 {
					d.skip(objcTruncated, spec.name+" size is not a multiple of the pointer width")
				}
				classlist += len(b) / word
				continue
			}
			if names[spec.name] == nil {
				names[spec.name] = map[string]bool{}
			}
			seen := 0
			for block := range strings.SplitSeq(string(b), "\x00") {
				if block == "" {
					continue
				}
				if seen >= objcMaxNames {
					capped = true
					break
				}
				seen++
				if !objcPrintable(block) {
					d.unparsed()
					continue
				}
				names[spec.name][block] = true
				d.parsed()
			}
		}
	}
	if len(present) == 0 {
		// A Mach-O without a single __objc_ section and no ObjC symbol is a C or
		// Swift binary: silence keeps "no metadata" out of every Mach-O digest.
		if evidence {
			d.skip(objcNoSections, "ObjC markers present, none of the four name sections")
		}
		return
	}
	if capped {
		d.skip(objcNameCap, "more than "+strconv.Itoa(objcMaxNames)+" name blocks in one section, refused past the cap")
	}

	var caps []string
	for _, spec := range objcSections {
		if !read[spec.name] {
			continue
		}
		if spec.plural == "classlist" {
			caps = append(caps, "objc:classlist="+strconv.FormatInt(int64(classlist), 10))
			continue
		}
		list := make([]string, 0, len(names[spec.name]))
		for n := range names[spec.name] {
			list = append(list, n)
		}
		sort.Strings(list)
		key := "objc:" + spec.plural
		caps = append(caps, key+"="+strconv.Itoa(len(list)))
		for _, n := range list {
			caps = append(caps, "objc:"+spec.singular+"="+n)
		}
	}
	d.Capabilities = append(d.Capabilities, uniqued(caps)...)
}

// objcEvidence reports whether the file was built with any Objective-C at all:
// a support section, an __OBJC segment or the linker's OBJC_ symbols. It only
// decides whether a missing name section is worth reporting.
func objcEvidence(f *macho.File) bool {
	for _, s := range f.Sections {
		if s.Seg == "__OBJC" || strings.HasPrefix(s.Name, "__objc_") {
			return true
		}
	}
	if f.Symtab != nil {
		for _, sym := range f.Symtab.Syms {
			if strings.HasPrefix(sym.Name, "_OBJC_") || strings.HasPrefix(sym.Name, "OBJC_") {
				return true
			}
		}
	}
	return false
}

// objcPrintable keeps binary junk out of a name list: selectors, class names and
// type encodings are all short ASCII.
func objcPrintable(s string) bool {
	if len(s) > 256 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
