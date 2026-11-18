package main

import (
	"encoding/binary"
	"fmt"
	"sort"
	"unicode/utf16"
)

func init() {
	registerOp(op{
		name:  "inspect_keyed_archive",
		route: "L",
		needs: true,
		desc:  "NSKeyedArchiver bplist: $archiver, $top keys, $objects count and the $class/$classname histogram",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			p, err := openBplist(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			keys, vals, isDict, err := p.entry(p.top)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if !isDict {
				return skipf("%s top object is not a dictionary (not an NSKeyedArchiver)", path), nil
			}
			res := struct {
				Archiver   string   `json:"archiver,omitempty"`
				TopKeys    []string `json:"top_keys"`
				Objects    int      `json:"objects"`
				ClassCount int      `json:"classes"`
				ClassNames []string `json:"class_names,omitempty"`
				Histogram  []string `json:"class_histogram,omitempty"`
			}{TopKeys: []string{}}
			var roots []int
			haveRoots := false
			for i, k := range keys {
				name, _ := p.str(k)
				res.TopKeys = append(res.TopKeys, name)
				switch name {
				case "$archiver":
					res.Archiver, _ = p.str(vals[i])
				case "$objects":
					refs, _, ok, e := p.array(vals[i])
					if e != nil {
						return nil, fmt.Errorf("%s: %w", path, e)
					}
					if ok {
						roots, haveRoots = refs, true
					}
				}
			}
			if !haveRoots {
				return skipf("%s top object has no $objects array", path), nil
			}
			res.Objects = len(roots)
			// Each archived instance is a dict carrying "$class" → class dict → "$classname".
			counts := map[string]int{}
			for _, ref := range roots {
				ks, vs, ok, e := p.entry(ref)
				if e != nil || !ok {
					continue
				}
				classRef := -1
				for j, k := range ks {
					if n, _ := p.str(k); n == "$class" {
						classRef = vs[j]
						break
					}
				}
				if classRef < 0 {
					continue
				}
				// $class is either the class dict itself or a UID. A UID names an
				// index into the $objects array, not an object-table slot: the
				// array elements are references, so resolve the index through it.
				if idx, isUID := p.uid(classRef); isUID {
					if idx < 0 || idx >= len(roots) {
						continue
					}
					classRef = roots[idx]
				}
				cks, cvs, ok, e := p.entry(classRef)
				if e != nil || !ok {
					continue
				}
				for j, k := range cks {
					if n, _ := p.str(k); n == "$classname" {
						if cn, ok := p.str(cvs[j]); ok {
							counts[cn]++
						}
					}
				}
			}
			// Every class dict ("$classname") declares a class; count the ones
			// no instance references so the inventory is complete.
			for _, ref := range roots {
				ks, vs, ok, e := p.entry(ref)
				if e != nil || !ok {
					continue
				}
				for j, k := range ks {
					if n, _ := p.str(k); n == "$classname" {
						if cn, ok := p.str(vs[j]); ok {
							if _, seen := counts[cn]; !seen {
								counts[cn] = 0
							}
						}
					}
				}
			}
			for name, n := range counts {
				res.ClassNames = append(res.ClassNames, name)
				res.Histogram = append(res.Histogram, fmt.Sprintf("%s=%d", name, n))
			}
			sort.Strings(res.ClassNames)
			sort.Strings(res.Histogram)
			res.ClassCount = len(counts)
			if res.ClassCount == 0 {
				return skipf("%s carries no $class references in $objects", path), nil
			}
			return res, nil
		},
	})
}

// bplist is a minimal binary-plist reader: object offsets plus typed accessors.
type bplist struct {
	b       []byte
	offs    []int
	top     int
	refSize int
}

func openBplist(b []byte) (*bplist, error) {
	if len(b) < 40 || string(b[:8]) != "bplist00" {
		return nil, fmt.Errorf("not a bplist00 archive")
	}
	tr := b[len(b)-32:]
	offSize := int(tr[6])
	if offSize < 1 || offSize > 8 {
		return nil, fmt.Errorf("offset int size %d out of range", offSize)
	}
	n := int(binary.BigEndian.Uint64(tr[8:16]))
	top := int(binary.BigEndian.Uint64(tr[16:24]))
	table := int(binary.BigEndian.Uint64(tr[24:32]))
	if n <= 0 || n > 1<<24 || top < 0 || top >= n {
		return nil, fmt.Errorf("trailer declares %d objects, top %d", n, top)
	}
	if table < 8 || table+offSize*n > len(b)-32 {
		return nil, fmt.Errorf("offset table %d+%d×%d escapes the file", table, n, offSize)
	}
	p := &bplist{b: b, top: top, refSize: int(tr[7])}
	if p.refSize < 1 || p.refSize > 8 {
		return nil, fmt.Errorf("object ref size %d out of range", p.refSize)
	}
	for i := range n {
		p.offs = append(p.offs, int(readUintBE(b[table+i*offSize:table+(i+1)*offSize])))
	}
	return p, nil
}

// count decodes an object's element count, following the 0xF extended form.
func (p *bplist) count(off, lo int) (int, error) {
	if lo != 0xF {
		return lo, nil
	}
	if off+1 >= len(p.b) || p.b[off+1]&0xF0 != 0x10 {
		return 0, fmt.Errorf("object at %d has no extended count", off)
	}
	sz := 1 << (p.b[off+1] & 0xF)
	if off+2+sz > len(p.b) {
		return 0, fmt.Errorf("extended count at %d is cut", off)
	}
	v := readUintBE(p.b[off+2 : off+2+sz])
	// int() of a 64-bit count can wrap negative, and a huge count wraps the
	// later n*refSize bounds checks back under len(b), so reject it here like
	// bplistString does (a count can never exceed the file size anyway).
	if v > uint64(len(p.b)) {
		return 0, fmt.Errorf("extended count at %d exceeds the file size", off)
	}
	return int(v), nil
}

func (p *bplist) obj(i int) int { return p.offs[i] }

func (p *bplist) ref(at int) int { return int(readUintBE(p.b[at : at+p.refSize])) }

// entry returns a dict's key/value refs, or ok=false when the object is not a dict.
func (p *bplist) entry(i int) (keys, vals []int, ok bool, err error) {
	if i < 0 || i >= len(p.offs) {
		return nil, nil, false, fmt.Errorf("object ref %d out of range", i)
	}
	off := p.offs[i]
	if off+1 > len(p.b) {
		return nil, nil, false, fmt.Errorf("object %d offset %d past end", i, off)
	}
	if p.b[off]>>4 != 0xD {
		return nil, nil, false, nil
	}
	n, err := p.count(off, int(p.b[off]&0xF))
	if err != nil {
		return nil, nil, false, err
	}
	p0 := off + 1
	if p.b[off]&0xF == 0xF {
		p0 = off + 2 + (1 << (p.b[off+1] & 0xF))
	}
	if p0+n*2*p.refSize > len(p.b) {
		return nil, nil, false, fmt.Errorf("dict object %d declares %d pairs past end", i, n)
	}
	for k := range n {
		keys = append(keys, p.ref(p0+k*p.refSize))
	}
	for k := range n {
		vals = append(vals, p.ref(p0+(n+k)*p.refSize))
	}
	return keys, vals, true, nil
}

// array returns an array object's element refs.
func (p *bplist) array(i int) (refs []int, n int, ok bool, err error) {
	if i < 0 || i >= len(p.offs) {
		return nil, 0, false, fmt.Errorf("object ref %d out of range", i)
	}
	off := p.offs[i]
	if off+1 > len(p.b) || p.b[off]>>4 != 0xA {
		return nil, 0, false, nil
	}
	count, err := p.count(off, int(p.b[off]&0xF))
	if err != nil {
		return nil, 0, false, err
	}
	start := off + 1
	if p.b[off]&0xF == 0xF {
		start = off + 2 + (1 << (p.b[off+1] & 0xF))
	}
	if start+count*p.refSize > len(p.b) {
		return nil, 0, false, fmt.Errorf("array object %d declares %d refs past end", i, count)
	}
	for k := range count {
		refs = append(refs, p.ref(start+k*p.refSize))
	}
	return refs, count, true, nil
}

// str returns the string value of an object ref (ASCII or UTF-16BE).
func (p *bplist) str(i int) (string, bool) {
	if i < 0 || i >= len(p.offs) {
		return "", false
	}
	off := p.offs[i]
	if off+1 > len(p.b) {
		return "", false
	}
	marker, lo := p.b[off]>>4, int(p.b[off]&0xF)
	n, err := p.count(off, lo)
	if err != nil {
		return "", false
	}
	start := off + 1
	if lo == 0xF {
		start = off + 2 + (1 << (p.b[off+1] & 0xF))
	}
	switch marker {
	case 0x5:
		if start+n > len(p.b) {
			return "", false
		}
		return string(p.b[start : start+n]), true
	case 0x6:
		if start+2*n > len(p.b) {
			return "", false
		}
		u := make([]uint16, n)
		for k := range n {
			u[k] = binary.BigEndian.Uint16(p.b[start+2*k:])
		}
		return string(utf16.Decode(u)), true
	}
	return "", false
}

// uid decodes a 0x8N UID object into the $objects index it names.
func (p *bplist) uid(i int) (int, bool) {
	if i < 0 || i >= len(p.offs) {
		return 0, false
	}
	off := p.offs[i]
	if off+1 > len(p.b) || p.b[off]>>4 != 0x8 {
		return 0, false
	}
	size := 1 << (p.b[off] & 0xF)
	if size > 8 || off+1+size > len(p.b) {
		return 0, false
	}
	return int(readUintBE(p.b[off+1 : off+1+size])), true
}
