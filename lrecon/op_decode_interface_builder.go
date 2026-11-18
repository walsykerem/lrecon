package main

import (
	"fmt"
	"strings"
)

// A compiled nib (NIBArchive) is a header followed by four variable-length
// tables: objects, key strings, coder values and class names. All counts are
// VInt32 (7 bits per byte, little-endian, high bit set on the last byte).
const (
	nibHeaderSize = 50

	nibValueInt8      = 0
	nibValueInt16     = 1
	nibValueInt32     = 2
	nibValueInt64     = 3
	nibValueFalse     = 4
	nibValueTrue      = 5
	nibValueFloat     = 6
	nibValueDouble    = 7
	nibValueBytes     = 8
	nibValueNil       = 9
	nibValueReference = 10
)

type nibObject struct {
	class      int
	valueStart int
	valueCount int
}

type nibValue struct {
	key  int
	typ  uint8
	ref  uint32
	data []byte
}

type nibArchive struct {
	version uint32
	coder   uint32
	keys    []string
	values  []nibValue
	objects []nibObject
	classes []string
}

func init() {
	registerOp(op{
		name:  "decode_interface_builder",
		route: "L",
		needs: true,
		desc:  "read a compiled NIBArchive: table counts and the real outlet/action names carried by NSNibOutletConnector/NSNibControlConnector objects",
		run: func(path string) (any, error) {
			b, err := opRead(path, 64<<20)
			if err != nil {
				return nil, err
			}
			a, err := nibParse(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			outlets, actions := nibConnections(a)
			outlets = uniqSorted(outlets)
			actions = uniqSorted(actions)
			if len(outlets) > 40 {
				outlets = outlets[:40]
			}
			res := struct {
				Version uint32   `json:"version"`
				Coder   uint32   `json:"coder_version"`
				Objects int      `json:"objects"`
				Keys    int      `json:"keys"`
				Classes int      `json:"classes"`
				Outlets []string `json:"outlets,omitempty"`
				Actions []string `json:"actions,omitempty"`
			}{Version: a.version, Coder: a.coder, Objects: len(a.objects),
				Keys: len(a.keys), Classes: len(a.classes),
				Outlets: outlets, Actions: actions}
			return res, nil
		},
	})
}

// nibVInt decodes one VInt32 and returns the position after it. The high bit is
// set on the most significant (last) byte, not on continuation bytes.
func nibVInt(b []byte, off int) (uint32, int, error) {
	var v uint64
	for shift := uint(0); shift <= 28; shift += 7 {
		if off < 0 || off >= len(b) {
			return 0, off, fmt.Errorf("vint runs past the end of the file")
		}
		c := b[off]
		off++
		v |= uint64(c&0x7f) << shift
		if c&0x80 != 0 {
			if v > 0xffffffff {
				return 0, off, fmt.Errorf("vint %#x does not fit in 32 bits", v)
			}
			return uint32(v), off, nil
		}
	}
	return 0, off, fmt.Errorf("vint is longer than 5 bytes")
}

func nibParse(b []byte) (*nibArchive, error) {
	if len(b) < nibHeaderSize || string(b[:10]) != "NIBArchive" {
		return nil, fmt.Errorf("not a NIBArchive")
	}
	a := &nibArchive{version: u32le(b, 10), coder: u32le(b, 14)}
	objectCount := int(u32le(b, 18))
	objectOff := int(u32le(b, 22))
	keyCount := int(u32le(b, 26))
	keyOff := int(u32le(b, 30))
	valueCount := int(u32le(b, 34))
	valueOff := int(u32le(b, 38))
	classCount := int(u32le(b, 42))
	classOff := int(u32le(b, 46))
	for _, t := range []struct {
		name string
		off  int
		n    int
	}{{"objects", objectOff, objectCount}, {"keys", keyOff, keyCount}, {"values", valueOff, valueCount}, {"class names", classOff, classCount}} {
		if t.off < nibHeaderSize || t.off > len(b) || t.n < 0 || t.n > len(b) {
			return nil, fmt.Errorf("%s table offset %d / count %d out of range", t.name, t.off, t.n)
		}
	}
	if objectCount == 0 {
		return nil, fmt.Errorf("declares zero objects")
	}

	for off, i := keyOff, 0; i < keyCount; i++ {
		n, next, err := nibVInt(b, off)
		if err != nil {
			return nil, fmt.Errorf("key %d: %w", i, err)
		}
		if n == 0 || next+int(n) > len(b) {
			return nil, fmt.Errorf("key %d has a bad length %d", i, n)
		}
		name := b[next : next+int(n)]
		if !printableASCII(name) {
			return nil, fmt.Errorf("key %d is not printable", i)
		}
		a.keys = append(a.keys, string(name))
		off = next + int(n)
	}

	for off, i := valueOff, 0; i < valueCount; i++ {
		key, next, err := nibVInt(b, off)
		if err != nil {
			return nil, fmt.Errorf("value %d: %w", i, err)
		}
		if int(key) >= len(a.keys) {
			return nil, fmt.Errorf("value %d names key %d of %d", i, key, len(a.keys))
		}
		if next >= len(b) {
			return nil, fmt.Errorf("value %d has no type byte", i)
		}
		t := b[next]
		next++
		v := nibValue{key: int(key), typ: t}
		size := 0
		switch t {
		case nibValueInt8:
			size = 1
		case nibValueInt16:
			size = 2
		case nibValueInt32, nibValueFloat, nibValueReference:
			size = 4
		case nibValueInt64, nibValueDouble:
			size = 8
		case nibValueFalse, nibValueTrue, nibValueNil:
		case nibValueBytes:
			n, after, err := nibVInt(b, next)
			if err != nil {
				return nil, fmt.Errorf("value %d bytes: %w", i, err)
			}
			if after+int(n) > len(b) {
				return nil, fmt.Errorf("value %d bytes run past the end of the file", i)
			}
			v.data = b[after : after+int(n)]
			next = after + int(n)
		default:
			return nil, fmt.Errorf("value %d has unknown type %d", i, t)
		}
		if size > 0 {
			if next+size > len(b) {
				return nil, fmt.Errorf("value %d payload runs past the end of the file", i)
			}
			if t == nibValueReference {
				v.ref = u32le(b, next)
			}
			v.data = b[next : next+size]
			next += size
		}
		a.values = append(a.values, v)
		off = next
	}

	for off, i := objectOff, 0; i < objectCount; i++ {
		class, next, err := nibVInt(b, off)
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		start, next2, err := nibVInt(b, next)
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		count, next3, err := nibVInt(b, next2)
		if err != nil {
			return nil, fmt.Errorf("object %d: %w", i, err)
		}
		if int(class) >= classCount || int(start)+int(count) > len(a.values) && count != 0 {
			return nil, fmt.Errorf("object %d references class %d / values %d..%d out of range", i, class, start, int(start)+int(count))
		}
		a.objects = append(a.objects, nibObject{class: int(class), valueStart: int(start), valueCount: int(count)})
		off = next3
	}

	for off, i := classOff, 0; i < classCount; i++ {
		n, next, err := nibVInt(b, off)
		if err != nil {
			return nil, fmt.Errorf("class %d: %w", i, err)
		}
		fallbacks, next2, err := nibVInt(b, next)
		if err != nil {
			return nil, fmt.Errorf("class %d: %w", i, err)
		}
		next2 += 4 * int(fallbacks)
		if n == 0 || next2+int(n) > len(b) {
			return nil, fmt.Errorf("class %d has a bad name length %d", i, n)
		}
		name := strings.TrimRight(string(b[next2:next2+int(n)]), "\x00")
		if !printableASCII([]byte(name)) {
			return nil, fmt.Errorf("class %d is not printable", i)
		}
		a.classes = append(a.classes, name)
		off = next2 + int(n)
	}
	return a, nil
}

// nibConnections resolves the archive's real connections. The key table alone is
// a global dictionary (NSConnections, NSWindowTemplate, ...): outlet and action
// names live in NSString objects referenced by the NSLabel value of
// NSNibOutletConnector (outlet) and NSNibControlConnector (action) objects.
func nibConnections(a *nibArchive) (outlets, actions []string) {
	seen := map[string]bool{}
	for _, o := range a.objects {
		if o.class >= len(a.classes) {
			continue
		}
		var kind string
		switch a.classes[o.class] {
		case "NSNibOutletConnector":
			kind = "outlet"
		case "NSNibControlConnector":
			kind = "action"
		default:
			continue
		}
		name, ok := a.nibLabel(o)
		if !ok {
			continue
		}
		key := kind + "\x00" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		if kind == "outlet" {
			outlets = append(outlets, name)
		} else {
			actions = append(actions, name)
		}
	}
	return outlets, actions
}

// nibLabel follows an object's NSLabel reference to the string object it names.
func (a *nibArchive) nibLabel(o nibObject) (string, bool) {
	if o.valueCount <= 0 || o.valueStart < 0 || o.valueStart+o.valueCount > len(a.values) {
		return "", false
	}
	for _, v := range a.values[o.valueStart : o.valueStart+o.valueCount] {
		if a.keys[v.key] != "NSLabel" || v.typ != nibValueReference {
			continue
		}
		if int(v.ref) >= len(a.objects) {
			return "", false
		}
		target := a.objects[v.ref]
		if target.valueCount <= 0 || target.valueStart < 0 || target.valueStart+target.valueCount > len(a.values) {
			return "", false
		}
		for _, tv := range a.values[target.valueStart : target.valueStart+target.valueCount] {
			if tv.typ == nibValueBytes {
				s := string(tv.data)
				if printableASCII([]byte(s)) && s != "" {
					return s, true
				}
			}
		}
	}
	return "", false
}
