package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
)

// Model weights: safetensors opens with an 8-byte little-endian JSON header
// length, GGUF with "GGUF" and a typed key/value table. Both carry a tensor
// table, so the answer names every tensor with its dtype/shape or type/offset
// straight from the header. safetensors data_offsets are checked against the
// real bytes; GGUF offsets are reported as declared, since where the payload
// starts depends on the file's general.alignment setting.

var ggufValueNames = map[uint32]string{
	0: "uint8", 1: "int8", 2: "uint16", 3: "int16", 4: "uint32", 5: "int32",
	6: "float32", 7: "bool", 8: "string", 9: "array", 10: "uint64", 11: "int64", 12: "float64",
}

var ggmlTypeNames = map[uint32]string{
	0: "F32", 1: "F16", 2: "Q4_0", 3: "Q4_1", 6: "Q5_0", 7: "Q5_1", 8: "Q8_0", 9: "Q8_1",
	10: "Q2_K", 11: "Q3_K", 12: "Q4_K", 13: "Q5_K", 14: "Q6_K", 15: "Q8_K",
	16: "IQ2_XXS", 17: "IQ2_XS", 18: "IQ3_XXS", 19: "IQ1_S", 20: "IQ4_NL",
	21: "IQ3_S", 22: "IQ2_S", 23: "IQ4_XS", 24: "I8", 25: "I16", 26: "I32",
	27: "I64", 28: "F64", 29: "IQ1_M", 30: "BF16",
}

var sfDtypeSizes = map[string]uint64{
	"F64": 8, "F32": 4, "F16": 2, "BF16": 2, "I64": 8, "I32": 4, "I16": 2,
	"I8": 1, "U8": 1, "BOOL": 1, "F8_E4M3": 1, "F8_E5M2": 1,
}

type modelTensor struct {
	Name     string   `json:"name"`
	DType    string   `json:"dtype,omitempty"`
	Shape    []uint64 `json:"shape,omitempty"`
	Elements uint64   `json:"elements,omitempty"`
	Begin    uint64   `json:"begin,omitempty"`
	End      uint64   `json:"end,omitempty"`
	Bytes    uint64   `json:"bytes,omitempty"`
	Type     uint32   `json:"ggml_type,omitempty"`
	TypeName string   `json:"ggml_type_name,omitempty"`
	Offset   uint64   `json:"offset,omitempty"`
}

type ggufKV struct {
	Key   string `json:"key"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type ggCursor struct {
	b []byte
	i int
}

func (c *ggCursor) take(n uint64) ([]byte, bool) {
	if n > uint64(len(c.b)-c.i) {
		return nil, false
	}
	p := c.b[c.i : c.i+int(n)]
	c.i += int(n)
	return p, true
}

func (c *ggCursor) u8() (uint8, bool) {
	p, ok := c.take(1)
	if !ok {
		return 0, false
	}
	return p[0], true
}
func (c *ggCursor) u16() (uint16, bool) {
	p, ok := c.take(2)
	if !ok {
		return 0, false
	}
	return u16le(p, 0), true
}
func (c *ggCursor) u32() (uint32, bool) {
	p, ok := c.take(4)
	if !ok {
		return 0, false
	}
	return u32le(p, 0), true
}
func (c *ggCursor) u64() (uint64, bool) {
	p, ok := c.take(8)
	if !ok {
		return 0, false
	}
	return u64le(p, 0), true
}
func (c *ggCursor) str() (string, bool) {
	n, ok := c.u64()
	if !ok || n > 1<<24 {
		return "", false
	}
	p, ok := c.take(n)
	if !ok {
		return "", false
	}
	return string(p), true
}

func init() {
	registerOp(op{
		name:  "inspect_model_artifact",
		route: "L",
		needs: true,
		desc:  "safetensors header (u64 length + JSON dtype/shape/offsets) or GGUF typed metadata and tensor table",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			if len(b) >= 4 && string(b[:4]) == "GGUF" {
				return inspectGGUF(path, b)
			}
			return inspectSafetensors(path, b)
		},
	})
}

func inspectSafetensors(path string, b []byte) (any, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("%s is %d bytes, shorter than the 8-byte header length", path, len(b))
	}
	hdr := u64le(b, 0)
	if hdr == 0 || hdr > uint64(len(b)-8) {
		return nil, fmt.Errorf("%s safetensors header declares %d bytes, file holds %d", path, hdr, len(b)-8)
	}
	header := b[8 : 8+hdr]
	data := b[8+hdr:]
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(header, &raw); err != nil {
		return nil, fmt.Errorf("%s safetensors header: %v", path, err)
	}
	res := struct {
		Format  string            `json:"format"`
		Header  uint64            `json:"header_bytes"`
		Data    uint64            `json:"data_bytes"`
		Meta    map[string]string `json:"metadata,omitempty"`
		Tensors []modelTensor     `json:"tensors"`
	}{Format: "safetensors", Header: hdr, Data: uint64(len(data))}
	for _, name := range sfSortedKeys(raw) {
		v := raw[name]
		if name == "__metadata__" {
			if err := json.Unmarshal(v, &res.Meta); err != nil {
				return nil, fmt.Errorf("%s safetensors metadata: %v", path, err)
			}
			continue
		}
		var t struct {
			DType   string   `json:"dtype"`
			Shape   []uint64 `json:"shape"`
			Offsets []uint64 `json:"data_offsets"`
		}
		if err := json.Unmarshal(v, &t); err != nil {
			return nil, fmt.Errorf("%s safetensors tensor %q: %v", path, name, err)
		}
		if t.DType == "" || len(t.Offsets) != 2 {
			return nil, fmt.Errorf("%s safetensors tensor %q has no dtype or no data_offsets pair", path, name)
		}
		begin, end := t.Offsets[0], t.Offsets[1]
		if begin > end || end > uint64(len(data)) {
			return nil, fmt.Errorf("%s safetensors tensor %q spans %d..%d of %d data bytes", path, name, begin, end, len(data))
		}
		elements := uint64(1)
		for _, d := range t.Shape {
			if d != 0 && elements > math.MaxUint64/d {
				return nil, fmt.Errorf("%s safetensors tensor %q shape overflows", path, name)
			}
			elements *= d
		}
		if size, known := sfDtypeSizes[t.DType]; known && elements*size != end-begin {
			return nil, fmt.Errorf("%s safetensors tensor %q is %s %v = %d bytes, offsets say %d",
				path, name, t.DType, t.Shape, elements*size, end-begin)
		}
		res.Tensors = append(res.Tensors, modelTensor{Name: name, DType: t.DType, Shape: t.Shape,
			Elements: elements, Begin: begin, End: end, Bytes: end - begin})
	}
	if len(res.Tensors) == 0 {
		return nil, fmt.Errorf("%s safetensors header carries no tensor", path)
	}
	return res, nil
}

func inspectGGUF(path string, b []byte) (any, error) {
	if len(b) < 24 {
		return nil, fmt.Errorf("%s is %d bytes, shorter than the GGUF header", path, len(b))
	}
	version := u32le(b, 4)
	if version < 2 || version > 3 {
		return nil, fmt.Errorf("%s is GGUF version %d, not 2 or 3", path, version)
	}
	tensors, kvs := u64le(b, 8), u64le(b, 16)
	if tensors > 1<<24 || kvs > 1<<24 {
		return nil, fmt.Errorf("%s GGUF declares %d tensors and %d metadata entries", path, tensors, kvs)
	}
	c := &ggCursor{b: b, i: 24}
	res := struct {
		Format   string        `json:"format"`
		Version  uint32        `json:"version"`
		Declared uint64        `json:"tensor_count"`
		Metadata []ggufKV      `json:"metadata"`
		Tensors  []modelTensor `json:"tensors"`
	}{Format: "gguf", Version: version, Declared: tensors}
	for i := range kvs {
		key, ok := c.str()
		if !ok {
			return nil, fmt.Errorf("%s GGUF metadata %d has a cut key", path, i)
		}
		typ, ok := c.u32()
		if !ok {
			return nil, fmt.Errorf("%s GGUF metadata %q has no type", path, key)
		}
		val, name, err := ggufValue(c, typ, 0)
		if err != nil {
			return nil, fmt.Errorf("%s GGUF metadata %q: %v", path, key, err)
		}
		res.Metadata = append(res.Metadata, ggufKV{Key: key, Type: name, Value: val})
	}
	for i := range tensors {
		name, ok := c.str()
		if !ok {
			return nil, fmt.Errorf("%s GGUF tensor %d has a cut name", path, i)
		}
		nd, ok := c.u32()
		if !ok || nd > 8 {
			return nil, fmt.Errorf("%s GGUF tensor %q has %d dimensions", path, name, nd)
		}
		shape := make([]uint64, nd)
		for j := range shape {
			if shape[j], ok = c.u64(); !ok {
				return nil, fmt.Errorf("%s GGUF tensor %q has a cut shape", path, name)
			}
		}
		typ, ok := c.u32()
		if !ok {
			return nil, fmt.Errorf("%s GGUF tensor %q has no ggml type", path, name)
		}
		off, ok := c.u64()
		if !ok {
			return nil, fmt.Errorf("%s GGUF tensor %q has no data offset", path, name)
		}
		res.Tensors = append(res.Tensors, modelTensor{Name: name, Shape: shape, Type: typ,
			TypeName: ggmlTypeNames[typ], Offset: off})
	}
	if len(res.Tensors) == 0 {
		return nil, fmt.Errorf("%s GGUF header carries no tensor", path)
	}
	return res, nil
}

// ggufValue decodes one typed metadata value. Arrays recurse, so depth is
// capped: real files nest at most one level.
func ggufValue(c *ggCursor, typ uint32, depth int) (any, string, error) {
	name := ggufValueNames[typ]
	if name == "" {
		return nil, "", fmt.Errorf("unknown value type %d", typ)
	}
	if depth > 4 {
		return nil, name, fmt.Errorf("array nesting is deeper than 4")
	}
	switch typ {
	case 0:
		v, ok := c.u8()
		if !ok {
			return nil, name, fmt.Errorf("cut uint8")
		}
		return v, name, nil
	case 1:
		v, ok := c.u8()
		if !ok {
			return nil, name, fmt.Errorf("cut int8")
		}
		return int8(v), name, nil
	case 2:
		v, ok := c.u16()
		if !ok {
			return nil, name, fmt.Errorf("cut uint16")
		}
		return v, name, nil
	case 3:
		v, ok := c.u16()
		if !ok {
			return nil, name, fmt.Errorf("cut int16")
		}
		return int16(v), name, nil
	case 4:
		v, ok := c.u32()
		if !ok {
			return nil, name, fmt.Errorf("cut uint32")
		}
		return v, name, nil
	case 5:
		v, ok := c.u32()
		if !ok {
			return nil, name, fmt.Errorf("cut int32")
		}
		return int32(v), name, nil
	case 6:
		v, ok := c.u32()
		if !ok {
			return nil, name, fmt.Errorf("cut float32")
		}
		return math.Float32frombits(v), name, nil
	case 7:
		v, ok := c.u8()
		if !ok {
			return nil, name, fmt.Errorf("cut bool")
		}
		return v != 0, name, nil
	case 8:
		v, ok := c.str()
		if !ok {
			return nil, name, fmt.Errorf("cut string")
		}
		return v, name, nil
	case 9:
		et, ok := c.u32()
		if !ok {
			return nil, name, fmt.Errorf("array has no element type")
		}
		if ggufValueNames[et] == "" {
			return nil, name, fmt.Errorf("array element type %d is unknown", et)
		}
		n, ok := c.u64()
		if !ok {
			return nil, name, fmt.Errorf("array has no count")
		}
		if n > 1<<24 {
			return nil, name, fmt.Errorf("array declares %d elements", n)
		}
		arr := make([]any, 0, n)
		for i := range n {
			v, _, err := ggufValue(c, et, depth+1)
			if err != nil {
				return nil, name, fmt.Errorf("array element %d: %v", i, err)
			}
			arr = append(arr, v)
		}
		return arr, name, nil
	case 10:
		v, ok := c.u64()
		if !ok {
			return nil, name, fmt.Errorf("cut uint64")
		}
		return v, name, nil
	case 11:
		v, ok := c.u64()
		if !ok {
			return nil, name, fmt.Errorf("cut int64")
		}
		return int64(v), name, nil
	case 12:
		v, ok := c.u64()
		if !ok {
			return nil, name, fmt.Errorf("cut float64")
		}
		return math.Float64frombits(v), name, nil
	}
	return nil, name, fmt.Errorf("unhandled value type %d", typ)
}

func sfSortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
