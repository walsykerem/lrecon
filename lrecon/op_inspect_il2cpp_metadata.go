package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

// final.md: inspect_il2cpp_metadata.
func init() {
	registerOp(op{
		name:  "inspect_il2cpp_metadata",
		route: "L",
		desc:  "Unity IL2CPP: global-metadata.dat version with type and method tables, or the il2cpp marker in a player image",
		needs: true,
		run: func(path string) (any, error) {
			d, err := Probe(path)
			if err != nil {
				return nil, err
			}
			if d.Kind == "il2cpp-metadata" {
				return inspectIl2cppMetadata(path)
			}
			if !slices.Contains(d.Capabilities, "il2cpp") {
				return skipf("%s carries no IL2CPP marker (no global-metadata.dat reference or Unity player strings)", path), nil
			}
			return struct {
				Kind         string   `json:"kind"`
				Toolchain    string   `json:"toolchain,omitempty"`
				Capabilities []string `json:"capabilities"`
			}{d.Kind, d.Toolchain, d.Capabilities}, nil
		},
	})
}

// il2cppHeader is the part of Il2CppGlobalMetadataHeader that all supported
// versions share: the string pool and the type/method tables sit at fixed
// offsets from 8 onward, before any versioned tail.
type il2cppHeader struct {
	version    int
	stringOff  int
	stringSize int
	methodsOff int
	methodsLen int
	typesOff   int
	typesLen   int
}

func inspectIl2cppMetadata(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	h, err := il2cppParseHeader(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if h.version < 27 {
		// The type table grew and shrank across 16..26 (rgctx, byref,
		// custom-attribute fields), so a fixed stride would report names from
		// the wrong bytes. The version is still worth answering.
		return struct {
			Kind         string   `json:"kind"`
			Version      int      `json:"version"`
			TypesCount   int      `json:"types_count"`
			MethodsCount int      `json:"methods_count"`
			Notes        []string `json:"notes,omitempty"`
		}{"il2cpp-metadata", h.version, 0, 0,
			[]string{"type and method tables before version 27 are not decoded"}}, nil
	}
	typeStride, methodStride := 88, 32
	if h.version >= 31 {
		methodStride = 36 // v31 added returnParameterToken
	}
	if h.typesLen%typeStride != 0 {
		return nil, fmt.Errorf("type definition table is %d bytes, not a multiple of %d", h.typesLen, typeStride)
	}
	if h.methodsLen%methodStride != 0 {
		return nil, fmt.Errorf("method table is %d bytes, not a multiple of %d", h.methodsLen, methodStride)
	}
	typeCount := h.typesLen / typeStride
	methodCount := h.methodsLen / methodStride
	if typeCount == 0 && methodCount == 0 {
		return struct {
			Kind         string   `json:"kind"`
			Version      int      `json:"version"`
			TypesCount   int      `json:"types_count"`
			MethodsCount int      `json:"methods_count"`
			Notes        []string `json:"notes,omitempty"`
		}{"il2cpp-metadata", h.version, 0, 0,
			[]string{"header is valid but the type and method tables are empty"}}, nil
	}

	// Type names are needed as the prefix of every method, so read all of them
	// even when the JSON list below is capped.
	typeNames := make([]string, typeCount)
	types := make([]il2cppType, 0, min(typeCount, 1000))
	for i := range typeCount {
		p := h.typesOff + i*typeStride
		name := il2cppString(b, h, int(binary.LittleEndian.Uint32(b[p:])))
		ns := il2cppString(b, h, int(binary.LittleEndian.Uint32(b[p+4:])))
		full := name
		if ns != "" {
			full = ns + "." + name
		}
		typeNames[i] = full
		if i < 1000 {
			types = append(types, il2cppType{
				Name:      full,
				Namespace: ns,
				Methods:   int(binary.LittleEndian.Uint16(b[p+64:])),
				Token:     binary.LittleEndian.Uint32(b[p+84:]),
			})
		}
	}
	methods := make([]il2cppMethod, 0, min(methodCount, 1000))
	tokenOff := 20
	if h.version >= 31 {
		tokenOff = 24 // returnParameterToken shifted token down
	}
	for i := 0; i < methodCount && i < 1000; i++ {
		p := h.methodsOff + i*methodStride
		decl := int(int32(binary.LittleEndian.Uint32(b[p+4:])))
		owner := ""
		if decl >= 0 && decl < len(typeNames) {
			owner = typeNames[decl]
		}
		methods = append(methods, il2cppMethod{
			Name:  il2cppString(b, h, int(binary.LittleEndian.Uint32(b[p:]))),
			Type:  owner,
			Token: binary.LittleEndian.Uint32(b[p+tokenOff:]),
		})
	}
	res := struct {
		Kind         string         `json:"kind"`
		Version      int            `json:"version"`
		TypesCount   int            `json:"types_count"`
		Types        []il2cppType   `json:"types,omitempty"`
		MethodsCount int            `json:"methods_count"`
		Methods      []il2cppMethod `json:"methods,omitempty"`
		Truncated    bool           `json:"truncated,omitempty"`
	}{Kind: "il2cpp-metadata", Version: h.version, TypesCount: typeCount, Types: types,
		MethodsCount: methodCount, Methods: methods,
		Truncated: typeCount > len(types) || methodCount > len(methods)}
	return res, nil
}

type il2cppType struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Methods   int    `json:"methods"`
	Token     uint32 `json:"token,omitempty"`
}

type il2cppMethod struct {
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Token uint32 `json:"token,omitempty"`
}

func il2cppParseHeader(b []byte) (il2cppHeader, error) {
	var h il2cppHeader
	if len(b) < 168 {
		return h, fmt.Errorf("metadata is %d bytes, shorter than the 168-byte header", len(b))
	}
	if magic := binary.LittleEndian.Uint32(b); magic != 0xFAB11BAF {
		return h, fmt.Errorf("magic %#x is not IL2CPP global-metadata (want 0xFAB11BAF)", magic)
	}
	h.version = int(int32(binary.LittleEndian.Uint32(b[4:])))
	if h.version < 16 || h.version > 31 {
		return h, fmt.Errorf("metadata version %d is not supported (16 through 31)", h.version)
	}
	h.stringOff = int(int32(binary.LittleEndian.Uint32(b[24:])))
	h.stringSize = int(int32(binary.LittleEndian.Uint32(b[28:])))
	h.methodsOff = int(int32(binary.LittleEndian.Uint32(b[48:])))
	h.methodsLen = int(int32(binary.LittleEndian.Uint32(b[52:])))
	h.typesOff = int(int32(binary.LittleEndian.Uint32(b[160:])))
	h.typesLen = int(int32(binary.LittleEndian.Uint32(b[164:])))
	for _, t := range []struct {
		name string
		off  int
		size int
	}{
		{"string", h.stringOff, h.stringSize},
		{"method", h.methodsOff, h.methodsLen},
		{"type definition", h.typesOff, h.typesLen},
	} {
		if t.off < 0 || t.size < 0 || t.off > len(b) || t.size > len(b)-t.off {
			return h, fmt.Errorf("%s table at %d (%d bytes) is past the %d-byte file", t.name, t.off, t.size, len(b))
		}
	}
	if h.version < 27 {
		// The type table grew and shrank across 16..26 (rgctx, byref,
		// custom-attribute fields), so a fixed stride would report names from
		// the wrong bytes. The version is still worth answering.
		return h, nil
	}
	return h, nil
}

// il2cppString resolves one index into the metadata string pool. Indices are
// byte offsets from stringOffset, and the strings are NUL-terminated UTF-8.
func il2cppString(b []byte, h il2cppHeader, idx int) string {
	if idx < 0 || idx >= h.stringSize {
		return ""
	}
	p := h.stringOff + idx
	end := h.stringOff + h.stringSize
	if p >= len(b) || end > len(b) {
		return ""
	}
	if end > len(b) {
		end = len(b)
	}
	e := p
	for e < end && b[e] != 0 {
		e++
	}
	s := b[p:e]
	if !utf8.Valid(s) {
		return strings.ToValidUTF8(string(s), "\uFFFD")
	}
	return string(s)
}
