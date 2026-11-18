package main

import (
	"encoding/binary"
	"fmt"
)

func init() {
	registerOp(op{
		name:  "inspect_dart_aot",
		route: "L",
		needs: true,
		desc:  "Dart snapshot header: kind, declared vs actual length, build version hash (cluster table is not byte-documented)",
		run: func(path string) (any, error) {
			b, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			if len(b) < dartHeaderSize {
				return nil, fmt.Errorf("%s must be at least %d bytes for the Dart header, is %d", path, dartHeaderSize, len(b))
			}
			if binary.LittleEndian.Uint32(b) != dartMagic {
				return nil, fmt.Errorf("%s does not carry the Dart snapshot magic", path)
			}
			declared := int(binary.LittleEndian.Uint64(b[4:]) + 4)
			kind := binary.LittleEndian.Uint64(b[12:])
			kindName, ok := dartKinds[kind]
			if !ok {
				return nil, fmt.Errorf("%s has unknown Dart snapshot kind %d", path, kind)
			}
			hash := dartVersionHash(b[dartHeaderSize:])
			res := struct {
				Kind        string `json:"kind"`
				Declared    int    `json:"declared_bytes"`
				Actual      int    `json:"actual_bytes"`
				Consistent  bool   `json:"length_consistent"`
				VersionHash string `json:"version_hash,omitempty"`
				AppJIT      bool   `json:"app_jit,omitempty"`
			}{Kind: kindName, Declared: declared, Actual: len(b),
				Consistent: declared == len(b), VersionHash: hash, AppJIT: kind == 1}
			if !res.Consistent {
				return nil, fmt.Errorf("%s is not the size its header declares: header says %d bytes, file holds %d", path, declared, len(b))
			}
			if hash == "" {
				return skipf("%s carries no readable Dart version hash", path), nil
			}
			return res, nil
		},
	})
}
