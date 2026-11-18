package main

import (
	"fmt"
)

func init() {
	registerOp(op{
		name:  "inspect_evm_interface",
		route: "L",
		needs: true,
		desc:  "EVM dispatcher scan: every PUSH4 selector compared with EQ (0x14) in the bytecode, plus the 4-byte fallback check",
		run: func(path string) (any, error) {
			raw, err := opRead(path, opMaxFile)
			if err != nil {
				return nil, err
			}
			// A dispatcher scan reads the bytes as EVM opcodes. Inside a verified
			// container (Mach-O, ELF, PE, zip) PUSH4/EQ-shaped bytes are payload,
			// and naming them selectors invents a contract the target lacks.
			if d, err := Probe(path); err != nil {
				return nil, err
			} else if d.Kind != "unknown" && d.Kind != "text" {
				detected := d.Kind
				if d.Format != "" {
					detected = d.Kind + "/" + d.Format
				}
				return skipf("%s: %s is not EVM bytecode; a dispatcher scan over a verified format would fabricate selectors", path, detected), nil
			}
			code, err := evmBytecode(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			if len(code) < 6 {
				return nil, fmt.Errorf("%s is not long enough for a dispatcher: %d bytes", path, len(code))
			}
			// The compiler signature `PUSH4 sel EQ JUMPI` (0x63 .. 0x14 0x57) is
			// what solc, vyper and most proxies emit; scanning for it beats
			// guessing from a jump table we cannot symbolically execute. Only
			// opcode positions count: a PUSH immediate can hold the same bytes.
			sels := evmSelectors(code)
			if len(sels) == 0 {
				return skipf("%s: no PUSH4/EQ dispatcher (fallback-only or unverified contract)", path), nil
			}
			return struct {
				CodeBytes int      `json:"code_bytes"`
				Selectors int      `json:"selectors"`
				Values    []string `json:"values"`
			}{len(code), len(sels), sels}, nil
		},
	})
}

// evmSelectors walks the opcode stream and reports every PUSH4 immediate that
// is compared with EQ. Skipping PUSH immediates keeps dispatcher-shaped bytes
// inside constant data from being read as selectors.
func evmSelectors(code []byte) []string {
	seen := map[[4]byte]bool{}
	var sels []string
	for i := 0; i < len(code); i++ {
		op := code[i]
		if op == 0x63 { // PUSH4
			if i+5 < len(code) && code[i+5] == 0x14 { // EQ
				var s [4]byte
				copy(s[:], code[i+1:i+5])
				if s != [4]byte{0, 0, 0, 0} && !seen[s] {
					seen[s] = true
					sels = append(sels, fmt.Sprintf("0x%x", s))
				}
			}
			i += 4
			continue
		}
		if op >= 0x60 && op <= 0x7f { // PUSH1..PUSH32
			i += int(op - 0x5f)
		}
	}
	return sels
}

// evmBytecode accepts raw EVM bytecode or its usual hex serialisation.
// Whitespace inside the hex is ignored. The decoded buffer is at most half the
// input length, and the input itself comes from a bounded file read.
func evmBytecode(raw []byte) ([]byte, error) {
	start := 0
	for start < len(raw) && evmSpace(raw[start]) {
		start++
	}
	if start+1 < len(raw) && raw[start] == '0' && (raw[start+1] == 'x' || raw[start+1] == 'X') {
		start += 2
	}
	nibbles := 0
	for i := start; i < len(raw); i++ {
		if evmSpace(raw[i]) {
			continue
		}
		if hexVal(raw[i]) < 0 {
			return raw, nil // not a hex serialisation: the bytes stay as they are
		}
		nibbles++
	}
	if nibbles == 0 || nibbles%2 != 0 {
		return raw, nil
	}
	// The decoded form is at most half the (already file-bounded) input.
	out := make([]byte, len(raw)/2)
	n := 0
	hi := 0
	half := false
	for i := start; i < len(raw); i++ {
		if evmSpace(raw[i]) {
			continue
		}
		if !half {
			hi = hexVal(raw[i])
			half = true
			continue
		}
		out[n] = byte(hi<<4 | hexVal(raw[i]))
		n++
		half = false
	}
	return out[:n], nil
}

func evmSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
