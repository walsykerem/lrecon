package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf16"
)

// maxTraceHits bounds one literal search; truncated says when the cap was hit.
const maxTraceHits = 32

// metaTraceHit is one place a feature was found, resolved to a section and
// symbol so it can be traced further.
type metaTraceHit struct {
	Offset  int64  `json:"offset"`
	Address string `json:"address,omitempty"`
	Section string `json:"section,omitempty"`
	Segment string `json:"segment,omitempty"`
	Symbol  string `json:"symbol,omitempty"`
	Delta   int64  `json:"symbol_delta,omitempty"`
	Hex     string `json:"hex"`
	Context string `json:"context,omitempty"`
}

func init() {
	registerOp(op{
		name:  "trace_feature",
		route: "L",
		needs: true,
		desc:  "Trace a feature to bytes: job \"address\" maps one virtual address to file offset/section/symbol/bytes, job \"string\" finds every literal hit and maps each back to an address.",
		run:   runTraceFeature,
	})
}

func runTraceFeature(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	res := map[string]any{"file": target}
	switch {
	case job.Address != "":
		addr, err := metaParseAddr(job.Address)
		if err != nil {
			return nil, fmt.Errorf("trace_feature: address %q is not a hex offset: %v", job.Address, err)
		}
		p, err := metaLocate(target, addr)
		if err != nil {
			return nil, err
		}
		if !p.Exact {
			return nil, fmt.Errorf("trace_feature: %#x is not inside any mapped section of %s", addr, target)
		}
		b := readFileAt(target, p.Offset, 64)
		if b == nil {
			return nil, fmt.Errorf("trace_feature: cannot read 64 bytes at file offset %d of %s", p.Offset, target)
		}
		res["mode"] = "address"
		res["feature"] = map[string]any{
			"address": fmt.Sprintf("%#x", addr),
			"offset":  p.Offset,
			"section": p.Section,
			"segment": p.Segment,
			"arch":    p.Arch,
			"symbol":  p.Symbol,
			"delta":   p.Delta,
			"bytes":   len(b),
			"hex":     metaHex(b),
		}
		return res, nil
	case job.String != "":
		b, err := opRead(target, opMaxFile)
		if err != nil {
			return nil, err
		}
		var hits []metaTraceHit
		encodings := map[string][]byte{"utf8": []byte(job.String)}
		var u16 []byte
		for _, r := range utf16.Encode([]rune(job.String)) {
			var pair [2]byte
			binary.LittleEndian.PutUint16(pair[:], r)
			u16 = append(u16, pair[:]...)
		}
		encodings["utf16le"] = u16
		seen := map[int64]bool{}
		truncated := false
		for _, enc := range []string{"utf8", "utf16le"} {
			needle := encodings[enc]
			for at := 0; at < len(b); {
				i := bytes.Index(b[at:], needle)
				if i < 0 {
					break
				}
				off := int64(at + i)
				at += i + len(needle)
				if seen[off] {
					continue
				}
				seen[off] = true
				// Stop at the cap, but say so: 32 hits read as a complete list is
				// a wrong answer about how often the literal occurs.
				if len(hits) >= maxTraceHits {
					truncated = true
					break
				}
				hit := metaTraceHit{Offset: off, Hex: metaHex(needle)}
				if p, err := metaLocateOffset(target, off); err == nil && p.Exact {
					hit.Address = fmt.Sprintf("%#x", p.Address)
					hit.Section, hit.Segment, hit.Symbol, hit.Delta = p.Section, p.Segment, p.Symbol, p.Delta
				}
				if ctx := readFileAt(target, off-16, int64(len(needle)+32)); ctx != nil {
					hit.Context = metaHex(ctx)
				}
				hits = append(hits, hit)
			}
			if truncated {
				break
			}
		}
		res["mode"] = "string"
		res["string"] = job.String
		res["hits"] = hits
		res["count"] = len(hits)
		res["truncated"] = truncated
		return res, nil
	}
	return nil, fmt.Errorf("trace_feature: job needs \"address\" (hex) or \"string\"")
}
