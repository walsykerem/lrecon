package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

//go:embed decoders.json
var embeddedDecoders []byte

func init() {
	registerOp(op{
		name:  "inspect_signal_decoders",
		route: "L",
		desc:  "search the local decoders.json table by decoder name, family, modulation, symbol rate or channel (query = LRECON_QUERY, or the target when it contains a path separator)",
		needs: false,
		run:   inspectSignalDecoders,
	})
}

type rtDecoder struct {
	Name       string  `json:"name"`
	Family     string  `json:"family,omitempty"`
	Modulation string  `json:"modulation,omitempty"`
	SymbolRate float64 `json:"symbol_rate,omitempty"`
	Channel    string  `json:"channel,omitempty"`
}

type rtDecoderHits struct {
	Query   string      `json:"query"`
	Table   string      `json:"table"`
	Matches []rtDecoder `json:"matches"`
}

// inspectSignalDecoders is §y item 147: the table ships beside lrecon (or is
// named by LRECON_DECODERS) and the match is a plain case-insensitive substring
// over the columns, plus numeric equality on symbol_rate. No network, no
// invented rows.
// decoderTable prefers an explicit table, then decoders.json in the working
// directory or beside the binary, and finally the copy compiled into lrecon so
// a fresh install can answer without shipping a data file.
func decoderTable() ([]byte, string, error) {
	if p := strings.TrimSpace(os.Getenv("LRECON_DECODERS")); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			// ENOTDIR (a path component is the binary itself, e.g. cwd-relative
			// "lrecon/decoders.json" from lrecon/) is also "table not found":
			// os.IsNotExist alone misses it and the raw PathError leaked as
			// kind=bad_arg instead of the documented no_engine guidance.
			if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
				return nil, p, fmt.Errorf("decoder table %s not found: ship decoders.json beside lrecon or set LRECON_DECODERS", p)
			}
			return nil, p, err
		}
		return b, p, nil
	}
	for _, p := range []string{"decoders.json", ""} {
		if p == "" {
			exe, err := os.Executable()
			if err != nil {
				break
			}
			p = filepath.Join(filepath.Dir(exe), "decoders.json")
		}
		if b, err := os.ReadFile(p); err == nil {
			return b, p, nil
		}
	}
	return embeddedDecoders, "embedded", nil
}

func inspectSignalDecoders(query string) (any, error) {
	// A query is a word, not a file: the CLI's live-target guard rejects a bare
	// word as a process name, so LRECON_QUERY is the channel that reaches here.
	if q := strings.TrimSpace(os.Getenv("LRECON_QUERY")); q != "" {
		query = q
	}
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("inspect_signal_decoders needs a query: set LRECON_QUERY to a decoder name, family, modulation, symbol rate or channel")
	}
	b, table, err := decoderTable()
	if err != nil {
		return nil, err
	}
	var rows []rtDecoder
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("%s is not a decoder table: %w", table, err)
	}
	q := strings.ToLower(strings.TrimSpace(query))
	rate, perr := strconv.ParseFloat(q, 64)
	rateOK := perr == nil
	res := rtDecoderHits{Query: query, Table: table, Matches: []rtDecoder{}}
	for _, d := range rows {
		if rtDecoderMatches(d, q, rate, rateOK) {
			res.Matches = append(res.Matches, d)
		}
	}
	return res, nil
}

func rtDecoderMatches(d rtDecoder, q string, rate float64, rateOK bool) bool {
	for _, field := range []string{d.Name, d.Family, d.Modulation, d.Channel} {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	return rateOK && d.SymbolRate == rate
}
