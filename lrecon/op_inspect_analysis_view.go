package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "inspect_analysis_view",
		route: "L",
		needs: true,
		desc:  "Return one analysis view of the target: digest (text), json, symbols, skipped, notes or raw (first 128 bytes); job \"view\" picks it, default digest.",
		run:   runInspectAnalysisView,
	})
}

func runInspectAnalysisView(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	view := job.View
	if view == "" {
		view = "digest"
	}
	d, err := loadDigest(target)
	if err != nil {
		return nil, err
	}
	res := map[string]any{"file": target, "view": view, "kind": d.Kind, "contract_version": d.ContractVersion}
	switch view {
	case "digest":
		res["text"] = d.Text()
	case "json":
		b, err := json.MarshalIndent(d, "", "  ")
		if err != nil {
			return nil, err
		}
		res["json"] = string(b)
	case "symbols":
		res["symbols"] = d.Symbols
		res["names"] = d.Names
		res["exports"] = d.Exports
	case "skipped":
		rows := make([]string, 0, len(d.Skipped))
		for _, s := range d.Skipped {
			rows = append(rows, strings.TrimSpace(s.Reason+" "+s.Detail))
		}
		res["skipped"] = rows
		res["coverage"] = d.coverageClaim()
	case "notes":
		res["notes"] = d.Notes
	case "raw":
		// Only the first 128 bytes are shown, so read no more than that: a
		// multi-gigabyte target must not be slurped to render its header.
		f, err := os.Open(target)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		var buf [128]byte
		n, err := io.ReadFull(f, buf[:])
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		b := buf[:n]
		var lines []string
		for i := 0; i < len(b); i += 16 {
			end := min(i+16, len(b))
			lines = append(lines, fmt.Sprintf("%08x  % x", i, b[i:end]))
		}
		res["hex"] = lines
		res["bytes_shown"] = len(b)
	default:
		return nil, fmt.Errorf("inspect_analysis_view: unknown view %q (digest, json, symbols, skipped, notes, raw)", view)
	}
	return res, nil
}
