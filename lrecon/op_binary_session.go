package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// metaSession is `session.json`: the document a caller last opened, so a later
// op can resume without being told the path again. A closed session keeps the
// document name but marks finished; close_binary removes the file.
// metaSession is `session.json`: the document a caller last opened, so a later
// one-shot CLI call can answer current_address. It is the same struct the
// navigation items persist — one file, one schema, two writers — otherwise the
// two paths keep seeing each other as a foreign artifact.
type metaSession = nativeSession

func init() {
	registerOp(op{
		name:  "binary_session",
		route: "L",
		needs: true,
		desc:  "Open (or re-open) the analysis session for a binary and persist it to <state>/session.json; state is opened|reopened plus the document path about to be opened again.",
		run:   runBinarySession,
	})
}

func runBinarySession(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	// A missing target still answers: the session records the intent, but the
	// adapter field must say the open failed instead of leaving the caller to
	// assume it worked.
	adapter, adapterOK, adapterReason := "unknown", false, ""
	fi, err := os.Stat(abs)
	switch {
	case err != nil:
		adapterReason = err.Error()
	case fi.IsDir():
		return nil, fmt.Errorf("binary_session: %s is a directory, not a binary", target)
	default:
		adapter, adapterOK, adapterReason = sessionAdapter(abs)
	}
	root, err := metaStateRoot("", job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "session.json")
	if err != nil {
		return nil, err
	}
	var s metaSession
	prev, err := metaReadState(file, "lrecon.session/1", &s)
	// A second writer (the native session path) keeps the same file with no
	// "kind" field. That is not a reason to refuse: the adapter already opened
	// the target, so the answer stands and the foreign file is left alone.
	foreign := false
	if err != nil {
		doc, ok := sessionLegacyDocument(file)
		if !ok {
			return nil, err
		}
		prev, s.Document, foreign = true, doc, true
	}
	previous := s.Document
	state := "opened"
	opened := metaNow()
	if prev && !s.Closed && s.Document == abs {
		state, opened = "reopened", s.Opened
	}
	// Re-opening the same document must keep the reader's cursor, procedure and
	// earlier documents; switching documents must drop the cursor, because an
	// address from the old image means nothing in the new one.
	cursor, procedure := uint64(0), ""
	if s.Document == abs {
		cursor, procedure = s.Cursor, s.Procedure
	}
	s = selectDocument(s, abs)
	s.Kind = "lrecon.session/1"
	s.Document = abs
	s.Cursor = cursor
	s.Procedure = procedure
	s.Opened = opened
	s.Closed = false
	persisted := true
	if !foreign {
		if err := metaWriteJSON(file, s); err != nil {
			return nil, err
		}
	} else {
		persisted = false
	}
	res := map[string]any{
		"state":             state,
		"project":           s.Project,
		"document":          s.Document,
		"opened":            s.Opened,
		"session_file":      file,
		"adapter":           adapter,
		"adapter_ok":        adapterOK,
		"session_persisted": persisted,
	}
	if !persisted {
		res["session_note"] = "session.json was written by another lrecon path; open not persisted, that file untouched"
	}
	if !adapterOK {
		res["adapter_reason"] = adapterReason
	}
	if prev && previous != "" && previous != abs {
		res["previous_document"] = previous
	}
	return res, nil
}

// sessionLegacyDocument reports the document of a session file that carries no
// "kind" field, so a file from the native session path is not mistaken for a
// foreign artifact.
func sessionLegacyDocument(file string) (string, bool) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", false
	}
	var probe map[string]json.RawMessage
	if json.Unmarshal(b, &probe) != nil {
		return "", false
	}
	if _, hasKind := probe["kind"]; hasKind {
		return "", false
	}
	var doc string
	if raw, ok := probe["document"]; ok && json.Unmarshal(raw, &doc) == nil && doc != "" {
		return doc, true
	}
	return "", false
}

// sessionAdapter runs the same magic sniff every read op uses, so adapter_ok
// reports that a reader actually opened the target, not that a session file
// was written. Probe sets kind for every recognised format.
func sessionAdapter(path string) (name string, ok bool, reason string) {
	d, err := Probe(path)
	if err != nil {
		return "unknown", false, err.Error()
	}
	if d.Kind == "" || d.Kind == "unknown" {
		return "unknown", false, "no adapter matched the target's leading bytes"
	}
	return d.Kind, true, ""
}
