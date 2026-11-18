package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func init() {
	registerOp(op{
		name:  "close_binary",
		route: "L",
		needs: false,
		desc:  "Close the recorded analysis session: report {closed:true,target:...}, then remove <state>/session.json when this path owns it; a session.json without the lrecon.session/1 kind is closed without being deleted or rewritten.",
		run:   runCloseBinary,
	})
}

func runCloseBinary(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "session.json")
	if err != nil {
		return nil, err
	}
	var s metaSession
	exists, err := metaReadState(file, "lrecon.session/1", &s)
	if err != nil {
		// A session.json with no "kind" is an older lrecon session (the native
		// session path writes that shape). binary_session already leaves such a
		// file alone; close_binary must agree: report the session as closed but
		// touch neither its bytes nor its existence, because this path does not
		// own the document. Any other artifact stays a conflict.
		if doc, ok := sessionLegacyDocument(file); ok {
			return map[string]any{
				"closed":          true,
				"target":          doc,
				"project":         filepath.Base(filepath.Dir(doc)),
				"document":        doc,
				"session_file":    file,
				"removed":         "",
				"session_removed": false,
				"note":            "session.json carries no lrecon.session/1 kind (older writer); closed without deleting or rewriting that file",
			}, nil
		}
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("close_binary: no session to close in %s", root)
	}
	if err := os.Remove(file); err != nil {
		return nil, err
	}
	return map[string]any{
		"closed":          true,
		"target":          s.Document,
		"project":         s.Project,
		"document":        s.Document,
		"opened":          s.Opened,
		"session_file":    file,
		"removed":         file,
		"session_removed": true,
	}, nil
}
