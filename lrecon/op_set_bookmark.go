package main

import "fmt"

// metaBookmark is one row of `bookmarks.json`, which final.md fixes as a bare
// array of {file,address,note,created}.
type metaBookmark struct {
	File    string `json:"file"`
	Address string `json:"address"`
	Note    string `json:"note"`
	Created string `json:"created"`
}

func init() {
	registerOp(op{
		name:  "set_bookmark",
		route: "L",
		needs: true,
		desc:  "Set a bookmark (file + address + note) in <state>/bookmarks.json; an existing bookmark at the same file/address takes the new note and keeps its created time.",
		run:   runSetBookmark,
	})
}

func runSetBookmark(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if job.File == "" || job.Address == "" {
		return nil, fmt.Errorf("set_bookmark: job needs \"file\" and \"address\"")
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "bookmarks.json")
	if err != nil {
		return nil, err
	}
	// Read and write under one lock: two `set_bookmark` runs in parallel would
	// otherwise both edit the list they read and one note would be lost.
	unlock, err := metaLock(file)
	if err != nil {
		return nil, err
	}
	defer unlock()
	marks, _, err := metaReadBookmarks(file)
	if err != nil {
		return nil, err
	}
	note := job.Text
	if job.Note != "" {
		note = job.Note
	}
	bm := metaBookmark{File: job.File, Address: job.Address, Note: note, Created: metaNow()}
	updated := false
	for i := range marks {
		if marks[i].File == bm.File && marks[i].Address == bm.Address {
			bm.Created = marks[i].Created
			marks[i] = bm
			updated = true
			break
		}
	}
	if !updated {
		marks = append(marks, bm)
	}
	if err := metaWriteJSON(file, marks); err != nil {
		return nil, err
	}
	return map[string]any{
		"bookmark":       bm,
		"updated":        updated,
		"count":          len(marks),
		"bookmarks_file": file,
	}, nil
}
