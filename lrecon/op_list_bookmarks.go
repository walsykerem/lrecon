package main

import "fmt"

func init() {
	registerOp(op{
		name:  "list_bookmarks",
		route: "L",
		needs: false,
		desc:  "List bookmarks from <state>/bookmarks.json, optionally filtered to one file with a job {\"file\":...}.",
		run:   runListBookmarks,
	})
}

func runListBookmarks(path string) (any, error) {
	job, err := metaLoadJob(path)
	if err != nil {
		return nil, err
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "bookmarks.json")
	if err != nil {
		return nil, err
	}
	marks, exists, err := metaReadBookmarks(file)
	if err != nil {
		return nil, err
	}
	out := make([]metaBookmark, 0, len(marks))
	for _, m := range marks {
		if job.File != "" && m.File != job.File {
			continue
		}
		out = append(out, m)
	}
	return map[string]any{
		"bookmarks":      out,
		"count":          len(out),
		"total":          len(marks),
		"exists":         exists,
		"bookmarks_file": file,
	}, nil
}

func metaRequireBookmarkAddress(job metaJob) error {
	if job.Address == "" {
		return fmt.Errorf("job needs \"address\"")
	}
	return nil
}
