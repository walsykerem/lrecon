package main

import "fmt"

func init() {
	registerOp(op{
		name:  "unset_bookmark",
		route: "L",
		needs: false,
		desc:  "Remove the bookmark at an address (and file, when the job names one) from <state>/bookmarks.json; removing nothing is an error, not a silent success.",
		run:   runUnsetBookmark,
	})
}

func runUnsetBookmark(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	if err := metaRequireBookmarkAddress(job); err != nil {
		return nil, fmt.Errorf("unset_bookmark: %v", err)
	}
	root, err := metaStateRoot(path, job)
	if err != nil {
		return nil, err
	}
	file, err := metaStateFile(root, "bookmarks.json")
	if err != nil {
		return nil, err
	}
	// Same lock as set_bookmark: the removal must see the list it writes back.
	unlock, err := metaLock(file)
	if err != nil {
		return nil, err
	}
	defer unlock()
	marks, exists, err := metaReadBookmarks(file)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, fmt.Errorf("unset_bookmark: no bookmarks recorded in %s", root)
	}
	keep := make([]metaBookmark, 0, len(marks))
	var removed []metaBookmark
	for _, m := range marks {
		if m.Address == job.Address && (job.File == "" || m.File == job.File) {
			removed = append(removed, m)
			continue
		}
		keep = append(keep, m)
	}
	if len(removed) == 0 {
		return nil, fmt.Errorf("unset_bookmark: no bookmark at %s in %s", job.Address, file)
	}
	if err := metaWriteJSON(file, keep); err != nil {
		return nil, err
	}
	return map[string]any{
		"removed":        removed,
		"count":          len(keep),
		"bookmarks_file": file,
	}, nil
}
