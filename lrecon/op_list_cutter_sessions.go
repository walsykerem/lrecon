package main

import (
	"os"
	"path/filepath"
	"sort"
)

// final.md 66: list_cutter_sessions.
func init() {
	registerOp(op{
		name:  "list_cutter_sessions",
		route: "L", // no external tool: kernel process table + filesystem globs
		desc:  "running Cutter processes and saved rizin project files found in the standard project directories",
		needs: false,
		run: func(path string) (any, error) {
			out := map[string]any{
				"cutter_processes": []string{},
				"projects":         []string{},
			}
			// The kernel process table is read in-process (no pgrep): the
			// command name is what Cutter sets for its GUI binary.
			procs, perr := findProcesses("cutter")
			out["cutter_processes"] = procs
			out["process_source"] = "kernel process table via syscall (no pgrep); command name matched case-insensitively"
			if perr != nil {
				out["process_error"] = perr.Error()
			}
			dirs := []string{}
			if home, err := os.UserHomeDir(); err == nil {
				dirs = []string{
					filepath.Join(home, "Library", "Application Support", "Cutter"),
					filepath.Join(home, "Library", "Application Support", "rizin", "projects"),
					filepath.Join(home, ".local", "share", "rizin", "projects"),
				}
			}
			out["searched"] = dirs
			projects := []string{}
			for _, d := range dirs {
				m, err := filepath.Glob(filepath.Join(d, "*.rzdb"))
				if err != nil {
					continue
				}
				projects = append(projects, m...)
			}
			sort.Strings(projects)
			out["projects"] = projects
			out["rizin"] = "project listing is filesystem-only: lrecon never probes or runs rizin"
			return out, nil
		},
	})
}
