package main

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	registerOp(op{
		name:  "list_adb_directory",
		route: "Y",
		desc:  "file table of one device directory from `adb shell ls -la <dir>` (target = device directory)",
		needs: true,
		run:   listADBDirectory,
	})
}

type rtDirEntry struct {
	Perm  string `json:"perm"`
	Links string `json:"links,omitempty"`
	Owner string `json:"owner"`
	Group string `json:"group"`
	Size  string `json:"size"`
	Date  string `json:"date"`
	Time  string `json:"time"`
	Name  string `json:"name"`
	IsDir bool   `json:"dir"`
}

type rtDirListing struct {
	Path    string       `json:"path"`
	Entries []rtDirEntry `json:"entries"`
}

// listADBDirectory is §y y29 (sync LIST alternative, `ls -la` here): toybox
// prints `<perm> <links> <owner> <group> <size> <date> <time> <name>`, and a
// name may contain spaces, so only the first seven fields are positional.
func listADBDirectory(dir string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "ls -la <dir>")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "ls", "-la", adbShellQuote(dir))
	if err != nil {
		return nil, err
	}
	res := rtDirListing{Path: dir}
	for _, l := range rtLines(out) {
		if strings.HasPrefix(l, "total ") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 8 || len(f[0]) < 10 {
			continue
		}
		if _, err := strconv.Atoi(f[4]); err != nil {
			continue // not a long-format row (error text, blank, ...)
		}
		res.Entries = append(res.Entries, rtDirEntry{
			Perm:  f[0],
			Links: f[1],
			Owner: f[2],
			Group: f[3],
			Size:  f[4],
			Date:  f[5],
			Time:  f[6],
			Name:  strings.Join(f[7:], " "),
			IsDir: f[0][0] == 'd',
		})
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ls -la %s produced no long-format rows: %s", dir, rtFirstLine(out))
	}
	return res, nil
}

// adbShellQuote wraps one shell word in single quotes. adb joins its argv with
// spaces and the device shell re-splits that string, so an unquoted path that
// holds a space (or a metacharacter) reaches ls as several arguments.
func adbShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
