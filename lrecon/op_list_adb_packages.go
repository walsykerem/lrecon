package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "list_adb_packages",
		route: "Y",
		desc:  "installed packages with their APK path (`cmd package list packages -f` on the attached device)",
		run:   listADBPackages,
	})
}

type rtADBPkgRow struct {
	Package string `json:"package"`
	APK     string `json:"apk,omitempty"`
}

type rtADBPackages struct {
	Packages []rtADBPkgRow `json:"packages"`
	Count    int           `json:"count"`
}

// listADBPackages is §y y31: `-f` is what makes the APK path part of the row.
func listADBPackages(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "cmd package list packages -f")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "cmd", "package", "list", "packages", "-f")
	if err != nil {
		return nil, err
	}
	res := rtADBPackages{}
	for _, l := range rtLines(out) {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "package:") {
			continue
		}
		// The APK path may itself contain '=' (modern /data/app paths embed a
		// base64-encoded id such as ~~gCz...==), so the package name follows
		// the LAST '=', not the first: splitting at the first one truncates
		// the path and invents a package name like "=/data/app/...".
		row := strings.TrimPrefix(l, "package:")
		if i := strings.LastIndexByte(row, '='); i >= 0 {
			res.Packages = append(res.Packages, rtADBPkgRow{Package: row[i+1:], APK: row[:i]})
			continue
		}
		res.Packages = append(res.Packages, rtADBPkgRow{Package: row})
	}
	if len(res.Packages) == 0 {
		return nil, fmt.Errorf("cmd package list packages -f printed no package: rows: %s", rtFirstLine(out))
	}
	res.Count = len(res.Packages)
	return res, nil
}
