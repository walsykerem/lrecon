package main

import (
	"fmt"
	"strings"
)

// 166. resolve_adb_packages — y44: `cmd package resolve-activity --components`
// with `-c android.intent.category.DEFAULT`; --components prints only the
// component line, and --brief is dropped because it adds a priority line.
func init() {
	registerOp(op{
		name:  "resolve_adb_packages",
		route: "Y",
		desc:  "adb shell cmd package resolve-activity --components -a <action> -d <uri> -c DEFAULT; target is <uri> or <action>,<uri> (final.md y44)",
		needs: true,
		run:   opResolveAdbPackages,
	})
}

type rt2ResolvedComponent struct {
	Component string `json:"component"`
	Package   string `json:"package"`
	Activity  string `json:"activity"`
}

type rt2ResolvedIntents struct {
	Action     string                 `json:"action"`
	URI        string                 `json:"uri"`
	Components []rt2ResolvedComponent `json:"components"`
	Count      int                    `json:"count"`
}

func opResolveAdbPackages(target string) (any, error) {
	action := "android.intent.action.VIEW"
	uri := strings.TrimSpace(target)
	if a, b, ok := strings.Cut(uri, ","); ok {
		action, uri = strings.TrimSpace(a), strings.TrimSpace(b)
	}
	if action == "" || uri == "" {
		return nil, fmt.Errorf("resolve_adb_packages needs an argument: a URI, or <action>,<uri> (got %q)", target)
	}
	if sk, err := rt2AdbReady("cmd package resolve-activity --components -a <action> -d <uri> -c android.intent.category.DEFAULT"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("cmd", "package", "resolve-activity", "--components",
		"-a", action, "-d", uri, "-c", "android.intent.category.DEFAULT")
	if sk != nil || err != nil {
		return sk, err
	}
	res := rt2ResolvedIntents{Action: action, URI: uri}
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		pkg, act, ok := strings.Cut(line, "/")
		if !ok || strings.ContainsAny(pkg, " =") || strings.ContainsAny(act, " =") {
			continue
		}
		res.Components = append(res.Components, rt2ResolvedComponent{Component: line, Package: pkg, Activity: act})
	}
	res.Count = len(res.Components)
	return res, nil
}
