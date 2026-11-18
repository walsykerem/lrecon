package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 162. pull_adb_package — y40: `pm path` gives the base APK and every split;
// each path is one sync RECV into the current directory.
func init() {
	registerOp(op{
		name:  "pull_adb_package",
		route: "Y",
		desc:  "adb shell pm path <pkg> then adb pull each split into -o DIR (final.md y40; the CLI refuses without -o)",
		needs: true,
		run:   opPullAdbPackage,
	})
}

type rt2PulledSplit struct {
	Remote string `json:"remote"`
	Local  string `json:"local"`
	Bytes  int64  `json:"bytes"`
}

type rt2PulledPackage struct {
	Package string           `json:"package"`
	Splits  []rt2PulledSplit `json:"splits"`
	Count   int              `json:"count"`
}

func opPullAdbPackage(target string) (any, error) {
	pkg := strings.TrimSpace(target)
	if pkg == "" {
		return nil, fmt.Errorf("pull_adb_package needs an argument: a package name")
	}
	if sk, err := rt2AdbReady("pm path <pkg>", "pull <remote> <dir>"); sk != nil || err != nil {
		return sk, err
	}
	out, sk, err := rt2AdbShell("pm", "path", pkg)
	if sk != nil || err != nil {
		return sk, err
	}
	var remotes []string
	for line := range strings.SplitSeq(out, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "package:"); ok && p != "" {
			remotes = append(remotes, p)
		}
	}
	if len(remotes) == 0 {
		return nil, fmt.Errorf("pm path %s printed no package: lines (first line: %q)", pkg, rt2FirstLine(out))
	}
	// The destination is named by the caller (-o DIR): pulling beside the
	// working directory would drop APKs into whatever tree lrecon was run from.
	dir, err := adbPullDest(pkg)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	res := rt2PulledPackage{Package: pkg}
	for _, remote := range remotes {
		local := filepath.Join(dir, filepath.Base(remote))
		if _, sk, err := rt2AdbTransfer("pull", remote, local); sk != nil || err != nil {
			return sk, err
		}
		st, err := os.Stat(local)
		if err != nil {
			return nil, err
		}
		abs, err := filepath.Abs(local)
		if err != nil {
			return nil, err
		}
		res.Splits = append(res.Splits, rt2PulledSplit{Remote: remote, Local: abs, Bytes: st.Size()})
	}
	res.Count = len(res.Splits)
	return res, nil
}

// adbPullDest is -o DIR, or for an in-process caller a fresh directory under
// the system temp dir. exportDirDest's own fallback is also the system temp dir
// now; the CLI already refuses the call without -o.
func adbPullDest(pkg string) (string, error) {
	if strings.TrimSpace(opOutput) != "" {
		return exportDirDest("pull_adb_package", pkg)
	}
	return tempDir("lrecon-pull_adb_package-")
}
