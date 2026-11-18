package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	registerOp(op{
		name:  "install_adb_package",
		route: "Y",
		desc:  "install one APK on the attached device with `adb install -r -t` (target = APK path)",
		needs: true,
		run:   installADBPackage,
	})
}

type rtADBInstall struct {
	APK    string `json:"apk"`
	Result string `json:"result"`
	Method string `json:"method"`
}

// rtInstallTimeout bounds one install: an APK is pushed and scanned, so a
// large one on a loaded device needs minutes where every other adb call here
// needs seconds. The 60s session budget killed real installs mid-serve.
const rtInstallTimeout = 5 * time.Minute

// installADBPackage is §y y26's streamed install (`exec:cmd package install -S`
// in ADB's own client); `adb install` is that same path from the shipped CLI.
// The status line decides, not the exit code: adbd returns 0 with a failure
// message on screen.
func installADBPackage(apk string) (any, error) {
	if _, err := os.Stat(apk); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), rtInstallTimeout)
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "install -r -t <apk>")
	if err != nil || sk != nil {
		return sk, err
	}
	// adb writes progress to stdout and the verdict to stdout, and a failed
	// install exits non-zero with only progress on stderr. Reading stdout first
	// keeps the Failure line that says why in the error instead of "Serving...".
	raw, errRaw, runErr := rtRunRawStreams(ctx, adb, "-s", serial, "install", "-r", "-t", apk)
	out := string(raw)
	ok, verdict := false, ""
	for _, l := range rtLines(out) {
		if strings.Contains(l, "Success") {
			ok, verdict = true, "Success"
			break
		}
		if strings.Contains(l, "Failure") {
			verdict = strings.TrimSpace(l)
			break
		}
	}
	if !ok {
		switch {
		case verdict != "":
			return nil, fmt.Errorf("install did not report Success: %s", verdict)
		case runErr != nil:
			// The reason (INSTALL_FAILED_*, a java exception) is on stderr after
			// adb's own echo line, so quote it instead of the progress line.
			if detail := installReason(string(errRaw)); detail != "" {
				return nil, fmt.Errorf("%s -s %s install -r -t %s: %s", filepath.Base(adb), serial, apk, detail)
			}
			return nil, fmt.Errorf("%s -s %s install -r -t %s: %w", filepath.Base(adb), serial, apk, runErr)
		default:
			return nil, fmt.Errorf("install printed no Success or Failure line: %s", rtFirstLine(out))
		}
	}
	return rtADBInstall{APK: apk, Result: "Success", Method: "streamed install -r -t"}, nil
}

// installReason picks the stderr line that explains a failed install: adb's
// first line is only the echo "adb: failed to install x.apk:" and the reason
// follows it, sometimes behind the "Exception occurred while executing" banner.
func installReason(stderr string) string {
	for _, l := range rtLines(stderr) {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "adb: failed to install") && strings.HasSuffix(l, ":") {
			continue
		}
		if strings.HasPrefix(l, "Exception occurred while executing") {
			continue
		}
		return l
	}
	return ""
}
