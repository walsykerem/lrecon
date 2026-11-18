package main

import (
	"os"
	"os/exec"
	"path/filepath"
)

// The runtime helpers spawn adb by name (rtAdb, rt2Exec both call
// exec.LookPath), and platform-tools is not on PATH on a machine where Android
// Studio installed it. Prepending the SDK's own directory once is the single
// seam that reaches every adb op without teaching each call site a path.
func init() { installADBOnPath() }

func installADBOnPath() {
	if _, err := exec.LookPath("adb"); err == nil {
		return
	}
	if bin, ok := findADBInSDK(); ok {
		os.Setenv("PATH", filepath.Dir(bin)+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
}

// findADBInSDK looks where the Android tools themselves look: the two SDK
// environment variables first, then the default install of each platform.
//
// shortcut: the two documented SDK root variables plus the macOS/Linux default
// installs; Windows %LOCALAPPDATA% is not searched. Upgrade: add the Windows
// root if lrecon ever ships there.
func findADBInSDK() (string, bool) {
	var roots []string
	for _, k := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if v := os.Getenv(k); v != "" {
			roots = append(roots, v)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots, filepath.Join(home, "Library", "Android", "sdk"), filepath.Join(home, "Android", "Sdk"))
	}
	for _, root := range roots {
		bin := filepath.Join(root, "platform-tools", "adb")
		if st, err := os.Stat(bin); err == nil && !st.IsDir() {
			return bin, true
		}
	}
	return "", false
}
