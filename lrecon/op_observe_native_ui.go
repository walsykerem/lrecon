package main

import (
	"fmt"
	"strings"
	"time"
)

// 160. observe_native_ui — y38: dump to a fresh name each turn (a stale file
// is impossible), trust the tool's own "dumped to:" line instead of pulling
// blindly, then read and remove it. --compressed stays off: it drops the
// accessibility-unimportant views the bounds map needs.
func init() {
	registerOp(op{
		name:  "observe_native_ui",
		route: "Y",
		desc:  "adb shell uiautomator dump --windows <fresh path>: the device UI hierarchy as XML (final.md y38)",
		run:   opObserveNativeUI,
	})
}

type rt2NativeUI struct {
	Dumped  bool   `json:"dumped"`
	Path    string `json:"path"`
	Nodes   int    `json:"nodes"`
	Bytes   int    `json:"bytes"`
	XML     string `json:"xml"`
	Cleanup string `json:"cleanup,omitempty"`
}

func opObserveNativeUI(string) (any, error) {
	if sk, err := rt2AdbReady("uiautomator", "dump", "--windows"); sk != nil || err != nil {
		return sk, err
	}
	path := fmt.Sprintf("/data/local/tmp/ui-%d.xml", time.Now().UnixNano())
	// A dump is a device-side render, not a probe: measured 37.36s on a working
	// emulator, so the 20s probe budget reported "timeout" for a UI that was
	// there. It gets the same budget as a transfer.
	out, sk, err := rt2RunTimeout("adb", rt2AdbAlt, rt2TransferTimeout, "shell", "uiautomator", "dump", "--windows", path)
	if sk != nil || err != nil {
		return sk, err
	}
	// Idle timeout: the process exits 0 and writes no file, so the missing
	// "dumped to:" line is the only signal.
	if !strings.Contains(out, "dumped to:") {
		return rt2NativeUI{Dumped: false, Path: path, Cleanup: "nothing written, nothing to remove"}, nil
	}
	xmlOut, sk, err := rt2AdbShell("cat", path)
	if sk != nil || err != nil {
		// The dump wrote the file whatever the read did: remove it on the way
		// out, or the hierarchy stays in /data/local/tmp with no one to name it.
		// A failed rm is appended to the read error so the orphan is not silent.
		if _, csk, cerr := rt2AdbShell("rm", "-f", path); csk != nil {
			err = fmt.Errorf("%w (cleanup: %s)", err, csk.Reason)
		} else if cerr != nil {
			err = fmt.Errorf("%w (cleanup: %v)", err, cerr)
		}
		return sk, err
	}
	res := rt2NativeUI{
		Dumped: true,
		Path:   path,
		Nodes:  strings.Count(xmlOut, "<node"),
		Bytes:  len(xmlOut),
		XML:    xmlOut,
	}
	if _, sk, err := rt2AdbShell("rm", "-f", path); sk != nil || err != nil {
		if sk != nil {
			res.Cleanup = sk.Reason
		} else {
			res.Cleanup = err.Error()
		}
	}
	return res, nil
}
