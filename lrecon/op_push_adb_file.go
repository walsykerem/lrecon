package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 163. push_adb_file — y41: sync SEND (adb push) plus a size check read back
// from the device, so a short write is reported instead of reported as done.
func init() {
	registerOp(op{
		name:  "push_adb_file",
		route: "Y",
		desc:  "adb push <local> <remote> then adb shell stat -c %s; target is <local>:<remote> (final.md y41)",
		needs: true,
		run:   opPushAdbFile,
	})
}

type rt2PushedFile struct {
	Local       string `json:"local"`
	Remote      string `json:"remote"`
	LocalBytes  int64  `json:"local_bytes"`
	RemoteBytes int64  `json:"remote_bytes"`
	Verified    bool   `json:"verified"`
}

func opPushAdbFile(target string) (any, error) {
	local, remote, err := rt2Pair(target, ":")
	if err != nil {
		return nil, err
	}
	st, err := os.Stat(local)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory: adb push of a directory is not one file", local)
	}
	if sk, err := rt2AdbReady("push <local> <remote>", "stat -c %s <remote>"); sk != nil || err != nil {
		return sk, err
	}
	if _, sk, err := rt2AdbTransfer("push", local, remote); sk != nil || err != nil {
		return sk, err
	}
	sizeOut, sk, err := rt2AdbShell("stat", "-c", "%s", remote)
	if sk != nil || err != nil {
		return sk, err
	}
	remoteBytes, err := strconv.ParseInt(strings.TrimSpace(sizeOut), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("stat %s on the device: %q is not a byte count", remote, strings.TrimSpace(sizeOut))
	}
	return rt2PushedFile{
		Local:       local,
		Remote:      remote,
		LocalBytes:  st.Size(),
		RemoteBytes: remoteBytes,
		Verified:    st.Size() == remoteBytes,
	}, nil
}
