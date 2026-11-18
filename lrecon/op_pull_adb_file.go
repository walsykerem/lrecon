package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// 161. pull_adb_file — y39: sync RECV (adb pull) plus a size check against the
// device's own stat, so a truncated pull cannot pass as success.
func init() {
	registerOp(op{
		name:  "pull_adb_file",
		route: "Y",
		desc:  "adb pull <remote> <local> then adb shell stat -c %s; target is <remote>:<local> (final.md y39)",
		needs: true,
		run:   opPullAdbFile,
	})
}

type rt2PulledFile struct {
	Remote      string `json:"remote"`
	Local       string `json:"local"`
	RemoteBytes int64  `json:"remote_bytes"`
	LocalBytes  int64  `json:"local_bytes"`
	SHA256      string `json:"sha256"`
	Verified    bool   `json:"verified"`
}

func opPullAdbFile(target string) (any, error) {
	remote, local, err := rt2Pair(target, ":")
	if err != nil {
		return nil, err
	}
	if sk, err := rt2AdbReady("pull <remote> <local>", "stat -c %s <remote>"); sk != nil || err != nil {
		return sk, err
	}
	if _, sk, err := rt2AdbTransfer("pull", remote, local); sk != nil || err != nil {
		if err != nil && strings.Contains(err.Error(), "Permission denied") {
			// adb pull runs as the shell user: /system and other apps' data are
			// refused by selinux even when the file is world-readable to root.
			return skipf("the device refused %s: Permission denied. The shell user cannot read that path; pull an installed app's APK with --op pull_adb_package, or a file under /sdcard or /data/local/tmp.", remote), nil
		}
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
	st, err := os.Stat(local)
	if err != nil {
		return nil, err
	}
	sum, err := rt2SHA256(local)
	if err != nil {
		return nil, err
	}
	return rt2PulledFile{
		Remote:      remote,
		Local:       local,
		RemoteBytes: remoteBytes,
		LocalBytes:  st.Size(),
		SHA256:      sum,
		Verified:    remoteBytes == st.Size(),
	}, nil
}
