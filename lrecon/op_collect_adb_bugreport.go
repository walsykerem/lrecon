package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

func init() {
	registerOp(op{
		name:  "collect_adb_bugreport",
		route: "Y",
		desc:  "bugreportz on the attached device, then pull the zip and hash it (target = local .zip path)",
		needs: true,
		run:   collectADBBugreport,
	})
}

type rtADBBugreport struct {
	Remote string `json:"remote"`
	Local  string `json:"local"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
}

// collectADBBugreport is §y y16: bugreportz is mandatory because it streams to
// a file instead of ~100 MB over the shell; only API<24 needs the legacy
// redirect, which §y keeps as a separate branch we refuse to guess at.
func collectADBBugreport(local string) (any, error) {
	// The destination is checked before the device is touched: a call that
	// cannot be answered must not leave a fresh bugreport on the phone.
	if local == "" {
		// The zip is tens of MB and the caller only learns a temp path after the
		// transfer finishes; killed mid-pull, that file is a leak and the answer
		// is gone. Name the destination instead of inventing one.
		return nil, fmt.Errorf(`this op needs a local path to write the bugreport zip to ("--op collect_adb_bugreport <local.zip>"): bugreportz streams tens of MB`)
	}
	// A sweep that hands every op the same target can hand this one the device
	// serial, and adb pull would then create a file named emulator-5554 in the
	// working directory (that is where the 8.6 MB stray zip came from). A
	// destination is a .zip path, never a selector.
	if !strings.HasSuffix(strings.ToLower(local), ".zip") {
		return nil, fmt.Errorf("collect_adb_bugreport writes a zip and needs a path ending in .zip (got %q); a device serial is a selector, not a destination", local)
	}
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "bugreportz")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "bugreportz")
	if err != nil {
		if strings.Contains(out, "FAIL:") {
			// The device answers FAIL:<why> and exits non-zero; dumpstatez is
			// disabled on emulator images, so this is a device limit, not a bad
			// request.
			return skipf("bugreportz is not available on this device: %s. The full log still comes from --op read_adb_logcat (`adb logcat -d`).", rtFirstLine(out)), nil
		}
		return nil, err
	}
	var remote string
	for _, l := range rtLines(out) {
		v, ok := strings.CutPrefix(strings.TrimSpace(l), "OK:")
		if ok {
			remote = v
			break
		}
	}
	if remote == "" {
		if strings.Contains(out, "FAIL:") {
			return skipf("bugreportz is not available on this device: %s. The full log still comes from --op read_adb_logcat (`adb logcat -d`).", rtFirstLine(out)), nil
		}
		return nil, fmt.Errorf("bugreportz did not print OK:<path>: %s (API<24 has no bugreportz)", rtFirstLine(out))
	}
	// adb pull writes the file itself; the size and hash afterwards are the
	// observation that it arrived whole.
	// A bugreport zip is tens of MB: the 20s probe budget is not a transfer
	// budget, and a context derived from the op ctx was silently capped by it.
	// rt2AdbTransfer gives the pull its own deadline.
	if _, sk, err := rt2AdbTransfer("-s", serial, "pull", remote, local); sk != nil {
		return sk, nil
	} else if err != nil {
		return nil, err
	}
	// The hash is streamed: a bugreport is tens of MB and reading it whole only
	// to hash it held the entire zip in the heap (measured: 85 MiB peak RSS for
	// a 64 MiB zip, 17 MiB after).
	// ponytail: one forward pass, no re-read; add a buffered read only if the
	// filesystem turns out to be the bottleneck.
	f, err := os.Open(local)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		// The pull reported success and wrote nothing: the destination cannot be
		// read as a bugreport, so the kind has to be io, not internal.
		return nil, fmt.Errorf("adb pull %s -> %s wrote an empty file (0 bytes); the destination cannot be read as a bugreport", remote, local)
	}
	return rtADBBugreport{Remote: remote, Local: local, Bytes: n, SHA256: hex.EncodeToString(h.Sum(nil)), Format: "bugreportz"}, nil
}
