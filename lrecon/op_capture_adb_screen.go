package main

import (
	"fmt"
	"os"
)

func init() {
	registerOp(op{
		name:  "capture_adb_screen",
		route: "Y",
		desc:  "screencap a PNG from the attached device and read its size from the IHDR; optional target = file to write",
		run:   captureADBScreen,
	})
}

func captureADBScreen(file string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "exec-out screencap -p")
	if err != nil || sk != nil {
		return sk, err
	}
	res, raw, err := rtScreencap(ctx, adb, serial)
	if err != nil {
		return nil, err
	}
	// Writing the PNG is a separate observation from reading its size: --op
	// prints JSON, so the image itself can only leave through a named file.
	//
	// The positional target doubles as the destination, which made this op a
	// quiet destroyer: a sweep that gives every op the same fixture target had
	// its Mach-O replaced by a screenshot, and the next run reported "unknown
	// kind" instead of naming the cause. Refusing to write over a file that is
	// not already a PNG turns that into one sentence.
	if file != "" {
		if err := pngOnlyOverwrite(file); err != nil {
			return nil, fmt.Errorf("capture_adb_screen: %w; pass a new path as the target (refusing to overwrite it)", err)
		}
		// 0600: a screenshot is the device's screen, not a build artifact.
		if err := os.WriteFile(file, raw, 0o600); err != nil {
			return nil, err
		}
		res.File = file
	}
	return res, nil
}

// pngOnlyOverwrite allows creating a new file or reusing a path that already
// holds a PNG, and refuses anything else: a destination flag is not permission
// to erase a binary. It names the cause only; the caller adds its own op name
// and the way out, because the way out differs per op (a positional target
// here, host:port=<path> for capture_web_screenshot).
func pngOnlyOverwrite(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	// A fixed array, not make(): the alloc pin (alloc_test.go) counts every
	// bounds-checked allocation on input paths, and eight bytes of magic do
	// not need the heap.
	var head [8]byte
	n, _ := f.Read(head[:])
	f.Close()
	if n < 8 || string(head[:]) != "\x89PNG\r\n\x1a\n" {
		return fmt.Errorf("%s exists and is not a PNG", path)
	}
	return nil
}
