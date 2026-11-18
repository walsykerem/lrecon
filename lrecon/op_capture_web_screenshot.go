package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"image/png"
	"os"
)

// Item 184. y60: one Page.captureScreenshot with captureBeyondViewport, so a
// full page needs no stitching. The PNG is decoded here to report its real size
// and hash, not the base64 length.

func init() {
	registerOp(op{
		name:  "capture_web_screenshot",
		route: "Y",
		desc:  "capture a full-page PNG of the attached tab over CDP and report its path, size, dimensions and hash",
		needs: true,
		run:   opCaptureWebScreenshot,
	})
}

type screenshotResult struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	Width  int    `json:"width"`
	Height int    `json:"height"`
	SHA256 string `json:"sha256"`
	Target string `json:"target,omitempty"`
}

func opCaptureWebScreenshot(target string) (any, error) {
	ep, arg, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	dst := "web-screenshot.png"
	if arg != "" {
		dst = arg
	}
	// The destination is free-form (host:port=<path>), so nothing stops a
	// caller from pointing it at an existing artifact — the same mistake that
	// cost a Mach-O fixture on capture_adb_screen. Refuse before the CDP round
	// trip, so a doomed run does not even open a session.
	if err := pngOnlyOverwrite(dst); err != nil {
		return nil, fmt.Errorf("capture_web_screenshot: %w; pass a different path after = (refusing to overwrite it)", err)
	}
	out, sk, err := webRun("capture_web_screenshot", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Page.enable"},
			{Method: "Page.captureScreenshot", Params: map[string]any{"format": "png", "captureBeyondViewport": true}},
		},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	if len(out.Steps) < 2 || !out.Steps[1].Ok {
		return nil, fmt.Errorf("cdp %s: Page.captureScreenshot failed: %v", ep, stepFailure(out.Steps, 1))
	}
	data, err := base64.StdEncoding.DecodeString(str(out.Steps[1].Result["data"]))
	if err != nil {
		return nil, fmt.Errorf("cdp %s: screenshot payload is not base64: %w", ep, err)
	}
	cfg, err := png.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("cdp %s: screenshot is not a PNG: %w", ep, err)
	}
	// 0600: a screenshot of a web page is not a build artifact.
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	res := screenshotResult{
		Path:   dst,
		Bytes:  len(data),
		Width:  cfg.Width,
		Height: cfg.Height,
		SHA256: hex.EncodeToString(sum[:]),
	}
	if out.Target != nil {
		res.Target = out.Target.ID
	}
	return res, nil
}

// stepFailure names which step broke and why, so the error is not "failed".
func stepFailure(steps []webStepResult, i int) string {
	if i >= len(steps) {
		return "step never ran"
	}
	if steps[i].Error != nil {
		return fmt.Sprintf("%s: %s", steps[i].Method, steps[i].Error.Message)
	}
	if !steps[i].Ok {
		return steps[i].Method + ": rejected"
	}
	return steps[i].Method + ": no data"
}
