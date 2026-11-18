package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image"
	"image/png"
)

// Item 187. Two screenshots of one page with a click in between, then a plain
// pixel diff in Go: a threshold per pixel on the summed channel delta, a count,
// and the box that changed. Without the click the two PNGs are identical.

func init() {
	registerOp(op{
		name:  "compare_web_screenshots",
		route: "Y",
		desc:  "capture the tab, click its centre, capture again, and report differing pixels, bounding box and mean delta",
		needs: true,
		run:   opCompareWebScreenshots,
	})
}

const pixelThreshold = 24 // |dr|+|dg|+|db| above this counts as changed (y62)

type screenshotDiff struct {
	Width     int      `json:"width"`
	Height    int      `json:"height"`
	Different int      `json:"different_pixels"`
	Total     int      `json:"total_pixels"`
	MeanDelta float64  `json:"mean_delta"`
	Box       *diffBox `json:"box,omitempty"`
}

type diffBox struct {
	X0 int `json:"x0"`
	Y0 int `json:"y0"`
	X1 int `json:"x1"`
	Y1 int `json:"y1"`
}

func opCompareWebScreenshots(target string) (any, error) {
	ep, _, err := webTarget(target)
	if err != nil {
		return nil, err
	}
	click := "({x: Math.floor(innerWidth / 2), y: Math.floor(innerHeight / 2)})"
	out, sk, err := webRun("compare_web_screenshots", ep, webSpec{
		Mode: "session",
		Steps: []webStep{
			{Method: "Page.enable"},
			{Method: "Runtime.evaluate", Params: map[string]any{"expression": click, "returnByValue": true}},
			{Method: "Page.captureScreenshot", Params: map[string]any{"format": "png"}},
			{Method: "Input.dispatchMouseEvent", Params: map[string]any{"type": "mousePressed", "x": "$1.result.value.x", "y": "$1.result.value.y", "button": "left", "clickCount": 1}},
			{Method: "Input.dispatchMouseEvent", Params: map[string]any{"type": "mouseReleased", "x": "$1.result.value.x", "y": "$1.result.value.y", "button": "left", "clickCount": 1}},
			{Method: "Page.captureScreenshot", Params: map[string]any{"format": "png"}},
		},
		Collect: &webCollect{Ms: 300, Prefixes: []string{"Page."}},
	})
	if sk != nil {
		return sk, nil
	}
	if err != nil {
		return nil, err
	}
	first, err := screenshotPayload(out, ep, 2)
	if err != nil {
		return nil, err
	}
	second, err := screenshotPayload(out, ep, 5)
	if err != nil {
		return nil, err
	}
	return diffScreenshots(first, second)
}

// screenshotPayload decodes step i's PNG payload, naming the step when it is not
// there rather than returning an empty image.
func screenshotPayload(out webOut, ep string, i int) (image.Image, error) {
	if i >= len(out.Steps) || !out.Steps[i].Ok {
		return nil, fmt.Errorf("cdp %s: %s", ep, stepFailure(out.Steps, i))
	}
	raw, err := base64.StdEncoding.DecodeString(str(out.Steps[i].Result["data"]))
	if err != nil {
		return nil, fmt.Errorf("cdp %s: screenshot %d is not base64: %w", ep, i, err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("cdp %s: screenshot %d is not a PNG: %w", ep, i, err)
	}
	return img, nil
}

// diffScreenshots counts pixels above the threshold and grows one box around all
// of them. Two captures of different sizes are reported as such, never compared.
func diffScreenshots(a, b image.Image) (any, error) {
	res := screenshotDiff{Width: a.Bounds().Dx(), Height: a.Bounds().Dy()}
	res.Total = res.Width * res.Height
	if a.Bounds().Dx() != b.Bounds().Dx() || a.Bounds().Dy() != b.Bounds().Dy() {
		return nil, fmt.Errorf("captures differ in size (%dx%d vs %dx%d): capture both at one viewport", a.Bounds().Dx(), a.Bounds().Dy(), b.Bounds().Dx(), b.Bounds().Dy())
	}
	var sum float64
	note := func(x, y, d int) {
		res.Different++
		sum += float64(d)
		if res.Box == nil {
			res.Box = &diffBox{X0: x, Y0: y, X1: x, Y1: y}
			return
		}
		if x < res.Box.X0 {
			res.Box.X0 = x
		}
		if y < res.Box.Y0 {
			res.Box.Y0 = y
		}
		if x > res.Box.X1 {
			res.Box.X1 = x
		}
		if y > res.Box.Y1 {
			res.Box.Y1 = y
		}
	}
	ra, aRGBA := a.(*image.RGBA)
	rb, bRGBA := b.(*image.RGBA)
	for y := 0; y < res.Height; y++ {
		if aRGBA && bRGBA {
			// Two *image.RGBA captures (what PNG decoding hands back for a
			// screenshot) store premultiplied bytes, so At().RGBA()>>8 is the
			// byte itself: read Pix and skip four interface calls per pixel.
			ia := ra.PixOffset(ra.Rect.Min.X, ra.Rect.Min.Y+y)
			ib := rb.PixOffset(rb.Rect.Min.X, rb.Rect.Min.Y+y)
			for x := 0; x < res.Width; x++ {
				i, j := ia+x*4, ib+x*4
				d := absDiff(int(ra.Pix[i]), int(rb.Pix[j])) +
					absDiff(int(ra.Pix[i+1]), int(rb.Pix[j+1])) +
					absDiff(int(ra.Pix[i+2]), int(rb.Pix[j+2]))
				if d > pixelThreshold {
					note(x, y, d)
				}
			}
			continue
		}
		for x := 0; x < res.Width; x++ {
			ar, ag, ab, _ := a.At(x, y).RGBA()
			br, bg, bb, _ := b.At(x, y).RGBA()
			d := absDiff(int(ar>>8), int(br>>8)) + absDiff(int(ag>>8), int(bg>>8)) + absDiff(int(ab>>8), int(bb>>8))
			if d > pixelThreshold {
				note(x, y, d)
			}
		}
	}
	if res.Different == 0 {
		return nil, fmt.Errorf("the two captures are pixel-identical (%dx%d): the click between them changed nothing on screen", res.Width, res.Height)
	}
	res.MeanDelta = sum / float64(res.Different)
	return res, nil
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}
