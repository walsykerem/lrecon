package main

import "fmt"

func init() {
	registerOp(op{
		name:  "inspect_jeb_client",
		route: "L",
		needs: true,
		desc:  "JEB client check: the desktop client is a commercial GUI with no static interface, so only the DEX unit count is reported",
		run: func(path string) (any, error) {
			// An APK ships classes.dex, classes2.dex, ... and each carries its
			// own class_defs_size; counting only the first reported 3967 of an
			// image that held far more, so every dex entry is counted and the
			// file count is in the answer.
			imgs, err := jebdImages(path)
			if err != nil {
				return nil, err
			}
			classes, dexFiles := 0, 0
			for _, img := range imgs {
				if len(img.Bytes) < dexHeaderSize || !isDex(img.Bytes) {
					continue
				}
				dexFiles++
				classes += int(u32le(img.Bytes, 0x60))
			}
			if dexFiles == 0 {
				return nil, fmt.Errorf("%s is not a DEX image", path)
			}
			if classes == 0 {
				return skipf("%s has no DEX classes, nothing for the JEB client path", path), nil
			}
			// No static marker in a DEX/APK ties the image to the JEB client, so
			// the answer counts the DEX classes and names no client: a constant
			// "jeb" label would be a guess dressed as evidence.
			return struct {
				Classes  int    `json:"classes"`
				DexFiles int    `json:"dex_files"`
				Reason   string `json:"reason"`
			}{Classes: classes, DexFiles: dexFiles,
				Reason: fmt.Sprintf("no static marker identifies a JEB-produced image; %d DEX classes across %d dex files reported", classes, dexFiles)}, nil
		},
	})
}
