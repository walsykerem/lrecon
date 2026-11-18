package main

import (
	"fmt"
	"strings"
)

func init() {
	registerOp(op{
		name:  "list_adb_features",
		route: "Y",
		desc:  "server feature list from `adb host-features` (host:features, not the device's pm feature list)",
		run:   listADBFeatures,
	})
}

type rtADBFeatures struct {
	Features []string `json:"features"`
	Count    int      `json:"count"`
}

// listADBFeatures is §y y30: `host:features` says what the adb server speaks.
// `pm list features` is a different question (what the device supports) and is
// not mixed in here.
func listADBFeatures(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	out, err := rtRun(ctx, adb, "host-features")
	if err != nil {
		return nil, err
	}
	body := strings.TrimSpace(out)
	if body == "" {
		return nil, fmt.Errorf("adb host-features printed nothing")
	}
	feats := make([]string, 0, 8)
	for f := range strings.SplitSeq(strings.ReplaceAll(body, "\r", ""), ",") {
		if f = strings.TrimSpace(f); f != "" {
			feats = append(feats, f)
		}
	}
	return rtADBFeatures{Features: feats, Count: len(feats)}, nil
}
