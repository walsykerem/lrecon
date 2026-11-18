package main

import (
	"fmt"
	"os"
)

// metaClaimCheck is one claim re-read from the file: the bytes the claim says
// are at an offset versus the bytes that are actually there.
type metaClaimCheck struct {
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	Want   string `json:"want"`
	Got    string `json:"got,omitempty"`
	Match  bool   `json:"match"`
	Error  string `json:"error,omitempty"`
}

func init() {
	registerOp(op{
		name:  "verify_reconstruction",
		route: "L",
		needs: true,
		desc:  "Verify a reconstruction against the artifact: every claim {offset,length,expect-hex} is re-read from the file and compared byte for byte.",
		run:   runVerifyReconstruction,
	})
}

func runVerifyReconstruction(path string) (any, error) {
	job, err := opLoadJob(path)
	if err != nil {
		return nil, err
	}
	target := job.File
	if target == "" {
		target = path
	}
	if len(job.Claims) == 0 {
		return nil, fmt.Errorf("verify_reconstruction: job needs \"claims\" ([{offset,length,expect}])")
	}
	f, err := os.Open(target)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("%s is a directory: claims are file offsets", target)
	}
	size := fi.Size()
	checks := make([]metaClaimCheck, 0, len(job.Claims))
	matched := 0
	for _, c := range job.Claims {
		chk := metaClaimCheck{Offset: c.Offset, Length: c.Length, Want: c.Expect}
		want, err := metaHexBytes(c.Expect)
		if err != nil {
			chk.Error = err.Error()
		} else if c.Length > 0 && c.Length != len(want) {
			// A claim that states a length and an expect-hex of a different
			// length is not the claim it looks like: say so instead of
			// silently comparing whichever one is shorter.
			chk.Error = fmt.Sprintf("claim length %d does not match %d expect bytes", c.Length, len(want))
		} else if c.Offset < 0 || c.Offset+int64(len(want)) > size {
			chk.Error = fmt.Sprintf("claim [%d,%d) is outside the %d-byte file", c.Offset, c.Offset+int64(len(want)), size)
		} else {
			// Claims are windows, not the whole file: a claim is re-read at
			// its offset, so a huge artifact is never loaded to check a few
			// bytes of it.
			got := make([]byte, len(want))
			if _, err := f.ReadAt(got, c.Offset); err != nil {
				chk.Error = fmt.Sprintf("claim [%d,%d) not readable: %v", c.Offset, c.Offset+int64(len(want)), err)
			} else {
				chk.Got, chk.Match = metaHex(got), metaHex(got) == metaHex(want)
			}
		}
		if chk.Match {
			matched++
		}
		checks = append(checks, chk)
	}
	return map[string]any{
		"file":       target,
		"claims":     checks,
		"total":      len(checks),
		"matched":    matched,
		"mismatched": len(checks) - matched,
		"verified":   matched == len(checks),
	}, nil
}
