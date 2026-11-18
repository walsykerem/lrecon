package main

import (
	"fmt"
	"io"
	"os"
)

// readCapped reads a file that has to fit limit. A file over the cap is an
// error, never a silent prefix: half a JSON job or half a wasm header is a
// wrong answer, and the caller can say the file is too big instead.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than the %d-byte cap", path, limit)
	}
	return b, nil
}
