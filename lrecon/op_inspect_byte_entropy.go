package main

import (
	"fmt"
	"io"
	"math"
	"os"
)

func init() {
	registerOp(op{
		name:  "inspect_byte_entropy",
		route: "L",
		needs: true,
		desc:  "Shannon entropy per 4 KiB block: mean, spread, packed and plain-text block counts",
		run: func(path string) (any, error) {
			// One block at a time: a 256 MiB target costs 4 KiB of memory
			// here, and every block is still measured over exactly its own
			// 4096 bytes, so the numbers do not depend on how it was read.
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			st, err := f.Stat()
			if err != nil {
				return nil, err
			}
			if st.IsDir() {
				return nil, fmt.Errorf("%s is a directory", path)
			}
			if st.Size() > opMaxFile {
				return nil, fmt.Errorf("%s is %d bytes, over the %d-byte cap", path, st.Size(), opMaxFile)
			}
			if st.Size() < 4096 {
				return skipf("%s must be at least one 4096-byte block, is %d bytes", path, st.Size()), nil
			}
			const block = 4096
			// Fixed 4 KiB window on the stack: no declared length reaches an
			// allocation, so alloc_test keeps its pin.
			var buf [block]byte
			mean, lo, hi := 0.0, 8.0, 0.0
			packed, plain, blocks := 0, 0, 0
			for remaining := st.Size(); remaining > 0; {
				n := min(remaining, int64(block))
				if got, err := io.ReadFull(f, buf[:n]); err != nil {
					return nil, fmt.Errorf("%s: short read: got %d of %d bytes", path, got, n)
				}
				for _, v := range blockEntropy(buf[:n], block) {
					blocks++
					mean += v
					lo = math.Min(lo, v)
					hi = math.Max(hi, v)
					if v >= 7.5 {
						packed++
					}
					if v < 5 {
						plain++
					}
				}
				remaining -= n
			}
			if blocks == 0 {
				return nil, fmt.Errorf("%s produced no entropy blocks", path)
			}
			mean /= float64(blocks)
			return struct {
				BlockBytes int     `json:"block_bytes"`
				Blocks     int     `json:"blocks"`
				Mean       float64 `json:"mean"`
				Min        float64 `json:"min"`
				Max        float64 `json:"max"`
				Packed     int     `json:"packed_blocks"`
				Plain      int     `json:"plain_blocks"`
			}{block, blocks, round2(mean), lo, hi, packed, plain}, nil
		},
	})
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
