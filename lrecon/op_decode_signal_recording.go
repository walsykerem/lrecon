package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func init() {
	registerOp(op{
		name:  "decode_signal_recording",
		route: "L",
		desc:  "SigMF pair: sample rate and datatype from the .sigmf-meta, sample count/duration and peak frequency from the .sigmf-data (target = meta file)",
		needs: true,
		run:   decodeSignalRecording,
	})
}

type rtSignal struct {
	SampleRate float64 `json:"sample_rate"`
	Datatype   string  `json:"datatype"`
	Samples    int64   `json:"samples"`
	DurationS  float64 `json:"duration_s"`
	DFTBins    int     `json:"dft_bins"`
	PeakHz     float64 `json:"peak_hz,omitempty"`
	HasPeak    bool    `json:"peak_measured"`
	Note       string  `json:"note,omitempty"`
}

// rtSigMFItems maps the SigMF datatype to bytes per sample. Only the complex
// float formats can carry a peak frequency here; everything else is counted or
// refused by name instead of being reinterpreted.
var rtSigMFItems = map[string]int{
	"cf32_le": 8, "cf64_le": 16, "ci32_le": 8, "ci16_le": 4, "ci8": 2,
	"rf32_le": 4, "rf64_le": 8, "ri32_le": 4, "ri16_le": 2, "ru8": 1,
}

// decodeSignalRecording is §y item 137: the JSON header is read with
// encoding/json, the IQ samples are binary, and the peak comes from a direct
// DFT over a bounded prefix (latency, not accuracy, sets the prefix).
func decodeSignalRecording(metaPath string) (any, error) {
	b, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, err
	}
	var meta struct {
		Global map[string]json.RawMessage `json:"global"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("%s is not a SigMF meta JSON: want a sidecar with global.core:sample_rate and global.core:datatype (raw IQ, .cfile, WAV and CSV carry no metadata): %w", metaPath, err)
	}
	str := func(key string) string {
		raw, ok := meta.Global[key]
		if !ok {
			return ""
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return ""
		}
		return s
	}
	if len(meta.Global) == 0 {
		// Parsed as JSON but with nothing SigMF-shaped in it: name the format
		// instead of only complaining about the first missing key.
		return nil, fmt.Errorf("%s is not a SigMF meta JSON: no global object", metaPath)
	}
	res := rtSignal{Datatype: str("core:datatype")}
	rateRaw, ok := meta.Global["core:sample_rate"]
	if !ok {
		return nil, fmt.Errorf("%s has no global.core:sample_rate", metaPath)
	}
	if err := json.Unmarshal(rateRaw, &res.SampleRate); err != nil {
		return nil, fmt.Errorf("%s: core:sample_rate is not a number: %w", metaPath, err)
	}
	if res.SampleRate <= 0 {
		return nil, fmt.Errorf("%s: core:sample_rate is %v", metaPath, res.SampleRate)
	}
	item, ok := rtSigMFItems[res.Datatype]
	if !ok {
		return nil, fmt.Errorf("%s: unknown core:datatype %q (known: %s)", metaPath, res.Datatype, rtSigMFTypes())
	}
	dataPath := str("core:dataset")
	dir := filepath.Dir(metaPath)
	if dataPath == "" {
		dataPath = strings.TrimSuffix(metaPath, ".sigmf-meta") + ".sigmf-data"
	} else if filepath.IsAbs(dataPath) {
		// The sidecar is data: an absolute core:dataset would let it name any
		// file on the host, so the data file must stay a sibling of the meta.
		return nil, fmt.Errorf("%s: core:dataset %q must be relative to the meta file's directory", metaPath, dataPath)
	} else {
		dataPath = filepath.Clean(filepath.Join(dir, dataPath))
		rel, relErr := filepath.Rel(dir, dataPath)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("%s: core:dataset %q escapes the meta file's directory", metaPath, str("core:dataset"))
		}
	}
	data, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, err
	}
	res.Samples = int64(len(data) / item)
	res.DurationS = float64(res.Samples) / res.SampleRate
	if n := len(data) % item; n != 0 {
		res.Note = fmt.Sprintf("%d trailing bytes do not fill a %s sample", n, res.Datatype)
	}
	if peak, bins, ok := rtDFTPeak(data, res.Datatype); ok {
		res.DFTBins = bins
		// Bin k is k*sample_rate/n, but a complex IQ capture spans -fs/2..fs/2:
		// bins past n/2 are negative frequencies. Reporting bin 4011 of 4096 as
		// +47 kHz names a frequency the capture cannot hold, so wrap them back.
		res.PeakHz = float64(peak) * res.SampleRate / float64(bins)
		if peak*2 > bins {
			res.PeakHz -= res.SampleRate
		}
		res.HasPeak = true
	} else {
		res.Note = strings.TrimSpace(res.Note + " peak frequency measured only for complex float formats")
	}
	return res, nil
}

func rtSigMFTypes() string {
	names := make([]string, 0, len(rtSigMFItems))
	for k := range rtSigMFItems {
		names = append(names, k)
	}
	// Sorted, not map order: the same bad datatype must produce the same
	// sentence on every run.
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// rtDFTPeak takes the first at most 4096 complex samples and returns the bin
// with the largest magnitude. Direct evaluation with a rotating twiddle keeps
// it to complex multiplies, no per-term trig.
func rtDFTPeak(data []byte, dtype string) (int, int, bool) {
	var samples []complex128
	switch dtype {
	case "cf32_le":
		n := min(len(data)/8, 4096)
		samples = make([]complex128, n)
		for i := range n {
			re := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8:]))
			im := math.Float32frombits(binary.LittleEndian.Uint32(data[i*8+4:]))
			samples[i] = complex(float64(re), float64(im))
		}
	case "cf64_le":
		n := min(len(data)/16, 4096)
		samples = make([]complex128, n)
		for i := range n {
			re := math.Float64frombits(binary.LittleEndian.Uint64(data[i*16:]))
			im := math.Float64frombits(binary.LittleEndian.Uint64(data[i*16+8:]))
			samples[i] = complex(re, im)
		}
	default:
		return 0, 0, false
	}
	n := len(samples)
	if n < 2 {
		return 0, 0, false
	}
	bestBin, bestMag := 0, 0.0
	for k := range n {
		// scalar real/imag instead of complex128: same operations in the same
		// order (cmplx.Rect(1,θ) is exactly cos θ+i sin θ, cmplx.Abs is Hypot),
		// so the bins come out bit-identical while the inner loop does no
		// struct copies.
		theta := -2 * math.Pi * float64(k) / float64(n)
		wr, wi := math.Cos(theta), math.Sin(theta)
		var sr, si float64
		cr, ci := 1.0, 0.0
		for i := range n {
			x := samples[i]
			sr += real(x)*cr - imag(x)*ci
			si += real(x)*ci + imag(x)*cr
			cr, ci = cr*wr-ci*wi, cr*wi+ci*wr
		}
		if m := math.Hypot(sr, si); m > bestMag {
			bestBin, bestMag = k, m
		}
	}
	return bestBin, n, true
}
