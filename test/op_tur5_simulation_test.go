package main

// Tur 5 bağımsız simülasyon testleri. Yalnızca bu dosya yazıldı; üretim kodu
// ve başka lane'in test dosyaları değiştirilmedi.

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Sidecar güvenilmez girdi: boş global, eksik/bozuk sample_rate ve bilinmeyen
// datatype sessizce varsayılmak yerine adıyla reddedilmelidir.
func TestTur5SignalMetaRefusals(t *testing.T) {
	cases := []struct {
		name, meta, want string
	}{
		{"no-global", `{}`, "no global object"},
		{"no-rate", `{"global":{"core:datatype":"cf32_le"}}`, "has no global.core:sample_rate"},
		{"rate-string", `{"global":{"core:sample_rate":"x","core:datatype":"cf32_le"}}`, "core:sample_rate is not a number"},
		{"rate-zero", `{"global":{"core:sample_rate":0,"core:datatype":"cf32_le"}}`, "core:sample_rate is 0"},
		{"bad-datatype", `{"global":{"core:sample_rate":1000,"core:datatype":"bogus"}}`, "unknown core:datatype"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			mp := writeTemp(t, "cap.sigmf-meta", []byte(c.meta))
			_, err := decodeSignalRecording(mp)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("decodeSignalRecording(%s) = %v, want %q", c.meta, err, c.want)
			}
		})
	}
}

// Gerçek IQ baytları: örnek sayısı/süre veriden gelir; tam sample'a uymayan
// kuyruk baytları sayılır ve gizlenmez. Kompleks-olmayan formatta tepe
// frekansı ölçülmediği açıkça belirtilir — 0 Hz üretilmez.
func TestTur5SignalSamplesAndTrailingBytes(t *testing.T) {
	dir := t.TempDir()
	meta := `{"global":{"core:datatype":"cf32_le","core:sample_rate":1000}}`
	mp := filepath.Join(dir, "cap.sigmf-meta")
	if err := os.WriteFile(mp, []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	// 3 tam cf32_le örneği (24 bayt) + 3 kuyruk baytı.
	data := make([]byte, 24+3)
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(data[i*8:], math.Float32bits(float32(i+1)))
	}
	if err := os.WriteFile(filepath.Join(dir, "cap.sigmf-data"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := decodeSignalRecording(mp)
	if err != nil {
		t.Fatal(err)
	}
	got := res.(rtSignal)
	if got.Samples != 3 || math.Abs(got.DurationS-0.003) > 1e-9 {
		t.Fatalf("samples/duration = %d/%v, want 3/0.003", got.Samples, got.DurationS)
	}
	if !strings.Contains(got.Note, "3 trailing bytes") {
		t.Fatalf("trailing byte note = %q", got.Note)
	}
	if !got.HasPeak || got.DFTBins != 3 {
		t.Fatalf("cf32 peak = bins %d, has %v", got.DFTBins, got.HasPeak)
	}

	// ru8: 1 bayt/örnek, DFT yok — not bunu söylemeli.
	meta = `{"global":{"core:datatype":"ru8","core:sample_rate":2000,"core:dataset":"int.sigmf-data"}}`
	mp2 := filepath.Join(dir, "int.sigmf-meta")
	if err := os.WriteFile(mp2, []byte(meta), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "int.sigmf-data"), []byte{1, 2, 3, 4}, 0o644); err != nil {
		t.Fatal(err)
	}
	res, err = decodeSignalRecording(mp2)
	if err != nil {
		t.Fatal(err)
	}
	intSig := res.(rtSignal)
	if intSig.Samples != 4 || intSig.HasPeak || !strings.Contains(intSig.Note, "complex float") {
		t.Fatalf("ru8 result = %+v", intSig)
	}
}

// ops.json sözleşmesi: decode_signal_recording route L, needs=true,
// with_target=bad_arg. Hedef yoksa runOp reddetmeli; bozuk hedef de op
// içinde hata olmalı — ikisi de sessizce başarı dönmemeli.
func TestTur5SignalOpContractFromOpsJSON(t *testing.T) {
	if _, err := runOp("decode_signal_recording", ""); err == nil ||
		!strings.Contains(err.Error(), "needs a target path") {
		t.Fatalf("no target: got %v, want needs-a-target refusal", err)
	}
	bad := writeTemp(t, "bad.sigmf-meta", []byte(`{"global":{"core:sample_rate":1000,"core:datatype":"cf32_le"}}`))
	if _, err := runOp("decode_signal_recording", bad); err == nil {
		t.Fatal("bad target: expected a read/parse error, got success")
	}
}

// y67 removed the page|background_page|service_worker whitelist. A type that
// old filter hid (worker, shared_worker, browser_ui) must still be counted.
func TestTur5BrowserTargetsUnfilteredTypes(t *testing.T) {
	fakeDriver(t, webOut{
		Targets: []webTargetRow{
			{ID: "1", Type: "page"},
			{ID: "2", Type: "background_page"},
			{ID: "3", Type: "service_worker"},
			{ID: "4", Type: "worker"},
			{ID: "5", Type: "shared_worker"},
			{ID: "6", Type: "browser_ui"},
		},
		Version: map[string]any{"webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/browser/T5"},
	})
	f := fields(t, run(t, "list_browser_targets", "127.0.0.1:9222"))
	if f["count"] != float64(6) {
		t.Fatalf("count = %v, want 6 (y67 unfiltered)", f["count"])
	}
	by := f["by_type"].(map[string]any)
	for typ, want := range map[string]float64{
		"page": 1, "background_page": 1, "service_worker": 1,
		"worker": 1, "shared_worker": 1, "browser_ui": 1,
	} {
		if by[typ] != want {
			t.Errorf("by_type[%q] = %v, want %v", typ, by[typ], want)
		}
	}
	if f["browser_ws"] != "ws://127.0.0.1:9222/devtools/browser/T5" {
		t.Fatalf("browser_ws = %v", f["browser_ws"])
	}
	rows, _ := f["targets"].([]any)
	if len(rows) != 6 {
		t.Fatalf("targets = %d rows, want 6", len(rows))
	}
}

// peFile.at/fileOffset/sectionName are the shared mapping used by the
// certificates, load-config and resource ops; only openPEBytes was tested.
func TestTur5PERvaMapping(t *testing.T) {
	data := []byte("TUR5-SECTION-PAYLOAD")
	p, err := openPEBytes(sfPE(t, []sfSection{{name: ".text", rva: 0x1000, data: data}}, nil))
	if err != nil {
		t.Fatal(err)
	}
	s := p.sects[0]
	if got := p.span(s); got != uint64(s.rawSize) || got < uint64(len(data)) {
		t.Fatalf("span = %d, rawSize = %d", got, s.rawSize)
	}
	if got := p.sectionName(0x1000); got != ".text" {
		t.Fatalf("sectionName(.text rva) = %q", got)
	}
	if got := p.sectionName(0x9000); got != "" {
		t.Fatalf("sectionName(outside) = %q", got)
	}
	b, err := p.at(0x1000, uint32(len(data)))
	if err != nil || !bytes.Equal(b, data) {
		t.Fatalf("at(section) = %q, %v", b, err)
	}
	off, err := p.fileOffset(0x1000, 4)
	if err != nil || off != uint64(s.off) {
		t.Fatalf("fileOffset(section) = %#x, %v; want %#x", off, err, s.off)
	}
	if _, err := p.at(0x1000+s.rawSize, 4); err == nil {
		t.Fatal("at accepted an RVA past the section span")
	}
	if _, err := p.fileOffset(0x9000, 4); err == nil {
		t.Fatal("fileOffset accepted an RVA in no section")
	}
	w, ok := p.word(p.b[s.off:], 0)
	if !ok || w != binary.LittleEndian.Uint64(data[:8]) {
		t.Fatalf("word(PE32+) = %#x, %v", w, ok)
	}
	if _, ok := p.word(p.b[s.off:s.off+3], 8); ok {
		t.Fatal("word accepted a short slice")
	}
}

// Dedup and the all-zero drop are untested by the existing selector cases.
func TestTur5EvmSelectorsDedupAndZero(t *testing.T) {
	code := []byte{
		0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14, // selector A + EQ
		0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14, // duplicate A
		0x63, 0x00, 0x00, 0x00, 0x00, 0x14, // all-zero, dropped
		0x63, 0x11, 0x22, 0x33, 0x44, 0x00, // no EQ, not a selector
	}
	got := evmSelectors(code)
	if len(got) != 1 || got[0] != "0xaabbccdd" {
		t.Fatalf("evmSelectors = %v", got)
	}
}

// Raw bytecode, uppercase 0X hex and odd-nibble input take three distinct
// paths; the existing case covers only lowercase 0x hex.
func TestTur5EvmBytecodeRawAndUpperHex(t *testing.T) {
	raw := []byte{0x63, 0xaa, 0xbb, 0xcc, 0xdd, 0x14}
	if b, err := evmBytecode(raw); err != nil || !bytes.Equal(b, raw) {
		t.Fatalf("raw = %x, %v", b, err)
	}
	if b, err := evmBytecode([]byte("0X63AABBCCDD14")); err != nil || !bytes.Equal(b, raw) {
		t.Fatalf("uppercase hex = %x, %v", b, err)
	}
	odd := []byte("0x63aabbccdd1")
	if b, err := evmBytecode(odd); err != nil || !bytes.Equal(b, odd) {
		t.Fatalf("odd nibble = %x, %v; want raw", b, err)
	}
}
