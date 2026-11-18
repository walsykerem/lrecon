package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A reader that stops early must be an error, not a short slice: the parsers
// read the buffer at declared offsets and would otherwise answer from zero
// padding the file never had.
func TestReadExactlyRejectsShortRead(t *testing.T) {
	if _, err := readExactly(strings.NewReader("abc"), 5); err == nil {
		t.Fatal("readExactly(5) over a 3-byte reader: want an error, got none")
	} else if !strings.Contains(err.Error(), "short read: got 3 of 5 bytes") {
		t.Fatalf("error does not name the shortfall: %v", err)
	}

	b, err := readExactly(strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatalf("readExactly(3) over a 3-byte reader: %v", err)
	}
	if string(b) != "abc" {
		t.Fatalf("readExactly(3) = %q, want %q", b, "abc")
	}

	b, err = readExactly(strings.NewReader(""), 0)
	if err != nil {
		t.Fatalf("readExactly(0): %v", err)
	}
	if len(b) != 0 {
		t.Fatalf("readExactly(0) returned %d bytes, want an empty slice", len(b))
	}
}

// opRead keeps its whole-file path: a file shorter than the stat size (a
// truncated read) is an error naming the path, and a normal file comes back
// byte for byte.
func TestOpReadReadsWholeFile(t *testing.T) {
	dir := t.TempDir()
	body := []byte("0123456789")
	path := filepath.Join(dir, "whole.bin")
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := opRead(path, 1<<20)
	if err != nil {
		t.Fatalf("opRead: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("opRead = %q, want %q", got, body)
	}

	if _, err := opRead(path, 4); err == nil {
		t.Fatal("opRead over the cap: want an error, got none")
	} else if !strings.Contains(err.Error(), "over the 4-byte cap") {
		t.Fatalf("cap error does not name the cap: %v", err)
	}

	// 64 KiB is the first size past a single Read on most readers: it is where
	// a loop-less copy would silently return short.
	big := bytes.Repeat([]byte("z"), 64<<10)
	bigPath := filepath.Join(dir, "64k.bin")
	if err := os.WriteFile(bigPath, big, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = opRead(bigPath, 64<<10)
	if err != nil {
		t.Fatalf("opRead 64 KiB: %v", err)
	}
	if len(got) != len(big) || got[len(got)-1] != 'z' {
		t.Fatalf("opRead 64 KiB returned %d bytes, want %d", len(got), len(big))
	}
	if _, err := readExactly(strings.NewReader(string(big)), 64<<10+1); err == nil {
		t.Fatal("readExactly past 64 KiB: want an error, got none")
	} else if !strings.Contains(err.Error(), "got 65536 of 65537 bytes") {
		t.Fatalf("64 KiB short read does not name the shortfall: %v", err)
	}
}

// dexEdgeFixture is the smallest dex that carries one real call edge: class
// Lcom/example/A; has one virtual method a() whose code_item invokes
// Lcom/example/B;->b(). B declares no class_data_item (class_data_off 0), the
// shape every marker interface has and the walker used to read as a ULEB chain
// at file offset 0.
func dexEdgeFixture(t *testing.T) []byte {
	t.Helper()
	strs := []string{"Lcom/example/A;", "Lcom/example/B;", "V", "a", "b", "()V"}
	uleb := func(n int) []byte {
		var out []byte
		for {
			b := byte(n & 0x7F)
			n >>= 7
			if n != 0 {
				b |= 0x80
			}
			out = append(out, b)
			if n == 0 {
				return out
			}
		}
	}
	var data []byte
	var offs []int
	for _, s := range strs {
		offs = append(offs, len(data))
		data = append(data, uleb(len(s))...)
		data = append(data, s...)
		data = append(data, 0)
	}
	strOff := 0x70
	typeOff := strOff + 4*len(strs)
	protoOff := typeOff + 12
	methodOff := protoOff + 12
	dataOff := methodOff + 16
	codeOff := dataOff + len(data)
	// registers 1, ins 1, outs 1, no tries, no debug info, 4 insns:
	// invoke-virtual B->b (0x6e), then return-void (0x0e).
	code := []byte{1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0,
		0x6e, 0x00, 1, 0, 0, 0, 0x0e, 0x00}
	classDataOff := codeOff + len(code)
	classData := append(append(append(append(append(append(uleb(0), uleb(0)...), uleb(0)...), uleb(1)...), uleb(0)...), uleb(1)...), uleb(codeOff)...)
	clsOff := classDataOff + len(classData)
	b := make([]byte, clsOff+64)
	copy(b, "dex\n035\x00")
	put := func(at int, v int) { binary.LittleEndian.PutUint32(b[at:], uint32(v)) }
	put(0x20, len(b))
	put(0x24, 0x70)
	put(0x28, 0x12345678)
	put(0x38, len(strs))
	put(0x3C, strOff)
	put(0x40, 3)
	put(0x44, typeOff)
	put(0x48, 1)
	put(0x4C, protoOff)
	put(0x58, 2)
	put(0x5C, methodOff)
	put(0x60, 2)
	put(0x64, clsOff)
	put(0x68, len(b)-dataOff)
	put(0x6C, dataOff)
	for i, off := range offs {
		put(strOff+4*i, dataOff+off)
	}
	for i, t := range []int{0, 1, 2} {
		put(typeOff+4*i, t)
	}
	put(protoOff, 2)   // shorty "V"
	put(protoOff+4, 2) // return "V"
	put(methodOff, 0)  // A->a
	put(methodOff+4, 3)
	put(methodOff+8, 1) // B->b
	put(methodOff+12, 4)
	copy(b[dataOff:], data)
	copy(b[codeOff:], code)
	copy(b[classDataOff:], classData)
	put(clsOff, 0)   // Lcom/example/A;
	put(clsOff+4, 1) // public
	put(clsOff+24, classDataOff)
	put(clsOff+32, 1) // Lcom/example/B;
	put(clsOff+36, 1)
	return b
}

// A class with no class_data_item must be skipped, not parsed from offset 0:
// reading the dex header as a ULEB chain made every dex with a marker interface
// refuse with a member count it invented.
func TestTraceAndroidReferencesReadsDexCallEdge(t *testing.T) {
	p := filepath.Join(t.TempDir(), "edge.dex")
	fx := dexEdgeFixture(t)
	if err := os.WriteFile(p, fx, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_QUERY", "com.example.A")
	t.Setenv("LRECON_STATE", t.TempDir())
	got, err := runOp("trace_android_references", p)
	if err != nil {
		t.Fatalf("trace_android_references on a two-class dex: %v", err)
	}
	enc, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		Classes   int `json:"class_defs"`
		CodeItems int `json:"code_items"`
		Edges     int `json:"edges"`
		Callees   []struct {
			From string `json:"from"`
			To   string `json:"to"`
		} `json:"callees"`
	}
	if err := json.Unmarshal(enc, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.Classes != 2 || ref.Edges != 1 || ref.CodeItems != 1 {
		t.Fatalf("result %s is not two class defs, one code item and one edge", enc)
	}
	if len(ref.Callees) != 1 || ref.Callees[0].From != "Lcom/example/A;->a" || ref.Callees[0].To != "Lcom/example/B;->b" {
		t.Fatalf("result %s does not hold the A->a to B->b edge", enc)
	}
}

// Every refusal whose cause is the caller's input must land on bad_arg. These
// messages are the whole mechanism: the kind is read off the text, so a
// reworded message that loses the trigger silently files a user mistake as an
// lrecon fault.
func TestRefusalMessagesReachBadArg(t *testing.T) {
	for _, c := range []struct{ name, msg string }{
		{"pe without a cli header", "/tmp/tiny.exe carries no CLI header, so there is no managed metadata to read"},
		{"maxBytes out of range", "update_analysis_settings: maxBytes 0 is not inside 1..1073741824"},
		{"minString out of range", "update_analysis_settings: minString 65 is not inside 1..64"},
		{"label without a name", `set_addresses_names: labels[0] is not a pair of address and name`},
		{"address that is not hex", `trace_feature: address "zzz" is not a hex offset: bad address "zzz"`},
		{"source map that is not v3", "/x/a.map is not a v3 source map (version 2); only v3 maps carry mappings"},
		{"job with the wrong field types", `/x/job.json is not a job document: json: cannot unmarshal string into Go struct field metaJob.deep of type bool`},
		{"class_data that stops early", "class_data at 0x10 is not a complete item"},
		{"class_def past the dex", "/x.dex: class_def 3 at 0x900 is not inside the 344-byte dex"},
		{"invoke to a missing method", "/x.dex: Lcom/x/A;->a invokes method_id 9, which is not in method_ids"},
		{"method_id that is not in method_ids", "/x.dex: class_def 0 method_id 4 unreadable: it is not in method_ids"},
		{"class type that is not in type_ids", "/x.dex: class_def 0 type unreadable: it is not in type_ids"},
	} {
		if got := classify(c.msg); got != kindBadArg {
			t.Errorf("%s: classify(%q) = %s, want %s", c.name, c.msg, got, kindBadArg)
		}
	}
}

// A job that parses as JSON but has the wrong field types is the caller's
// input error: metaLoadJob hands back the raw encoding/json error, which the
// classifier cannot place, so opLoadJob has to name the shape.
func TestOpLoadJobNamesAWrongShapedJob(t *testing.T) {
	p := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(p, []byte(`{"deep":"yes"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := opLoadJob(p); err == nil {
		t.Fatal("opLoadJob on {\"deep\":\"yes\"}: want an error, got none")
	} else if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("opLoadJob kind = %s, want %s (%v)", got, kindBadArg, err)
	}
}

// inline_comment used metaLoadJob behind ghidraGate: the gate probed the job
// file itself, saw text, and returned a "no decompiler kind" skip before the
// wrong shape could be named. Job ops must parse first so the bad_arg survives.
func TestInlineCommentDoesNotMaskWrongShapedJob(t *testing.T) {
	p := filepath.Join(t.TempDir(), "job.json")
	if err := os.WriteFile(p, []byte(`{"deep":"yes"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := runOp("inline_comment", p)
	if err == nil {
		t.Fatalf("inline_comment on {\"deep\":\"yes\"}: want bad_arg, got result %v", res)
	}
	if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("inline_comment kind = %s, want %s (%v)", got, kindBadArg, err)
	}
}

// A claim states a length and an expect-hex of the same length. Comparing
// whichever is shorter made {"length":4,"expect":"41"} pass as a 4-byte claim
// while it only ever read one byte.
func TestVerifyReconstructionRejectsClaimLengthMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.WriteFile(bin, []byte{0x41, 0x42, 0x43, 0x44}, 0o644); err != nil {
		t.Fatal(err)
	}
	job := filepath.Join(dir, "job.json")
	body := `{"file":"` + bin + `","claims":[{"offset":0,"length":4,"expect":"41"}]}`
	if err := os.WriteFile(job, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_STATE", dir)
	got, err := runOp("verify_reconstruction", job)
	if err != nil {
		t.Fatalf("verify_reconstruction: %v", err)
	}
	enc, _ := json.Marshal(got)
	if !strings.Contains(string(enc), `"match":false`) {
		t.Fatalf("a claim of 4 bytes with 1 expect byte matched: %s", enc)
	}
	if !strings.Contains(string(enc), "claim length 4 does not match 1 expect bytes") {
		t.Fatalf("the claim error does not name the mismatch: %s", enc)
	}
}

// A settings value outside its range was given and is wrong: bad_arg, not the
// internal kind a caller reads as "lrecon broke".
func TestUpdateAnalysisSettingsOutOfRangeIsBadArg(t *testing.T) {
	dir := t.TempDir()
	job := filepath.Join(dir, "job.json")
	if err := os.WriteFile(job, []byte(`{"maxBytes":0}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LRECON_STATE", dir)
	if _, err := runOp("update_analysis_settings", job); err == nil {
		t.Fatal("maxBytes 0: want an error, got none")
	} else if got := classify(err.Error()); got != kindBadArg {
		t.Fatalf("maxBytes 0 kind = %s, want %s (%v)", got, kindBadArg, err)
	}
}
