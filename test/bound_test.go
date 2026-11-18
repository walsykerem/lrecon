package main

import "testing"

func TestAllocCeilRefusesAboveLimit(t *testing.T) {
	var d Digest
	buf, ok := allocCeil(&d, "asar", maxAsarHeader+1, "asar-too-big")
	if ok || buf != nil {
		t.Fatalf("allocCeil accepted declared %d over the asar cap %d", maxAsarHeader+1, maxAsarHeader)
	}
	if len(d.Skipped) != 1 || d.Skipped[0].Reason != "asar-too-big" {
		t.Fatalf("refusal not recorded: %+v", d.Skipped)
	}
	buf, ok = allocCeil(&d, "pe", maxPEHeader, "pe-too-big")
	if !ok || len(buf) != maxPEHeader {
		t.Fatalf("allocCeil refused a length inside the PE cap: ok=%v len=%d", ok, len(buf))
	}
	for _, c := range []struct {
		field string
		n     int64
	}{{"asar", -1}, {"nowhere", 1}, {"pe", maxPEHeader + 1}} {
		if buf, ok := allocCeil(&d, c.field, c.n, "pe-too-big"); ok || buf != nil {
			t.Fatalf("allocCeil accepted field %q declared %d", c.field, c.n)
		}
	}
	if err := d.checkReasons(); err != nil {
		t.Fatalf("refusals used an unregistered reason: %v", err)
	}
}

func FuzzAllocCeil(f *testing.F) {
	f.Add(int64(0), "pe")
	f.Add(int64(maxPEHeader+1), "pe")
	f.Add(int64(1<<32), "asar")
	f.Fuzz(func(t *testing.T, declared int64, field string) {
		if field != "asar" && field != "pe" {
			field = "asar"
		}
		var d Digest
		buf, ok := allocCeil(&d, field, declared, field+"-too-big")
		cap := allocCeilCeiling[field]
		if ok {
			if int64(len(buf)) != declared {
				t.Fatalf("allocated %d for declared %d", len(buf), declared)
			}
			if declared > cap {
				t.Fatalf("allocCeil returned %d bytes for declared %d (cap %d)", len(buf), declared, cap)
			}
			return
		}
		if buf != nil {
			t.Fatalf("refused path returned %d bytes", len(buf))
		}
		if declared >= 0 && declared <= cap && len(d.Skipped) != 0 {
			t.Fatalf("refused declared %d inside the %s cap %d", declared, field, cap)
		}
	})
}

// TestAllocCeilAsarBody checks a member body is bounded by the extraction cap,
// not by the header-JSON cap: Studio.app ships a 67.5 MiB member, and reading
// it through the 64 MiB header ceiling refused a perfectly legal body.
func TestAllocCeilAsarBody(t *testing.T) {
	var d Digest
	big := int64(68 << 20) // over maxAsarHeader, under maxExtract
	if buf, ok := allocCeil(&d, "asar", big, "asar-too-big"); ok || buf != nil {
		t.Fatalf("header field accepted %d bytes", big)
	}
	buf, ok := allocCeil(&d, "asar-body", big, "asar-too-big")
	if !ok || int64(len(buf)) != big {
		t.Fatalf("asar-body refused %d: ok=%v len=%d", big, ok, len(buf))
	}
	if buf, ok := allocCeil(&d, "asar-body", maxExtract+1, "asar-too-big"); ok || buf != nil {
		t.Fatalf("asar-body accepted %d over maxExtract %d", maxExtract+1, maxExtract)
	}
	if err := d.checkReasons(); err != nil {
		t.Fatalf("refusals used an unregistered reason: %v", err)
	}
}
