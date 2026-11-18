package main

import (
	"encoding/json"
	"testing"
)

// TestDigestAbsenceContract pins final.md 106: "" is "not applicable/absent",
// null is "not measured", [] is "measured, none". The two cuts (row cap, value
// cap) are names for "not the whole answer", never for absence.
func TestDigestAbsenceContract(t *testing.T) {
	b, err := json.Marshal(Digest{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["rpaths"]; !ok || v != nil {
		t.Errorf("unmeasured rpaths = %v, want null", v)
	}
	if v, ok := m["minos"]; !ok || v != "" {
		t.Errorf("absent minos = %#v, want \"\": a string field is never null", v)
	}

	d := Digest{Rpaths: []string{}, Capabilities: []string{"a"}}
	b, err = json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	m = nil
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if v, ok := m["rpaths"].([]any); !ok || len(v) != 0 {
		t.Errorf("measured-empty rpaths = %#v, want []", m["rpaths"])
	}
	if v, ok := m["imports"]; !ok || v != nil {
		t.Errorf("untouched imports = %v, want null", v)
	}
}
