package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// canonicalJSON is the one byte stream the evidence pointer covers: the digest
// marshaled, decoded with UseNumber (so int64 values keep their exact literal),
// then re-marshaled. encoding/json emits map keys sorted, so the result is
// independent of struct field order and of whitespace. Path is json:"-" and
// already excluded, which is why the same bytes give the same pointer from any
// directory.
func canonicalJSON(d Digest) ([]byte, error) {
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// evidenceLine is the attestation pointer: sha256 over canonicalJSON. Hashing
// Text() itself would make the pointer depend on the budget; hashing the JSON
// keeps the full document verifiable after the text is cut.
func evidenceLine(d Digest) (string, error) {
	c, err := canonicalJSON(d)
	if err != nil {
		return "", err
	}
	return evidenceLineFromCanonical(c), nil
}

func evidenceLineFromCanonical(c []byte) string {
	sum := sha256.Sum256(c)
	return "evidence: sha256:" + hex.EncodeToString(sum[:]) + "\n"
}

// digestTextWith renders Text() with a caller-computed evidence line, so one
// canonicalJSON + sha256 serves both the budget check and the body.
func digestTextWith(d Digest, ev string, limit int) string {
	body := d.Text()
	if limit <= 0 || len(body)+len(ev) <= limit {
		return body + ev
	}
	room := limit - len(ev) - budgetNoteReserve
	if room < 1 {
		return fmt.Sprintf("note: truncated at 0 of %d bytes; raise --max-bytes for more\n", len(body)) + ev
	}
	return truncate(body, room) + ev
}

// budgetNoteReserve covers the truncation note that truncate appends, so the
// evidence line still fits inside the caller's budget.
const budgetNoteReserve = 96

// digestText renders Text() with the evidence line last. A cut body never cuts
// the evidence line: the reader can still hash the full JSON document.
func digestText(d Digest, limit int) string {
	ev, err := evidenceLine(d)
	if err != nil {
		return d.Text()
	}
	return digestTextWith(d, ev, limit)
}

// digestFieldNames is the closed set of top-level contract keys.
var digestFieldNames = func() map[string]bool {
	m := map[string]bool{}
	t := reflect.TypeFor[Digest]()
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			m[name] = true
		}
	}
	return m
}()

// digestStringField returns the string value of a top-level field, so a claim
// whose value is that string can be attributed to the field's name.
func digestStringField(d Digest, field string) (string, bool) {
	v := reflect.ValueOf(d)
	t := v.Type()
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != field {
			continue
		}
		fv := v.FieldByIndex(f.Index)
		if fv.Kind() == reflect.String {
			return fv.String(), true
		}
		return "", false
	}
	return "", false
}

// ruleIDVersion is the rule identity the sha covers: the reader literal plus
// this build's version. Hashing the rule source slice is not possible at run
// time, so the pointer is over a fixed id+version string; it changes when the
// literal or the version changes and never with a byte offset.
func ruleIDVersion(id string) string {
	return "lrecon rule " + id + " v" + version
}

// ruleSHA is the rule digest an explanation prints.
func ruleSHA(id string) string {
	sum := sha256.Sum256([]byte(ruleIDVersion(id)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ExplainField answers "which rule, which byte" for one digest field. FIELD may
// be a contract key (toolchain, kind, minos, …), a claim source literal
// (luac-header) or a skip-reason field prefix (lua). The explanation names the
// claim, its byte offset and any refusal reason that stopped the field, plus the
// rule id and its sha. An unknown name is a refusal, not an empty answer.
func ExplainField(d Digest, field string) (string, error) {
	var claims []Claim
	var skips []Skip
	known := digestFieldNames[field]

	if v, ok := digestStringField(d, field); ok && v != "" {
		for _, c := range d.Claims {
			if c.Value == v {
				claims = append(claims, c)
			}
		}
	}
	// A source literal names the rule directly; a reason prefix names the reader.
	for _, c := range d.Claims {
		if c.Source == field && !containsClaim(claims, c) {
			claims = append(claims, c)
			known = true
		}
	}
	for _, s := range d.Skipped {
		if s.Reason == field || fieldOf(s.Reason) == field {
			skips = append(skips, s)
			known = true
		}
	}
	if !known {
		return "", fmt.Errorf("unknown field %q: not a digest key, a claim source or a skip reason", field)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "field: %s\n", field)
	for _, c := range claims {
		fmt.Fprintf(&b, "claim: %s (%s @%#x)\n", c.Value, c.Source, c.ByteOffset)
	}
	for _, s := range skips {
		if s.Detail != "" {
			fmt.Fprintf(&b, "reason: %s: %s\n", s.Reason, s.Detail)
		} else {
			fmt.Fprintf(&b, "reason: %s\n", s.Reason)
		}
	}
	if len(claims) == 0 && len(skips) == 0 {
		fmt.Fprintf(&b, "attribution: none\n")
	}
	seen := map[string]bool{}
	for _, c := range claims {
		if !seen[c.Source] {
			seen[c.Source] = true
			fmt.Fprintf(&b, "rule_id: %s\nrule_sha: %s\n", c.Source, ruleSHA(c.Source))
		}
	}
	for _, s := range skips {
		if !seen[s.Reason] {
			seen[s.Reason] = true
			fmt.Fprintf(&b, "rule_id: %s\nrule_sha: %s\n", s.Reason, ruleSHA(s.Reason))
		}
	}
	return b.String(), nil
}

func containsClaim(cs []Claim, c Claim) bool {
	for _, have := range cs {
		if have.Value == c.Value && have.Source == c.Source && have.ByteOffset == c.ByteOffset {
			return true
		}
	}
	return false
}
