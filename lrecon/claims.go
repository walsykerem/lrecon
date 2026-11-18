package main

import "slices"

import "sort"

// witnessMechs is the closed set the two-witness rule compares on Witness.Axis.
// A mechanism outside it has no identity to compare, so it cannot be one of the
// two, and no string a reader prints can stand in for a second reader.
var witnessMechs = map[string]bool{"parser": true, "sig": true, "passthrough": true}

// claimSlots is the whole claim surface for this release. A slot outside it is
// refused by name rather than generalised on the spot.
var claimSlots = map[string]bool{"language": true, "producer": true}

// Unknown is a slot that was looked for and not settled, with the rule that
// refused it. "Saw one witness" and "never looked" are different reasons.
type Unknown struct {
	Slot     string   `json:"slot"`
	Witness  *Witness `json:"witness,omitempty"`
	Reasons  []string `json:"reasons"`
	Searched []string `json:"searched,omitempty"`
}

// Conflict keeps both values for one slot. Picking a winner here would be a
// guess dressed as evidence.
type Conflict struct {
	Slot      string    `json:"slot"`
	Values    []string  `json:"values"`
	Witnesses []Witness `json:"witnesses,omitempty"`
}

// claimReq is one settlement proposal: a slot, its value, the witnesses behind
// it, and the slots it rests on.
type claimReq struct {
	Slot      string
	Value     string
	Witnesses []Witness
	Deps      []string
}

// emit settles a batch of proposals against the claim rules and writes the
// outcome to Claims, Unknown and Conflicts. Nothing is guessed: a proposal that
// fails a rule lands in Unknown with the rule that refused it, and two values
// for one slot keep both in Conflicts instead of picking a winner.
//
// State is per call: one emit call settles each slot at most once, so callers
// pass every proposal for a slot in the same batch. settleLanguage (sigpack.go)
// is the only reader that emits today; producer.go still records its claims
// through the legacy (*Digest).claim shim, which carries one mechanism and no
// confidence.
func (d *Digest) emit(reqs ...claimReq) {
	state := make([]string, len(reqs)) // "" = standing, else the refusing reason
	conflictValues := map[string][]string{}
	conflictWitnesses := map[string][]Witness{}
	for i, r := range reqs {
		if !claimSlots[r.Slot] {
			state[i] = "slot-unsupported"
			continue
		}
		if gap := witnessGap(r.Witnesses); gap != "" {
			state[i] = gap
			continue
		}
		if !hasValue(conflictValues[r.Slot], r.Value) {
			conflictValues[r.Slot] = append(conflictValues[r.Slot], r.Value)
			conflictWitnesses[r.Slot] = append(conflictWitnesses[r.Slot], r.Witnesses...)
		}
	}
	conflicted := map[string]bool{}
	var conflictedSlots []string
	for slot, values := range conflictValues {
		if len(values) < 2 {
			continue
		}
		conflictedSlots = append(conflictedSlots, slot)
		d.Conflicts = append(d.Conflicts, Conflict{Slot: slot, Values: values, Witnesses: conflictWitnesses[slot]})
	}
	sort.Strings(conflictedSlots)
	for _, slot := range conflictedSlots {
		for i := range reqs {
			if state[i] == "" && reqs[i].Slot == slot {
				state[i] = "slot-conflict"
			}
		}
		conflicted[slot] = true
	}
	// A premise is read one hop deep: a claim whose direct premise was dropped
	// goes with it, but a chain of drops is not chased any further.
	for i, r := range reqs {
		if state[i] != "" {
			continue
		}
		if reason := badDep(r.Deps, reqs, state, conflicted); reason != "" {
			state[i] = reason
		}
	}
	standing := map[string]int{}
	for i, r := range reqs {
		if state[i] == "" {
			standing[r.Slot] = i
		}
	}
	for i, r := range reqs {
		if state[i] == "" && reaches(r.Slot, r.Deps, reqs, standing, map[string]bool{}) {
			state[i] = "deps-cycle"
		}
	}
	settled := map[string]bool{}
	for i, r := range reqs {
		if state[i] != "" {
			d.Unknown = append(d.Unknown, Unknown{
				Slot:     r.Slot,
				Witness:  firstWitness(r.Witnesses),
				Reasons:  []string{state[i]},
				Searched: sourcesOf(r.Witnesses),
			})
			continue
		}
		if settled[r.Slot] {
			continue // one slot settles to one value; a repeat adds no evidence
		}
		settled[r.Slot] = true
		c := Claim{Slot: r.Slot, Value: r.Value, Witnesses: r.Witnesses, Conf: confOf(len(r.Witnesses))}
		if len(r.Witnesses) > 0 {
			c.Source = r.Witnesses[0].Class
			c.ByteOffset = r.Witnesses[0].Start
		}
		d.Claims = append(d.Claims, c)
	}
}

// reaches reports whether slot can walk back to itself over standing deps.
func reaches(slot string, deps []string, reqs []claimReq, standing map[string]int, seen map[string]bool) bool {
	for _, dep := range deps {
		if dep == slot {
			return true
		}
		i, ok := standing[dep]
		if !ok || seen[dep] {
			continue
		}
		seen[dep] = true
		if reaches(slot, reqs[i].Deps, reqs, standing, seen) {
			return true
		}
	}
	return false
}

// badDep names the first premise that cannot carry a claim.
func badDep(deps []string, reqs []claimReq, state []string, conflicted map[string]bool) string {
	for _, dep := range deps {
		if conflicted[dep] {
			return "premise-conflict:" + dep
		}
		found := false
		for i, r := range reqs {
			if r.Slot != dep {
				continue
			}
			found = true
			if state[i] != "" {
				return "premise-aborted:" + dep
			}
		}
		if !found {
			return "premise-unknown:" + dep
		}
	}
	return ""
}

// witnessGap names the first rule a witness set fails, or "" when it clears the
// bar: at least two witnesses, each citing a byte offset, each from a different
// mechanism, on ranges that do not overlap.
func witnessGap(ws []Witness) string {
	if len(ws) < 2 {
		return "witness-count"
	}
	mechs := map[string]bool{}
	for _, w := range ws {
		if w.Start < 0 {
			return "witness-no-offset"
		}
		if !witnessMechs[w.Axis] {
			return "witness-mech-unknown"
		}
		if mechs[w.Axis] {
			return "witness-same-mech"
		}
		mechs[w.Axis] = true
	}
	for i := range ws {
		for j := i + 1; j < len(ws); j++ {
			if !disjointSpans([][2]int64{spanOf(ws[i])}, [][2]int64{spanOf(ws[j])}) {
				return "witness-overlap"
			}
		}
	}
	return ""
}

// confOf is the witness ratio, not a calibrated probability: two independent
// witnesses are the bar and each extra one moves the value toward 1.
func confOf(n int) float64 { return float64(n) / float64(n+1) }

func hasValue(values []string, v string) bool {
	return slices.Contains(values, v)
}

func firstWitness(ws []Witness) *Witness {
	if len(ws) == 0 {
		return nil
	}
	w := ws[0]
	return &w
}

func sourcesOf(ws []Witness) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		if w.Class == "" || seen[w.Class] {
			continue
		}
		seen[w.Class] = true
		out = append(out, w.Class)
	}
	sort.Strings(out)
	return out
}
