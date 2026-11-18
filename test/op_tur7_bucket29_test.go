package main

import (
	"go/build"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// roleLabel is the shape of a declared role: one lowercase word, optional
// hyphenated tail. A label with a space or a colon is prose that slipped into
// the vocabulary, not a role.
var roleLabel = regexp.MustCompile(`^[a-z][a-z0-9]*(-[a-z0-9]+)*$`)

// TestTur7Bucket29PlatformDispatch proves the three proctable_*.go files are a
// real build-tag dispatch rather than dead copies: exactly one matches this
// host, its behaviour (live table vs refusal) is the one that ran, a pid the
// live table does not contain is refused by name instead of answering empty,
// and the reason and role vocabulary a verdict can carry is closed — declared
// tokens only, never ad-hoc prose.
func TestTur7Bucket29PlatformDispatch(t *testing.T) {
	// ---- 1. The tag is the selector -------------------------------------
	want := "proctable_other.go"
	switch runtime.GOOS {
	case "darwin":
		want = "proctable_darwin.go"
	case "linux":
		want = "proctable_linux.go"
	}
	var matched []string
	for _, name := range []string{"proctable_darwin.go", "proctable_linux.go", "proctable_other.go"} {
		ok, err := build.Default.MatchFile(".", name)
		if err != nil {
			t.Fatalf("MatchFile(%s): %v", name, err)
		}
		if ok {
			matched = append(matched, name)
		}
	}
	if len(matched) != 1 || matched[0] != want {
		t.Fatalf("build tags on %s select %v, want exactly [%s]", runtime.GOOS, matched, want)
	}

	// ---- 2. The selected file is the one that answers -------------------
	table := map[int]string{}
	rows, err := listProcesses()
	if want == "proctable_other.go" {
		// Unsupported host: refusal with the OS named, never an empty success.
		if err == nil {
			t.Fatalf("listProcesses on %s returned %d rows with no error; the other-OS file must refuse", runtime.GOOS, len(rows))
		}
		if !strings.Contains(err.Error(), runtime.GOOS) {
			t.Fatalf("other-OS refusal %q does not name GOOS %s", err, runtime.GOOS)
		}
		if rows != nil {
			t.Fatalf("other-OS refusal also returned %d rows", len(rows))
		}
	} else {
		if err != nil {
			t.Fatalf("listProcesses: %v", err)
		}
		self := os.Getpid()
		found := false
		for _, r := range rows {
			table[r.PID] = r.Comm
			if r.PID == self {
				found = true
				if strings.TrimSpace(r.Comm) == "" {
					t.Fatalf("own pid %d is in the table with an empty comm", r.PID)
				}
			}
		}
		if !found {
			t.Fatalf("listProcesses returns %d rows without own pid %d: a canned table, not this host's", len(rows), self)
		}
		// The empty note fingerpoints the file that answered, so a copy that
		// compiled under the wrong tag cannot pass on rows alone.
		list, err := rt2HostProcessList("")
		if err != nil {
			t.Fatalf("rt2HostProcessList: %v", err)
		}
		if list.Count != len(list.Processes) || list.Count == 0 {
			t.Fatalf("rt2HostProcessList count %d for %d rows", list.Count, len(list.Processes))
		}
		token := "/proc"
		if runtime.GOOS == "darwin" {
			token = "kern.proc.all"
		}
		if !strings.Contains(list.Note, token) {
			t.Fatalf("process table note %q does not name %s: the wrong platform file answered", list.Note, token)
		}
		for _, p := range list.Processes {
			if p.PID <= 0 || p.Name == "" {
				t.Fatalf("process row %+v is not a real table entry", p)
			}
		}
	}

	// ---- 3. A pid the table lacks is refused by name --------------------
	dead := 1 << 22 // above any host's pid_max
	for i := 0; i < 64; i++ {
		if _, inTable := table[dead]; !inTable && !pidAlive(dead) {
			break
		}
		dead++
	}
	if _, inTable := table[dead]; inTable || pidAlive(dead) {
		t.Fatalf("could not find a pid outside the table near %d", dead)
	}
	v, err := runOp("capture_process_scenario", strconv.Itoa(dead))
	if err != nil {
		t.Fatalf("capture_process_scenario(%d) as a pid: %v", dead, err)
	}
	sk, ok := v.(*skip)
	if !ok {
		t.Fatalf("capture_process_scenario(%d) answered %T (%v); a pid absent from the table must be a refusal, not an empty success", dead, v, v)
	}
	if !strings.Contains(sk.Reason, strconv.Itoa(dead)) || !strings.Contains(sk.Reason, "no live process") {
		t.Fatalf("refusal %q does not name pid %d and the missing process", sk.Reason, dead)
	}

	// ---- 4. Reasons come from the reader's declared set ------------------
	var pycReader *reader
	for i := range readers {
		if readers[i].format == "pyc" {
			pycReader = &readers[i]
		}
	}
	if pycReader == nil {
		t.Fatal("no reader registered for format pyc")
	}
	declared := make(map[string]bool, len(pycReader.reasons))
	for _, r := range pycReader.reasons {
		declared[r] = true
	}
	crafted := filepath.Join(t.TempDir(), "magic_only.pyc")
	// Valid pyc magic for an interpreter this tool never pinned, no header body.
	if err := os.WriteFile(crafted, []byte{0x80, 0x0c, 0x0d, 0x0a}, 0o644); err != nil {
		t.Fatalf("write crafted pyc: %v", err)
	}
	reasonsSeen := 0
	for _, path := range []string{filepath.Join("testdata", "fixtures", "pyc", "fixture_pyc.pyc"), crafted} {
		d, err := Probe(path)
		if err != nil {
			t.Fatalf("Probe(%s) rejected the verdict: %v", path, err)
		}
		if d.Format != "pyc" {
			t.Fatalf("Probe(%s) format %q, want pyc", path, d.Format)
		}
		for _, s := range d.Skipped {
			reasonsSeen++
			if strings.ContainsAny(s.Reason, " :") {
				t.Fatalf("verdict for %s emits reason %q: prose, not a declared token", path, s.Reason)
			}
			if !declared[s.Reason] {
				t.Fatalf("verdict for %s emits reason %q, not in the pyc reader's declared set %v", path, s.Reason, pycReader.reasons)
			}
			if !reasonRegistry[fieldOf(s.Reason)][s.Reason] {
				t.Fatalf("reason %q is not in registry field %q", s.Reason, fieldOf(s.Reason))
			}
		}
	}
	if reasonsSeen == 0 {
		t.Fatal("no reason emitted by a real pyc target; the vocabulary check proved nothing")
	}

	// ---- 5. Roles are declared labels, exercised on real link names ------
	declaredRoles := make(map[string]bool, len(roleRules))
	for _, r := range roleRules {
		if r.pat == "" || r.pat != strings.ToLower(r.pat) {
			t.Fatalf("role pattern %q is not a lowercase substring", r.pat)
		}
		if !roleLabel.MatchString(r.role) {
			t.Fatalf("role %q is not a closed-vocabulary label", r.role)
		}
		declaredRoles[r.role] = true
	}
	// /usr/bin/curl is a real, dynamically linked target: it links libcurl and
	// libz, so the vocabulary is exercised, not just declared. An absent target
	// is a failure, never a quiet pass.
	const roleTarget = "/usr/bin/curl"
	st, err := os.Stat(roleTarget)
	if err != nil {
		t.Fatalf("real role target %s is unavailable: %v", roleTarget, err)
	}
	if !st.Mode().IsRegular() {
		t.Fatalf("real role target %s is not a regular file (%s)", roleTarget, st.Mode().Type())
	}
	d, err := Probe(roleTarget)
	if err != nil {
		t.Fatalf("Probe(%s) rejected the verdict: %v", roleTarget, err)
	}
	names := append(append([]string{}, d.Dylibs...), d.Imports...)
	for _, dep := range d.Deps {
		names = append(names, dep.Path)
	}
	hits := 0
	for _, name := range names {
		role := RoleOf(name)
		if role == "" {
			continue
		}
		hits++
		if !declaredRoles[role] {
			t.Fatalf("RoleOf(%q) = %q, outside the declared vocabulary", name, role)
		}
		low := strings.ToLower(name)
		first := ""
		for _, r := range roleRules {
			if strings.Contains(low, r.pat) {
				first = r.role
				break
			}
		}
		if role != first {
			t.Fatalf("RoleOf(%q) = %q but the declared rules say %q", name, role, first)
		}
	}
	if hits == 0 {
		t.Fatalf("no role derived from %s's %d linked names; the vocabulary was never exercised", roleTarget, len(names))
	}
}
