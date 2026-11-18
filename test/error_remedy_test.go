package main

import (
	"strings"
	"testing"
)

// Failure-only discovery: a wrong op call answers once, on failure, with a
// machine envelope on stdout (kind + the next step in error) and one lrecon:
// hint on stderr. No 11-ref read and no 235-op listing here; both remedies
// below come from the failure envelope itself.
func TestFailureDiscoveryRemedy(t *testing.T) {
	t.Setenv("LRECON_AT", "")
	t.Setenv("LRECON_NAME", "")

	cases := []struct {
		name   string
		args   []string
		kind   string
		remedy string
	}{
		{
			name:   "needs_arg names the address env",
			args:   []string{"--op", "procedure_pseudo_code", "--json", fixtureMacho},
			kind:   "needs_arg",
			remedy: "set LRECON_AT (address) or LRECON_NAME (symbol) for this op",
		},
		{
			name:   "bad_arg names the op catalog",
			args:   []string{"--op", "no_such_op_for_test", "--json", fixtureMacho},
			kind:   "bad_arg",
			remedy: "see --list-ops",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stdout, stderr, code := runCLIAll(t, c.args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2; stdout:\n%s\nstderr:\n%s", code, stdout, stderr)
			}
			m := decodeEnvelope(t, stdout)
			if m["kind"] != c.kind {
				t.Fatalf("kind = %v, want %s: %s", m["kind"], c.kind, stdout)
			}
			if detail, _ := m["error"].(string); !strings.Contains(detail, c.remedy) {
				t.Fatalf("error = %q, want the %q remedy", detail, c.remedy)
			}
			if !strings.HasPrefix(stderr, "lrecon: ") || !strings.Contains(stderr, c.remedy) {
				t.Fatalf("stderr = %q, want the lrecon: hint carrying %q", stderr, c.remedy)
			}
		})
	}
}
