package main

// 138. frida_session_status — final.md y18 names Session.IsDetached() and
// Script.IsDestroyed() on a session the caller holds.
//
// There is no way to inspect another process's frida session table from the
// CLI, and lrecon has no session of its own to report on. Reporting
// "attachable" from a one-shot attach was an inference, not a status. The op
// refuses and leaves the live state to the caller's own driver. See
// op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "frida_session_status",
		route: "Y",
		desc:  "refuse live session status: lrecon owns no session and cannot see another process's (final.md y18)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
