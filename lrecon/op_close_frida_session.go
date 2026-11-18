package main

// 132. close_frida_session — final.md y13 names Script.Unload(), Session.Detach()
// and Clean() on a session the caller opened.
//
// Closing is the other half of a live session: there is nothing for lrecon to
// close, and a one-shot attach that already exited is not a session that was
// closed. The op refuses with the live half mapped to the caller's own driver.
// See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "close_frida_session",
		route: "Y",
		desc:  "refuse live session close: lrecon owns no session to detach or unload (final.md y13)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
