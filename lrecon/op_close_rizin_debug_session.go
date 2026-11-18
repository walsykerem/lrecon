package main

// 170. close_rizin_debug_session — y15: inventory row. lrecon holds no debugger
// between invocations, so there is no session to close; the honest answer names
// the batch equivalent rather than opening a session in order to close it
// (report B7).
func init() {
	registerOp(op{
		name:  "close_rizin_debug_session",
		route: "Y",
		desc:  "out of scope: lrecon holds no debugger process between ops, so there is nothing to close; the lldb batch equivalent is close_gdb_session (final.md y15)",
		needs: true,
		run:   refuseRizinDebug,
	})
}
