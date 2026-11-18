package main

// 169. rizin_debug_session_status — y47: inventory row. A thread list needs a
// live inferior, which lrecon never starts, so the row points at the batch lldb
// equivalent instead of running `rizin -d -c dij`.
func init() {
	registerOp(op{
		name:  "rizin_debug_session_status",
		route: "Y",
		desc:  "out of scope: no live debug session exists to report on; the batch lldb answer is gdb_session_status (final.md y47)",
		needs: true,
		run:   refuseRizinDebug,
	})
}
