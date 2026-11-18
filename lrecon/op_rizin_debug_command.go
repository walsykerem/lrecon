package main

// 168. rizin_debug_command — y46: inventory row. A live debugger command is the
// same live instrumentation the frida and gdb session rows refuse, so the row
// answers with the lldb/Ghidra mapping instead of spawning `rizin -d`
// (report B7: no half-open debugger behind an op).
func init() {
	registerOp(op{
		name:  "rizin_debug_command",
		route: "Y",
		desc:  "out of scope: live debugger commands are not part of lrecon; the lldb batch equivalents are gdb_console and gdb_session_status (final.md y46)",
		needs: true,
		run:   refuseRizinDebug,
	})
}
