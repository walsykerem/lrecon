package main

// Shared refusal bodies for the ops whose engine was removed from lrecon.
//
// lrecon reads static files: it never starts, attaches to, resumes or stops a
// live session, and it never injects a script. The ops stay registered under
// their 229 inventory names so a caller gets a named refusal with a concrete
// mapping (which static question answers the same thing, or which driver does
// the live part) instead of "unknown op". The mapping names tools; it never
// suggests installing one.

// liveFridaSessionDecline covers the frida session/instrument ops (y40–y45,
// y56–y57, y70). The static half is a Ghidra or file read; the live half is
// the caller's own driver.
const liveFridaSessionDecline = "out of scope: lrecon reads static files and never starts, attaches to, resumes or stops a live session; for a live target drive the frida CLI or a CDP page (observe_javascript_runtime), for the Android process list use list_frida_processes, and for JS semantics use observe_javascript_runtime over cdp:"

// refuseLiveFridaSession is the run body for every frida session item.
// refuseKind exits the process (stdout envelope under --json, stderr
// otherwise), so the return below is unreachable; the (any, error) shape lets
// the op table register it like any other item.
func refuseLiveFridaSession(string) (any, error) {
	refuseKind(kindOutOfScope, liveFridaSessionDecline)
	return nil, nil
}

// javascriptRuntimeFridaDecline is observe_javascript_runtime's frida: branch.
// The op keeps its CDP half; only the in-process attach is out of scope.
const javascriptRuntimeFridaDecline = "out of scope: attaching to a process with frida is live instrumentation, which lrecon does not do; the same question about a page's JavaScript is answered over CDP — call observe_javascript_runtime with cdp:<host:port>"

// nativeCallDecline covers observe_native_calls (y37, frida-trace). The static
// question — where is this symbol called from, what does its caller graph look
// like, what is its body — is answered by the Ghidra ops, which stay.
const nativeCallDecline = "out of scope: runtime tracing is live instrumentation, which lrecon does not do; the static answer is Ghidra: xrefs for call sites of the symbol, get_call_graph for the call graph, procedure_pseudo_code for the body"

func refuseNativeCall(string) (any, error) {
	refuseKind(kindOutOfScope, nativeCallDecline)
	return nil, nil
}

// rizinCommandDecline covers execute_rizin_command and cutter_command (y89–y90).
// Each rizin command named in the inventory has a Ghidra op with the same job.
const rizinCommandDecline = "out of scope: lrecon does not drive a command console; the same static questions are Ghidra ops: list_procedures (rizin afl), inspect_binary_layout (rizin iI), xrefs (rizin axt), procedure_pseudo_code (rizin pdf)"

func refuseRizinCommand(string) (any, error) {
	refuseKind(kindOutOfScope, rizinCommandDecline)
	return nil, nil
}

// rizinDebugDecline covers the rizin debug session items (y91–y94). Their lldb
// equivalents are the gdb_* ops, which drive lldb in batch mode.
const rizinDebugDecline = "out of scope: live debug sessions are not part of lrecon; the lldb batch equivalents are gdb_console (tt/bt), gdb_session_status (thread list), close_gdb_session (process kill), and gdb_console with an expression for rizin's debug commands"

func refuseRizinDebug(string) (any, error) {
	refuseKind(kindOutOfScope, rizinDebugDecline)
	return nil, nil
}
