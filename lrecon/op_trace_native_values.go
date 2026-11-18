package main

// 177. trace_native_values — final.md y55 hooks onEnter/onLeave and reads
// args[i] / retval from the live call, then reports each send() payload.
//
// Reading a value at runtime needs a live hook in a live process. lrecon reads
// static files, so the op refuses and names the static answer: the Ghidra ops
// that show call sites and the procedure body. See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "trace_native_values",
		route: "Y",
		desc:  "refuse runtime value tracing: live onEnter/onLeave hooks are not a static read; static answer is Ghidra xrefs + procedure_pseudo_code (final.md y55)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
