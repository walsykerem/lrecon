package main

// 159. observe_native_calls — final.md y37 names Interceptor.attach on a native
// export, whose CLI face is `frida-trace -i <symbol>`.
//
// Runtime call capture needs a live process and an injected agent; lrecon reads
// static files. The honest answer is the static half of the same question, and
// it already exists as Ghidra ops: `xrefs` for the call sites of a symbol,
// `get_call_graph` for the graph around it, `procedure_pseudo_code` for the
// body. The op stays registered so y37 gets that mapping instead of "unknown
// op". See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "observe_native_calls",
		route: "Y",
		desc:  "refuse runtime tracing (frida-trace): static answer is Ghidra xrefs/get_call_graph/procedure_pseudo_code (final.md y37)",
		needs: true,
		run:   refuseNativeCall,
	})
}
