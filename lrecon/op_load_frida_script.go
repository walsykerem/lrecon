package main

// 158. load_frida_script — final.md y36 names CreateScript() + Script.Load()
// against a running process.
//
// Loading a script means injecting it into a live target and keeping the
// session open to read its output. lrecon reads static files and never injects
// an agent, so the op refuses with the live half mapped to the caller's own
// driver. See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "load_frida_script",
		route: "Y",
		desc:  "refuse live script load: lrecon reads static files only and never injects an agent (final.md y36, item 158)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
