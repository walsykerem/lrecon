package main

// 179. unload_frida_script — final.md y57 names Script.Unload().
//
// Unloading a script means a script is loaded in a live process, which only the
// caller's own driver can know about: lrecon has no session to inherit and does
// not inject. The op refuses with the mapping instead of loading a script just
// to unload it again. See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "unload_frida_script",
		route: "Y",
		desc:  "refuse live script unload: lrecon reads static files only and never injects a script (final.md y57)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
