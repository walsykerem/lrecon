package main

// 174. start_rizin_debug_session — final.md y52 names `rizin -q0 -d`.
//
// Same scope rule as start_gdb_session (see op_start_gdb_session.go): the op
// is inventory, not a live driver. It refuses with kind "out_of_scope" before
// any process is started, so a caller never gets a half-open debugger or the
// toolchain's attach error dressed up as an lrecon result (report B7).
func init() {
	registerOp(op{
		name:  "start_rizin_debug_session",
		route: "Y",
		desc:  "refuse live debugging: lrecon reads static files only and never launches rizin -d (final.md y52)",
		needs: true,
		run:   refuseRizinDebug,
	})
}
