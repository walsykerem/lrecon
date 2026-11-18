package main

// 167. resume_frida_session — final.md y45 names Session.Resume(), or
// Device.Resume(pid) right after a spawn.
//
// Resuming is a live-session move: the process has to exist, be spawned by the
// caller and be held stopped by the caller's driver. lrecon reads static files
// and does not own a session, so the op refuses with a named reason and the
// mapping (frida CLI/CDP for the live half) instead of pretending a shell
// python shim was the same thing. See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "resume_frida_session",
		route: "Y",
		desc:  "refuse live session resume: lrecon reads static files only and never drives a spawn (final.md y45)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
