package main

// 172. start_frida_session — final.md y50 names Device.Attach(pid|name) or
// Device.Spawn(path), whose CLI face is `frida -p <pid> -e ...`.
//
// Attaching or spawning is a live-session move: the process has to exist and
// the caller's driver has to own it. lrecon reads static files and never owns a
// process, so the op refuses with the live half mapped to the caller's own
// driver instead of claiming an attach it did not make. See op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "start_frida_session",
		route: "Y",
		desc:  "refuse live session start/attach: lrecon reads static files only and never owns a process (final.md y50)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
