package main

// 173. start_gdb_session — final.md y51 names a live gdb (MI2) session.
//
// lrecon reads static files and never launches, attaches to or drives a live
// process. The op stays registered so a caller asking for y51 gets a named
// refusal instead of "unknown op", and it refuses before anything is spawned:
// the old body ran `lldb --batch ... process launch` here and reported the
// platform's "attach failed" as kind internal, which claimed a live-debug
// capability the tool does not have (report B7).
//
// The answer travels through errors.go's kind contract: one envelope with
// kind "no_engine" and exit 2, matching main.go's runtimeDecline wording.
const liveDebugDecline = "live debug sessions out of scope: lrecon reads static files only; for a live target drive lldb yourself (lldb --batch -o run -o bt), while the file-level gdb_console, gdb_session_status and close_gdb_session rows answer from the binary on disk"

func init() {
	registerOp(op{
		name:  "start_gdb_session",
		route: "Y",
		desc:  "refuse live debugging: lrecon reads static files only and never launches gdb/lldb (final.md y51)",
		needs: true,
		run:   refuseLiveDebug,
	})
}

// refuseLiveDebug is the run body for every live-debug item. refuseKind exits
// the process (stdout envelope under --json, stderr otherwise), so the return
// below is unreachable; keeping the (any, error) shape lets the op table
// register it like any other item.
func refuseLiveDebug(string) (any, error) {
	refuseKind(kindOutOfScope, liveDebugDecline)
	return nil, nil
}
