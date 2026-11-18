package main

import "regexp"

func init() {
	registerOp(op{
		name:  "gdb_session_status",
		route: "Y",
		desc:  "thread list and stop reason from one `lldb --batch -o \"thread list\"` dialog (no inferior, so the empty list states why; target = binary)",
		needs: true,
		run:   gdbSessionStatusLLDB,
	})
}

type rtGdbThread struct {
	ID string `json:"id"`
}

type rtGdbStatus struct {
	Binary  string        `json:"binary"`
	Engine  string        `json:"engine,omitempty"`
	Threads []rtGdbThread `json:"threads"`
	Stopped string        `json:"stopped,omitempty"`
	Note    string        `json:"note,omitempty"`
	Output  []string      `json:"output"`
}

// lldb prints the two facts this op reports (thread ids, stop reason) in its
// own console dialect; both are scraped from the transcript (op_gdb_lldb.go).
var (
	rtLLDBThread = regexp.MustCompile(`thread #(\d+)`)
	rtLLDBStop   = regexp.MustCompile(`stop reason = ([^,\n]+)`)
)
