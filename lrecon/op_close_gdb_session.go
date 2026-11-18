package main

func init() {
	registerOp(op{
		name:  "close_gdb_session",
		route: "Y",
		desc:  "close state of the batch debugger: `lldb --batch -o \"process status\"` shows no session is held between ops (target = binary)",
		needs: true,
		run:   closeGdbSessionLLDB,
	})
}

type rtGdbClosed struct {
	Binary string   `json:"binary"`
	Engine string   `json:"engine,omitempty"`
	Exited bool     `json:"exited"`
	Note   string   `json:"note,omitempty"`
	Output []string `json:"output"`
}
