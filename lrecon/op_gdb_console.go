package main

func init() {
	registerOp(op{
		name:  "gdb_console",
		route: "Y",
		desc:  "one batch console pass over a binary (`target list`, `image list`) on `lldb --batch`, no inferior started (target = binary)",
		needs: true,
		run:   gdbConsoleLLDB,
	})
}

type rtGdbConsole struct {
	Binary string   `json:"binary"`
	Engine string   `json:"engine,omitempty"`
	Output []string `json:"output"`
}
