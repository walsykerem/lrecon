package main

func init() {
	registerOp(op{
		name:  "execute_rizin_command",
		route: "Y",
		desc:  "out of scope: lrecon does not drive a command console; the same static questions are Ghidra ops (list_procedures, inspect_binary_layout, xrefs, procedure_pseudo_code)",
		needs: true,
		run:   refuseRizinCommand,
	})
}
