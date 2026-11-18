package main

// 149. instrument_with_frida — final.md y27 is the spawn + attach + load +
// resume chain driven by `frida -f <app> -l <script>`.
//
// Every step of that chain is live: spawn a process, attach, inject a script,
// resume it. lrecon reads static files and owns none of that state, so the op
// refuses with the chain mapped to the caller's own driver. See
// op_refuse_util.go.
func init() {
	registerOp(op{
		name:  "instrument_with_frida",
		route: "Y",
		desc:  "refuse live instrumentation: spawn+attach+inject+resume is not a static read (final.md y27, item 149)",
		needs: false,
		run:   refuseLiveFridaSession,
	})
}
