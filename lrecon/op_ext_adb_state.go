package main

// External-tool items for adb device state (addendum 458-464, route Y). Each
// item drives one adb subcommand over the host transport and answers with
// what adb printed, or refuses honestly when adb is absent (no_engine) or
// the 60 s Y deadline hits (timeout).

import (
	"strconv"
	"strings"
)

func init() {
	registerExtOp(extOp{
		name:  "adb_disconnect",
		route: "Y",
		desc:  "adb disconnect from a network device: adb disconnect [HOST[:PORT]]",
		needs: false,
		run:   runAdbDisconnect,
	})
	registerExtOp(extOp{
		name:  "adb_tcpip",
		route: "Y",
		desc:  "adb tcpip mode: adb tcpip PORT (target = fixture; port comes from the extra arg)",
		needs: true,
		run:   runAdbTcpip,
	})
	registerExtOp(extOp{
		name:  "adb_emu",
		route: "Y",
		desc:  "adb emulator console command: adb emu COMMAND",
		needs: true,
		run:   runAdbEmu,
	})
	registerExtOp(extOp{
		name:  "adb_wait_for_device",
		route: "Y",
		desc:  "adb wait for a device to attach: adb wait-for-device (60 s)",
		needs: false,
		run:   runAdbWaitForDevice,
	})
	registerExtOp(extOp{
		name:  "adb_get_state",
		route: "Y",
		desc:  "adb device state: adb get-state (offline|bootloader|device)",
		needs: false,
		run:   runAdbGetState,
	})
	registerExtOp(extOp{
		name:  "adb_get_serialno",
		route: "Y",
		desc:  "adb device serial: adb get-serialno",
		needs: false,
		run:   runAdbGetSerialno,
	})
	registerExtOp(extOp{
		name:  "adb_reboot",
		route: "Y",
		desc:  "adb reboot into a mode: adb reboot [bootloader|recovery|sideload]",
		needs: false,
		run:   runAdbReboot,
	})
}

// adbRun runs one host-side adb subcommand and answers with its combined
// output. A missing adb is extAdb's no_engine refusal; a present adb that
// fails (no device, host unreachable) answers with the tool's own failure
// and main classifies it — never by synthesis.
func adbRun(args ...string) (any, error) {
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extAdb(ctx, args...)
	if err != nil {
		return nil, err
	}
	combined := strings.TrimSpace(out)
	if e := strings.TrimSpace(errOut); e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	return extOut{Tool: "adb", Args: args, Output: combined, Lines: rtLines(combined)}, nil
}

func runAdbDisconnect(path string, args []string) (any, error) {
	// adb disconnect [HOST[:PORT]]: the optional selector rides along.
	return adbRun(append([]string{"disconnect"}, args...)...)
}

func runAdbTcpip(path string, args []string) (any, error) {
	// Usage is validated before the tool is touched: a missing port is a
	// needs_arg even when adb is absent, and a non-numeric port is a bad_arg.
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, extRefuse(kindNeedsArg, "adb_tcpip needs a port: usage: lrecon --ext-op adb_tcpip TARGET PORT")
	}
	port, err := strconv.Atoi(strings.TrimSpace(args[0]))
	if err != nil || port < 1 || port > 65535 {
		return nil, extRefuse(kindBadArg, "adb_tcpip port %q is not a port number (1-65535)", args[0])
	}
	return adbRun("tcpip", strconv.Itoa(port))
}

func runAdbEmu(path string, args []string) (any, error) {
	// Usage is validated before the tool is touched: the console command is
	// required, an empty one is a needs_arg.
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, extRefuse(kindNeedsArg, "adb_emu needs an emulator console command: usage: lrecon --ext-op adb_emu TARGET COMMAND")
	}
	return adbRun(append([]string{"emu"}, args...)...)
}

func runAdbWaitForDevice(path string, args []string) (any, error) {
	// Bounded by the extCtx deadline: no device by then is a timeout.
	return adbRun("wait-for-device")
}

func runAdbGetState(path string, args []string) (any, error) {
	// Device absence is the tool's own failure, not synthesized here: adb
	// reports it and main classifies it.
	return adbRun("get-state")
}

func runAdbGetSerialno(path string, args []string) (any, error) {
	return adbRun("get-serialno")
}

func runAdbReboot(path string, args []string) (any, error) {
	// The mode is optional; when given it must be one adb knows.
	switch {
	case len(args) == 0 || strings.TrimSpace(args[0]) == "":
		return adbRun("reboot")
	case args[0] == "bootloader" || args[0] == "recovery" || args[0] == "sideload":
		return adbRun("reboot", args[0])
	}
	return nil, extRefuse(kindBadArg, "adb_reboot mode %q is not a reboot mode (bootloader|recovery|sideload)", args[0])
}
