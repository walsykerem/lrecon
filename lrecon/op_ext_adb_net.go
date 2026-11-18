package main

// External-tool items for adb: forward/reverse lists and tweaks, connect,
// server state, root state, verity. Addendum 451-457, 465-475.

import "strings"

func init() {
	registerExtOp(extOp{
		name:  "adb_forward_list",
		route: "Y",
		desc:  "adb forward list: adb forward --list",
		needs: false,
		run:   adbForwardList,
	})
	registerExtOp(extOp{
		name:  "adb_forward_add",
		route: "Y",
		desc:  "adb forward add: adb forward tcp:LOCAL REMOTE (extra arg = remote)",
		needs: true,
		run:   adbForwardAdd,
	})
	registerExtOp(extOp{
		name:  "adb_forward_remove",
		route: "Y",
		desc:  "adb forward remove: adb forward --remove tcp:LOCAL",
		needs: true,
		run:   adbForwardRemove,
	})
	registerExtOp(extOp{
		name:  "adb_reverse_list",
		route: "Y",
		desc:  "adb reverse list: adb reverse --list",
		needs: false,
		run:   adbReverseList,
	})
	registerExtOp(extOp{
		name:  "adb_reverse_add",
		route: "Y",
		desc:  "adb reverse add: adb reverse tcp:REMOTE LOCAL (extra arg = local)",
		needs: true,
		run:   adbReverseAdd,
	})
	registerExtOp(extOp{
		name:  "adb_reverse_remove",
		route: "Y",
		desc:  "adb reverse remove: adb reverse --remove tcp:REMOTE",
		needs: true,
		run:   adbReverseRemove,
	})
	registerExtOp(extOp{
		name:  "adb_connect",
		route: "Y",
		desc:  "adb connect: adb connect HOST[:PORT] (target = host:port)",
		needs: true,
		run:   adbConnect,
	})
	registerExtOp(extOp{
		name:  "adb_remount",
		route: "Y",
		desc:  "adb remount: adb remount",
		needs: false,
		run:   adbRemount,
	})
	registerExtOp(extOp{
		name:  "adb_root",
		route: "Y",
		desc:  "adb root: adb root",
		needs: false,
		run:   adbRoot,
	})
	registerExtOp(extOp{
		name:  "adb_unroot",
		route: "Y",
		desc:  "adb unroot: adb unroot",
		needs: false,
		run:   adbUnroot,
	})
	registerExtOp(extOp{
		name:  "adb_usb",
		route: "Y",
		desc:  "adb usb: adb usb",
		needs: false,
		run:   adbUsb,
	})
	registerExtOp(extOp{
		name:  "adb_attach",
		route: "Y",
		desc:  "adb attach: adb attach",
		needs: false,
		run:   adbAttach,
	})
	registerExtOp(extOp{
		name:  "adb_detach",
		route: "Y",
		desc:  "adb detach: adb detach",
		needs: false,
		run:   adbDetach,
	})
	registerExtOp(extOp{
		name:  "adb_keygen",
		route: "Y",
		desc:  "adb keygen: adb keygen FILE (target = output key file dir)",
		needs: true,
		run:   adbKeygen,
	})
	registerExtOp(extOp{
		name:  "adb_disable_verity",
		route: "Y",
		desc:  "adb disable verity: adb disable-verity",
		needs: false,
		run:   adbDisableVerity,
	})
	registerExtOp(extOp{
		name:  "adb_enable_verity",
		route: "Y",
		desc:  "adb enable verity: adb enable-verity",
		needs: false,
		run:   adbEnableVerity,
	})
	registerExtOp(extOp{
		name:  "adb_server",
		route: "Y",
		desc:  "adb server: adb start-server|kill-server|reconnect (extra arg = verb)",
		needs: false,
		run:   adbServer,
	})
	registerExtOp(extOp{
		name:  "adb_jdwp",
		route: "Y",
		desc:  "adb jdwp: adb jdwp (streaming, bounded by the 60 s Y deadline)",
		needs: true,
		run:   adbJdwp,
	})
}

func adbForwardList(path string, args []string) (any, error) {
	return adbRun("forward", "--list")
}

func adbForwardAdd(path string, args []string) (any, error) {
	// target is tcp:LOCAL, extra arg is REMOTE (tcp:REMOTE or /path).
	local := strings.TrimSpace(path)
	if local == "" {
		return nil, extRefuse(kindNeedsArg, "adb_forward_add needs tcp:LOCAL: usage: lrecon --ext-op adb_forward_add tcp:LOCAL REMOTE")
	}
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, extRefuse(kindNeedsArg, "adb_forward_add needs REMOTE: usage: lrecon --ext-op adb_forward_add tcp:LOCAL REMOTE")
	}
	if !strings.HasPrefix(local, "tcp:") {
		local = "tcp:" + local
	}
	return adbRun("forward", local, strings.TrimSpace(args[0]))
}

func adbForwardRemove(path string, args []string) (any, error) {
	local := strings.TrimSpace(path)
	if local == "" {
		return nil, extRefuse(kindNeedsArg, "adb_forward_remove needs tcp:LOCAL: usage: lrecon --ext-op adb_forward_remove tcp:LOCAL")
	}
	if !strings.HasPrefix(local, "tcp:") {
		local = "tcp:" + local
	}
	return adbRun("forward", "--remove", local)
}

func adbReverseList(path string, args []string) (any, error) {
	return adbRun("reverse", "--list")
}

func adbReverseAdd(path string, args []string) (any, error) {
	remote := strings.TrimSpace(path)
	if remote == "" {
		return nil, extRefuse(kindNeedsArg, "adb_reverse_add needs tcp:REMOTE: usage: lrecon --ext-op adb_reverse_add tcp:REMOTE LOCAL")
	}
	if len(args) == 0 || strings.TrimSpace(args[0]) == "" {
		return nil, extRefuse(kindNeedsArg, "adb_reverse_add needs LOCAL: usage: lrecon --ext-op adb_reverse_add tcp:REMOTE LOCAL")
	}
	if !strings.HasPrefix(remote, "tcp:") {
		remote = "tcp:" + remote
	}
	return adbRun("reverse", remote, strings.TrimSpace(args[0]))
}

func adbReverseRemove(path string, args []string) (any, error) {
	remote := strings.TrimSpace(path)
	if remote == "" {
		return nil, extRefuse(kindNeedsArg, "adb_reverse_remove needs tcp:REMOTE: usage: lrecon --ext-op adb_reverse_remove tcp:REMOTE")
	}
	if !strings.HasPrefix(remote, "tcp:") {
		remote = "tcp:" + remote
	}
	return adbRun("reverse", "--remove", remote)
}

func adbConnect(path string, args []string) (any, error) {
	host := strings.TrimSpace(path)
	if host == "" {
		return nil, extRefuse(kindNeedsArg, "adb_connect needs HOST[:PORT]: usage: lrecon --ext-op adb_connect HOST[:PORT]")
	}
	return adbRun(append([]string{"connect", host}, args...)...)
}

func adbRemount(path string, args []string) (any, error) {
	return adbRun(append([]string{"remount"}, args...)...)
}

func adbRoot(path string, args []string) (any, error) {
	return adbRun("root")
}

func adbUnroot(path string, args []string) (any, error) {
	return adbRun("unroot")
}

func adbUsb(path string, args []string) (any, error) {
	return adbRun("usb")
}

func adbAttach(path string, args []string) (any, error) {
	return adbRun("attach")
}

func adbDetach(path string, args []string) (any, error) {
	return adbRun("detach")
}

func adbKeygen(path string, args []string) (any, error) {
	// keygen publishes the adb keypair under the target path; -o names the dir.
	name := strings.TrimSpace(path)
	if name == "" {
		return nil, extRefuse(kindNeedsArg, "adb_keygen needs a file: usage: lrecon --ext-op adb_keygen FILE")
	}
	return adbRun("keygen", name)
}

func adbDisableVerity(path string, args []string) (any, error) {
	return adbRun("disable-verity")
}

func adbEnableVerity(path string, args []string) (any, error) {
	return adbRun("enable-verity")
}

func adbServer(path string, args []string) (any, error) {
	verb := "start-server"
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		verb = strings.TrimSpace(args[0])
	}
	switch verb {
	case "start-server", "kill-server", "reconnect":
	default:
		return nil, extRefuse(kindBadArg, "adb_server verb %q is not one of start-server, kill-server, reconnect", verb)
	}
	return adbRun(verb)
}

func adbJdwp(path string, args []string) (any, error) {
	// jdwp streams forever; the 60 s Y deadline ends it, which extRun maps
	// to kindTimeout. A missing adb is no_engine before that.
	return adbRun("jdwp")
}
