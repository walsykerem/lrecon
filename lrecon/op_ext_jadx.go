package main

// External-tool items for jadx (addendum 496-507). Each drives `jadx` with
// the addendum's flags into extDir(); a missing jadx is no_engine.

func init() {
	registerExtOp(extOp{
		name:  "jadx_export_gradle",
		route: "Y",
		desc:  "jadx export gradle: jadx -e --export-gradle-type auto -d DIR APK",
		needs: true,
		run:   jadxExportGradle,
	})
	registerExtOp(extOp{
		name:  "jadx_deobf",
		route: "Y",
		desc:  "jadx deobf: jadx --deobf -d DIR APK",
		needs: true,
		run:   jadxDeobf,
	})
	registerExtOp(extOp{
		name:  "jadx_call_graph",
		route: "Y",
		desc:  "jadx call graph: jadx --call-graph dot -d DIR APK",
		needs: true,
		run:   jadxCallGraph,
	})
	registerExtOp(extOp{
		name:  "jadx_cfg",
		route: "Y",
		desc:  "jadx cfg: jadx --cfg -d DIR APK",
		needs: true,
		run:   jadxCfg,
	})
	registerExtOp(extOp{
		name:  "jadx_raw_cfg",
		route: "Y",
		desc:  "jadx raw cfg: jadx --raw-cfg -d DIR APK",
		needs: true,
		run:   jadxRawCfg,
	})
	registerExtOp(extOp{
		name:  "jadx_output_json",
		route: "Y",
		desc:  "jadx output json: jadx --output-format json -d DIR APK",
		needs: true,
		run:   jadxOutputJson,
	})
	registerExtOp(extOp{
		name:  "jadx_no_res",
		route: "Y",
		desc:  "jadx no res: jadx -r -d DIR APK",
		needs: true,
		run:   jadxNoRes,
	})
	registerExtOp(extOp{
		name:  "jadx_no_src",
		route: "Y",
		desc:  "jadx no src: jadx -s -d DIR APK",
		needs: true,
		run:   jadxNoSrc,
	})
	registerExtOp(extOp{
		name:  "jadx_mappings",
		route: "Y",
		desc:  "jadx mappings: jadx --mappings-path FILE -d DIR APK (extra arg = mappings file)",
		needs: true,
		run:   jadxMappings,
	})
	registerExtOp(extOp{
		name:  "jadx_fallback",
		route: "Y",
		desc:  "jadx fallback: jadx -f -d DIR APK",
		needs: true,
		run:   jadxFallback,
	})
	registerExtOp(extOp{
		name:  "jadx_single_class_full",
		route: "Y",
		desc:  "jadx single class full: jadx --single-class FQCN --single-class-output FILE APK (extra arg = FQCN)",
		needs: true,
		run:   jadxSingleClassFull,
	})
	registerExtOp(extOp{
		name:  "jadx_plugins",
		route: "Y",
		desc:  "jadx plugins: jadx plugins",
		needs: false,
		run:   jadxPlugins,
	})
}

func jadxRun(path string, args []string, jadxArgs ...string) (any, error) {
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	full := []string{"-d", dir}
	full = append(full, jadxArgs...)
	full = append(full, path)
	full = append(full, args...)
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "jadx", extJadxAlt, full...)
	if err != nil {
		return nil, err
	}
	combined := out
	if e := errOut; e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	return extOut{Tool: "jadx", Args: full, Output: combined, Lines: rtLines(combined)}, nil
}

func jadxExportGradle(path string, args []string) (any, error) {
	return jadxRun(path, args, "-e", "--export-gradle-type", "auto")
}

func jadxDeobf(path string, args []string) (any, error) {
	return jadxRun(path, args, "--deobf")
}

func jadxCallGraph(path string, args []string) (any, error) {
	return jadxRun(path, args, "--call-graph", "dot")
}

func jadxCfg(path string, args []string) (any, error) {
	return jadxRun(path, args, "--cfg")
}

func jadxRawCfg(path string, args []string) (any, error) {
	return jadxRun(path, args, "--raw-cfg")
}

func jadxOutputJson(path string, args []string) (any, error) {
	return jadxRun(path, args, "--output-format", "json")
}

func jadxNoRes(path string, args []string) (any, error) {
	return jadxRun(path, args, "-r")
}

func jadxNoSrc(path string, args []string) (any, error) {
	return jadxRun(path, args, "-s")
}

func jadxMappings(path string, args []string) (any, error) {
	if len(args) == 0 || args[0] == "" {
		return nil, extRefuse(kindNeedsArg, "jadx_mappings needs a mappings file: usage: lrecon --ext-op jadx_mappings APK MAPPINGS")
	}
	return jadxRun(path, args[1:], "--mappings-path", args[0])
}

func jadxFallback(path string, args []string) (any, error) {
	return jadxRun(path, args, "-f")
}

func jadxSingleClassFull(path string, args []string) (any, error) {
	if len(args) == 0 || args[0] == "" {
		return nil, extRefuse(kindNeedsArg, "jadx_single_class_full needs a class name: usage: lrecon --ext-op jadx_single_class_full APK FQCN")
	}
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	a := []string{"--single-class", args[0], "--single-class-output", dir + "/single.txt", path}
	a = append(a, args[1:]...)
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "jadx", extJadxAlt, a...)
	if err != nil {
		return nil, err
	}
	combined := out
	if e := errOut; e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	return extOut{Tool: "jadx", Args: a, Output: combined, Lines: rtLines(combined)}, nil
}

func jadxPlugins(path string, args []string) (any, error) {
	// `jadx plugins` is a tool inventory: it names no file. A target here is a
	// caller mistake, not an operand to drop silently (addendum 507 asks for
	// not_applicable with a target).
	if path != "" {
		return nil, extRefuse(kindBadArg, "jadx_plugins takes no target: `jadx plugins` lists the installed plugins; usage: lrecon --ext-op jadx_plugins")
	}
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "jadx", extJadxAlt, append([]string{"plugins"}, args...)...)
	if err != nil {
		return nil, err
	}
	combined := out
	if e := errOut; e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	return extOut{Tool: "jadx", Args: append([]string{"plugins"}, args...), Output: combined, Lines: rtLines(combined)}, nil
}
