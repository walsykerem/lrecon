package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// External-tool items for apktool (addendum 508-517).

func init() {
	registerExtOp(extOp{
		name:  "apktool_build",
		route: "Y",
		desc:  "apktool build: apktool b -o OUT.apk DIR",
		needs: true,
		run:   apktoolBuild,
	})
	registerExtOp(extOp{
		name:  "apktool_install_framework",
		route: "Y",
		desc:  "apktool install framework: apktool if APK",
		needs: true,
		run:   apktoolInstallFramework,
	})
	registerExtOp(extOp{
		name:  "apktool_clean_frameworks",
		route: "Y",
		desc:  "apktool clean frameworks: apktool cf",
		needs: false,
		run:   apktoolCleanFrameworks,
	})
	registerExtOp(extOp{
		name:  "apktool_list_frameworks",
		route: "Y",
		desc:  "apktool list frameworks: apktool lf",
		needs: false,
		run:   apktoolListFrameworks,
	})
	registerExtOp(extOp{
		name:  "apktool_publicize_resources",
		route: "Y",
		desc:  "apktool publicize resources: apktool pr FILE.arsc",
		needs: true,
		run:   apktoolPublicizeResources,
	})
	registerExtOp(extOp{
		name:  "apktool_only_manifest",
		route: "Y",
		desc:  "apktool only manifest: apktool d --only-manifest -o DIR APK",
		needs: true,
		run:   apktoolOnlyManifest,
	})
	registerExtOp(extOp{
		name:  "apktool_no_res",
		route: "Y",
		desc:  "apktool no res: apktool d -r -o DIR APK",
		needs: true,
		run:   apktoolNoRes,
	})
	registerExtOp(extOp{
		name:  "apktool_no_src",
		route: "Y",
		desc:  "apktool no src: apktool d -s -o DIR APK",
		needs: true,
		run:   apktoolNoSrc,
	})
	registerExtOp(extOp{
		name:  "apktool_frame_path",
		route: "Y",
		desc:  "apktool frame path: apktool d -p DIR -o OUT APK (extra arg = framework dir)",
		needs: true,
		run:   apktoolFramePath,
	})
	registerExtOp(extOp{
		name:  "apktool_lib",
		route: "Y",
		desc:  "apktool lib: apktool d -l PKG:FILE -o DIR APK (extra arg = PKG:FILE)",
		needs: true,
		run:   apktoolLib,
	})
}

func apktoolDecode(path string, args []string, dArgs ...string) (any, error) {
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	// apktool refuses an existing -o directory ("Destination directory already
	// exists"), so decode into a child that does not exist yet and let
	// apktool create it.
	full := []string{"d", "-o", filepath.Join(dir, "out")}
	full = append(full, dArgs...)
	full = append(full, path)
	full = append(full, args...)
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, full...)
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
	return extOut{Tool: "apktool", Args: full, Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolBuild(path string, args []string) (any, error) {
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	a := []string{"b", "-o", dir + "/out.apk", path}
	a = append(a, args...)
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, a...)
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
	return extOut{Tool: "apktool", Args: a, Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolInstallFramework(path string, args []string) (any, error) {
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, append([]string{"if", path}, args...)...)
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
	return extOut{Tool: "apktool", Args: append([]string{"if", path}, args...), Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolCleanFrameworks(path string, args []string) (any, error) {
	// `apktool cf` clears the framework cache and names no file. A target here
	// is a caller mistake, not an operand to drop silently (addendum 510 asks
	// for not_applicable with a target).
	if path != "" {
		return nil, extRefuse(kindBadArg, "apktool_clean_frameworks takes no target: `apktool cf` clears the installed framework cache; usage: lrecon --ext-op apktool_clean_frameworks")
	}
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, append([]string{"cf"}, args...)...)
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
	return extOut{Tool: "apktool", Args: append([]string{"cf"}, args...), Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolListFrameworks(path string, args []string) (any, error) {
	// Same rule as `cf`: `apktool lf` lists the framework cache and names no
	// file, so a target is refused instead of silently dropped (item 511).
	if path != "" {
		return nil, extRefuse(kindBadArg, "apktool_list_frameworks takes no target: `apktool lf` lists the installed framework cache; usage: lrecon --ext-op apktool_list_frameworks")
	}
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, append([]string{"lf"}, args...)...)
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
	return extOut{Tool: "apktool", Args: append([]string{"lf"}, args...), Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolPublicizeResources(path string, args []string) (any, error) {
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, append([]string{"pr", path}, args...)...)
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
	return extOut{Tool: "apktool", Args: append([]string{"pr", path}, args...), Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolOnlyManifest(path string, args []string) (any, error) {
	return apktoolDecode(path, args, "--only-manifest")
}

func apktoolNoRes(path string, args []string) (any, error) {
	return apktoolDecode(path, args, "-r")
}

func apktoolNoSrc(path string, args []string) (any, error) {
	return apktoolDecode(path, args, "-s")
}

// apktoolPrepareFramework seeds an empty framework directory with apktool if,
// so -p names a framework that exists instead of a dir apktool only warns
// about. A failed install is not fatal: decode runs anyway and its own error
// is the answer the caller needs.
func apktoolPrepareFramework(frame, path string) {
	entries, err := os.ReadDir(frame)
	if err != nil {
		return
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".apk") {
			return
		}
	}
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	if _, stderr, err := extTool(ctx, "apktool", extApktoolAlt, "if", "-p", frame, path); err != nil {
		// Not fatal: decode still runs and its own error is the answer. The
		// install failure is worth a line, though, or the decode error reads as
		// a broken framework with no hint that seeding it failed.
		log.Printf("apktool: framework seed %s failed: %v: %s", frame, err, strings.TrimSpace(rtFirstLine(stderr)))
	}
}

func apktoolFramePath(path string, args []string) (any, error) {
	if len(args) == 0 || args[0] == "" {
		return nil, extRefuse(kindNeedsArg, "apktool_frame_path needs a framework dir: usage: lrecon --ext-op apktool_frame_path APK FRAME_DIR")
	}
	if err := os.MkdirAll(args[0], 0o755); err != nil {
		return nil, err
	}
	apktoolPrepareFramework(args[0], path)
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	a := []string{"d", "-p", args[0], "-o", dir + "/out", path}
	a = append(a, args[1:]...)
	ctx, cancel := extCtx(extTimeoutY)
	defer cancel()
	out, errOut, err := extTool(ctx, "apktool", extApktoolAlt, a...)
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
	return extOut{Tool: "apktool", Args: a, Output: combined, Lines: rtLines(combined)}, nil
}

func apktoolLib(path string, args []string) (any, error) {
	if len(args) == 0 || args[0] == "" {
		return nil, extRefuse(kindNeedsArg, "apktool_lib needs PKG:FILE: usage: lrecon --ext-op apktool_lib APK PKG:FILE")
	}
	lib := args[0]
	return apktoolDecode(path, args[1:], "-l", lib)
}
