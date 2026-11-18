package main

// External-tool items for Ghidra headless (addendum 518-530, route G). Each
// runs analyzeHeadless importing the target; a missing Ghidra is no_engine
// before any JVM starts, and the 50 s G deadline bounds the import.

import (
	"os"
	"path/filepath"
	"strings"
)

func init() {
	registerExtOp(extOp{
		name:  "ghidra_prescript",
		route: "G",
		desc:  "ghidra prescript: analyzeHeadless -preScript SCRIPT",
		needs: true,
		run:   ghidraPrescript,
	})
	registerExtOp(extOp{
		name:  "ghidra_processor",
		route: "G",
		desc:  "ghidra processor: analyzeHeadless -processor LANG (extra arg = language)",
		needs: true,
		run:   ghidraProcessor,
	})
	registerExtOp(extOp{
		name:  "ghidra_cspec",
		route: "G",
		desc:  "ghidra cspec: analyzeHeadless -cspec COMPILER (extra arg = compiler)",
		needs: true,
		run:   ghidraCspec,
	})
	registerExtOp(extOp{
		name:  "ghidra_loader",
		route: "G",
		desc:  "ghidra loader: analyzeHeadless -loader NAME [-loader-arg VAL] (extra arg = loader name)",
		needs: true,
		run:   ghidraLoader,
	})
	registerExtOp(extOp{
		name:  "ghidra_analysis_timeout",
		route: "G",
		desc:  "ghidra analysis timeout: analyzeHeadless -analysisTimeoutPerFile SEC (extra arg = seconds)",
		needs: true,
		run:   ghidraAnalysisTimeout,
	})
	registerExtOp(extOp{
		name:  "ghidra_connect",
		route: "G",
		desc:  "ghidra connect: analyzeHeadless -connect [-p]",
		needs: true,
		run:   ghidraConnect,
	})
	registerExtOp(extOp{
		name:  "ghidra_commit",
		route: "G",
		desc:  "ghidra commit: analyzeHeadless -commit \"msg\" (extra arg = message)",
		needs: true,
		run:   ghidraCommit,
	})
	registerExtOp(extOp{
		name:  "ghidra_library_paths",
		route: "G",
		desc:  "ghidra library paths: analyzeHeadless -librarySearchPaths PATH (extra arg = path)",
		needs: true,
		run:   ghidraLibraryPaths,
	})
	registerExtOp(extOp{
		name:  "ghidra_keystore",
		route: "G",
		desc:  "ghidra keystore: analyzeHeadless -keystore PATH (extra arg = path)",
		needs: true,
		run:   ghidraKeystore,
	})
	registerExtOp(extOp{
		name:  "ghidra_overwrite",
		route: "G",
		desc:  "ghidra overwrite: analyzeHeadless -overwrite",
		needs: true,
		run:   ghidraOverwrite,
	})
	registerExtOp(extOp{
		name:  "ghidra_mirror",
		route: "G",
		desc:  "ghidra mirror: analyzeHeadless -mirror",
		needs: true,
		run:   ghidraMirror,
	})
	registerExtOp(extOp{
		name:  "ghidra_readonly",
		route: "G",
		desc:  "ghidra readonly: analyzeHeadless -readOnly",
		needs: true,
		run:   ghidraReadonly,
	})
	registerExtOp(extOp{
		name:  "ghidra_noanalysis",
		route: "G",
		desc:  "ghidra noanalysis: analyzeHeadless -noanalysis",
		needs: true,
		run:   ghidraNoanalysis,
	})
}

// extGhidraImport runs analyzeHeadless with the minimal import of the target:
// project "<dir>/project" named "lrecon", importing the target file. The
// item's own flags are inserted before -import. No postScript is run: the
// import is the honest work these items name.
func extGhidraImport(path string, args []string, ghidraFlags ...string) (any, error) {
	dir, cleanup, err := extDir()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	project := filepath.Join(dir, "project")
	// analyzeHeadless aborts with "Directory not found" when the project
	// location does not exist, so create it before the run.
	if err := os.MkdirAll(project, 0o755); err != nil {
		return nil, err
	}
	a := []string{project, "lrecon"}
	a = append(a, ghidraFlags...)
	a = append(a, "-import", path)
	a = append(a, args...)
	// The plan's flat 50 s is a floor, not the whole budget. The same 1.6 MB
	// fixture imports in 27-35 s idle and crossed 50.1 s while a second Ghidra
	// import shared the CPU, so the answer depended on machine load. Every
	// other G item already sizes its import (ghidraTimeoutForPath); follow that
	// and let LRECON_GHIDRA_TIMEOUT raise it further on a busy host.
	budget := max(ghidraTimeoutForPath(path), extTimeoutG)
	ctx, cancel := extCtx(budget)
	defer cancel()
	out, errOut, err := extGhidra(ctx, a...)
	combined := out
	if e := errOut; e != "" {
		if combined != "" {
			combined += "\n"
		}
		combined += e
	}
	if err != nil {
		if line := ghidraScriptError(combined); line != "" {
			return nil, extRefuse(kindInternal, "%s", line)
		}
		return nil, err
	}
	return extOut{Tool: "analyzeHeadless", Args: a, Output: combined, Lines: rtLines(combined)}, nil
}

// ghidraScriptError returns the log line naming a pre-script Ghidra could not run.
func ghidraScriptError(log string) string {
	for _, line := range rtLines(log) {
		trim := strings.TrimSpace(line)
		if strings.Contains(trim, "REPORT SCRIPT ERROR") {
			return trim
		}
	}
	return ""
}

// firstArg returns the first extra arg, refusing when none was given.
func firstArg(op, usage string, args []string) (string, error) {
	if len(args) == 0 || args[0] == "" {
		return "", extRefuse(kindNeedsArg, "%s needs an argument: usage: %s", op, usage)
	}
	return args[0], nil
}

// hasFlag reports whether args contains flag (exact "-name" or "-name=value").
func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag || (len(a) > len(flag) && a[:len(flag)+1] == flag+"=") {
			return true
		}
	}
	return false
}

func ghidraPrescript(path string, args []string) (any, error) {
	script, err := firstArg("ghidra_prescript", "lrecon --ext-op ghidra_prescript FILE SCRIPT", args)
	if err != nil {
		return nil, err
	}
	res, err := extGhidraImport(path, args[1:], "-preScript", script)
	if err != nil {
		return nil, err
	}
	// A script Ghidra could not load can still exit 0; the log is the only signal.
	if out, ok := res.(extOut); ok {
		if line := ghidraScriptError(out.Output); line != "" {
			return nil, extRefuse(kindInternal, "%s", line)
		}
	}
	return res, nil
}

func ghidraProcessor(path string, args []string) (any, error) {
	lang, err := firstArg("ghidra_processor", "lrecon --ext-op ghidra_processor FILE LANG", args)
	if err != nil {
		return nil, err
	}
	return extGhidraImport(path, args[1:], "-processor", lang)
}

func ghidraCspec(path string, args []string) (any, error) {
	comp, err := firstArg("ghidra_cspec", "lrecon --ext-op ghidra_cspec FILE COMPILER", args)
	if err != nil {
		return nil, err
	}
	// Ghidra rejects "-cspec" without "-processor" ("Compiler spec specified
	// without specifying language"), so default the processor to the target's
	// own architecture when the caller only named a compiler.
	flags := []string{"-cspec", comp}
	if !hasFlag(args, "-processor") {
		flags = append([]string{"-processor", "AARCH64:LE:64:v8A"}, flags...)
	}
	return extGhidraImport(path, args[1:], flags...)
}

func ghidraLoader(path string, args []string) (any, error) {
	loader, err := firstArg("ghidra_loader", "lrecon --ext-op ghidra_loader FILE LOADER", args)
	if err != nil {
		return nil, err
	}
	return extGhidraImport(path, args[1:], "-loader", loader)
}

func ghidraAnalysisTimeout(path string, args []string) (any, error) {
	sec, err := firstArg("ghidra_analysis_timeout", "lrecon --ext-op ghidra_analysis_timeout FILE SEC", args)
	if err != nil {
		return nil, err
	}
	return extGhidraImport(path, args[1:], "-analysisTimeoutPerFile", sec)
}

func ghidraConnect(path string, args []string) (any, error) {
	return extGhidraImport(path, args, "-connect")
}

func ghidraCommit(path string, args []string) (any, error) {
	msg, err := firstArg("ghidra_commit", "lrecon --ext-op ghidra_commit FILE MSG", args)
	if err != nil {
		return nil, err
	}
	return extGhidraImport(path, args[1:], "-commit", msg)
}

func ghidraLibraryPaths(path string, args []string) (any, error) {
	p, err := firstArg("ghidra_library_paths", "lrecon --ext-op ghidra_library_paths FILE PATH", args)
	if err != nil {
		return nil, err
	}
	return extGhidraImport(path, args[1:], "-librarySearchPaths", p)
}

func ghidraKeystore(path string, args []string) (any, error) {
	p, err := firstArg("ghidra_keystore", "lrecon --ext-op ghidra_keystore FILE PATH", args)
	if err != nil {
		return nil, err
	}
	// Ghidra rejects a directory as "-keystore" ("is not valid keystore file"),
	// so refuse a directory up front instead of burning a JVM to get there.
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return nil, extRefuse(kindNeedsArg, "ghidra_keystore needs a keystore file, not a directory: %s", p)
	}
	return extGhidraImport(path, args[1:], "-keystore", p)
}

func ghidraOverwrite(path string, args []string) (any, error) {
	return extGhidraImport(path, args, "-overwrite")
}

func ghidraMirror(path string, args []string) (any, error) {
	return extGhidraImport(path, args, "-mirror")
}

func ghidraReadonly(path string, args []string) (any, error) {
	return extGhidraImport(path, args, "-readOnly")
}

func ghidraNoanalysis(path string, args []string) (any, error) {
	return extGhidraImport(path, args, "-noanalysis")
}
