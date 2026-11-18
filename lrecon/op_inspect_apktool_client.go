package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// 15. inspect_apktool_client — y2: apktool has no "client state", so the tool
// versions are reported as tool state and the only file-side trace is the
// version: line a decoded dir's apktool.yml carries.
func init() {
	registerOp(op{
		name:  "inspect_apktool_client",
		route: "Y",
		desc:  "apktool --version and the JDK version read from <java-home>/release (no java process), plus the version: line of a decoded dir's apktool.yml; target is the project dir (final.md y2, item 15)",
		needs: true,
		run:   opInspectApktoolClient,
	})
}

const jebdClientAlt = "install apktool and run `apktool --version`; the file-side trace is only the version: line of a decoded dir's apktool.yml (final.md y2)"

type jebdClient struct {
	Apktool      string   `json:"apktool"`
	Smali        string   `json:"smali,omitempty"`
	Java         string   `json:"java,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	DecompiledBy string   `json:"decompiled_by,omitempty"`
	ApktoolYML   string   `json:"apktool_yml,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// jebdApktoolHelp parses the help banner: the version line names smali and
// baksmali, and the subcommand lines are the client's real capabilities, so
// this is observed output, never a guess.
func jebdApktoolHelp(help string) (string, []string) {
	var smali string
	var caps []string
	for raw := range strings.SplitSeq(help, "\n") {
		line := strings.TrimSpace(raw)
		if smali == "" {
			if _, after, ok := strings.Cut(line, "with smali "); ok {
				rest := after
				if j := strings.Index(rest, " and "); j > 0 {
					smali = strings.TrimSpace(rest[:j])
				}
			}
		}
		for _, cmd := range []string{"d|decode", "b|build", "if|install-framework", "e|empty-framework-dir"} {
			if strings.HasPrefix(line, "apktool "+cmd) {
				caps = append(caps, strings.SplitN(cmd, "|", 2)[1])
			}
		}
	}
	return smali, caps
}

// jebdJavaVersion reads the JDK release file instead of running `java
// -version`: the version is a static line in <java-home>/release, so the probe
// costs a file read and no process. false means nothing was observed, never a
// guess. java itself is still required by apktool (it is a jar), which is why
// the answer names the interpreter path.
func jebdJavaVersion() (string, bool) {
	for _, home := range jebdJavaHomes() {
		b, err := os.ReadFile(filepath.Join(home, "release"))
		if err != nil {
			continue
		}
		for raw := range strings.SplitSeq(string(b), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(raw), "JAVA_VERSION="); ok {
				v = strings.Trim(v, `"`)
				if v != "" {
					return v + " (" + filepath.Join(home, "bin", "java") + ")", true
				}
			}
		}
	}
	return "", false
}

// jebdJavaHomes is every JDK home this host could be using: the dir behind
// `java` on PATH, JAVA_HOME, and the bundles the platform installers write.
// The macOS /usr/bin/java launcher is a stub that resolves to no JDK, and
// /opt/homebrew/bin/java is often a dangling symlink, so the release file —
// not the launcher path — is what decides.
func jebdJavaHomes() []string {
	var homes []string
	if path, err := exec.LookPath("java"); err == nil {
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			real = path
		}
		// <home>/bin/java → <home>.
		homes = append(homes, filepath.Dir(filepath.Dir(real)))
	}
	if h := os.Getenv("JAVA_HOME"); h != "" {
		homes = append(homes, h)
	}
	for _, pat := range []string{
		"/Library/Java/JavaVirtualMachines/*/Contents/Home",
		"/opt/homebrew/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		"/usr/local/opt/openjdk*/libexec/openjdk.jdk/Contents/Home",
		"/usr/lib/jvm/*",
	} {
		if m, _ := filepath.Glob(pat); len(m) > 0 {
			homes = append(homes, m...)
		}
	}
	return homes
}

func opInspectApktoolClient(target string) (any, error) {
	// needs=true: the target is part of the call, so a missing path is io — not a
	// success whose note reads like an existing decoded dir without apktool.yml.
	// One stat here also keeps the three tool spawns for a real target only.
	st, serr := os.Stat(target)
	if serr != nil {
		return nil, serr
	}
	out, sk, err := rt2Run("apktool", jebdClientAlt, "--version")
	if sk != nil || err != nil {
		return sk, err
	}
	c := jebdClient{Apktool: rt2FirstLine(out)}
	if c.Apktool == "" {
		c.Notes = append(c.Notes, "apktool --version printed nothing")
	} else {
		c.Apktool = strings.TrimPrefix(c.Apktool, "Apktool v")
	}
	if v, ok := jebdJavaVersion(); ok {
		c.Java = v
	} else {
		c.Notes = append(c.Notes, "java version not reported: java is not on PATH or has no JDK release file beside it")
	}
	if help, _, herr := rt2Run("apktool", jebdClientAlt, "--help"); herr == nil && strings.TrimSpace(help) != "" {
		if smali, caps := jebdApktoolHelp(help); smali != "" || len(caps) > 0 {
			c.Smali, c.Capabilities = smali, caps
		}
	} else {
		c.Notes = append(c.Notes, "apktool --help not reported: capability list unavailable")
	}
	yml := target
	if st.IsDir() {
		yml = filepath.Join(target, "apktool.yml")
	}
	b, err := os.ReadFile(yml)
	switch {
	case errors.Is(err, os.ErrNotExist):
		c.Notes = append(c.Notes, fmt.Sprintf("no apktool.yml at %s; decompiled_by needs a decoded project dir (final.md y2)", yml))
	case err != nil:
		return nil, err
	default:
		for raw := range strings.SplitSeq(string(b), "\n") {
			line := strings.TrimRight(raw, "\r")
			if line != strings.TrimSpace(line) { // indented keys belong to nested maps
				continue
			}
			v, ok := strings.CutPrefix(line, "version:")
			if !ok {
				continue
			}
			if v = strings.Trim(strings.TrimSpace(v), `"'`); v != "" {
				c.DecompiledBy, c.ApktoolYML = v, yml
				break
			}
		}
		if c.DecompiledBy == "" {
			c.Notes = append(c.Notes, "no top-level version: line in "+yml)
		}
	}
	return c, nil
}
