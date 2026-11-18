package main

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Item 189. `--extract` writes one member at a time; this item writes every
// script member of one archive at once, because a bundle is read as a set. The
// output directory is -o, never the archive's own directory, and path traversal
// is refused: an archive member named ../../etc/x must not leave the tree.

func init() {
	registerOp(op{
		name:  "export_web_scripts",
		route: "L",
		desc:  "write every script member of one asar or zip archive into -o DIR, keeping member paths; nothing is written beside the archive",
		needs: true,
		run:   opExportWebScripts,
	})
}

const maxExportScript = 8 << 20 // one script body; a bigger one is named, not written

type scriptExport struct {
	Archive string   `json:"archive"`
	Dir     string   `json:"dir"`
	Scripts []string `json:"scripts"`
	Written int      `json:"written"`
	Bytes   int64    `json:"bytes"`
	Skipped []string `json:"skipped"`
}

func opExportWebScripts(archive string) (any, error) {
	st, err := os.Stat(archive)
	if err != nil {
		return nil, err
	}
	if st.IsDir() {
		return nil, fmt.Errorf("%s is a directory: pass one asar or zip archive", archive)
	}
	// -o DIR names the tree root. The historical <archive>.scripts is kept only
	// for an in-process caller with no -o (the package test pins that path); the
	// CLI refuses such a call before it runs, so it never lands beside a target.
	out := scriptExport{Archive: archive, Dir: archive + ".scripts"}
	if strings.TrimSpace(opOutput) != "" {
		dir, err := exportDirDest("export_web_scripts", archive)
		if err != nil {
			return nil, err
		}
		out.Dir = dir
	}
	// The tree is created before the archive is read, so a target that is not an
	// archive at all would otherwise leave an empty -o directory behind. Only a
	// directory this call created is removed on failure.
	_, statErr := os.Stat(out.Dir)
	created := os.IsNotExist(statErr)
	if err := os.MkdirAll(out.Dir, 0o755); err != nil {
		if created {
			os.RemoveAll(out.Dir)
		}
		return nil, err
	}
	cleanup := func(err error) error {
		if err != nil && created {
			os.RemoveAll(out.Dir)
		}
		return err
	}
	f, err := os.Open(archive)
	if err != nil {
		return nil, cleanup(err)
	}
	root, base, asarErr := asarHeader(f, "export_web_scripts")
	f.Close()
	if asarErr == nil {
		err = exportAsarScripts(archive, out.Dir, base, root, &out)
	} else {
		err = exportZipScripts(archive, out.Dir, &out)
	}
	if err != nil {
		return nil, cleanup(err)
	}
	if out.Written == 0 {
		return nil, cleanup(fmt.Errorf("%s holds no script members; %d files were inspected and it is not a script bundle", archive, len(out.Skipped)))
	}
	return out, nil
}

func exportAsarScripts(archive, dir string, base int64, root *asarNode, out *scriptExport) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, m := range asarScriptMembers(root) {
		if !isScriptPath(m.rel) {
			continue
		}
		if m.node.Unpacked {
			out.Skipped = append(out.Skipped, m.rel+" (unpacked: body lives beside the archive)")
			continue
		}
		body, ok := readAsarSlice(f, base, m.node, maxExportScript)
		if !ok {
			out.Skipped = append(out.Skipped, m.rel+" (body unreadable)")
			continue
		}
		if err := writeExported(dir, m.rel, body); err != nil {
			return err
		}
		out.Scripts = append(out.Scripts, m.rel)
		out.Written++
		out.Bytes += int64(len(body))
	}
	return nil
}

func exportZipScripts(archive, dir string, out *scriptExport) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return fmt.Errorf("%s is neither a zip/apk/ipa nor an asar: %v", filepath.Base(archive), err)
	}
	defer zr.Close()
	for _, zf := range zr.File {
		if zf.FileInfo().IsDir() || !isScriptPath(zf.Name) {
			continue
		}
		if zf.Mode()&os.ModeSymlink != 0 {
			out.Skipped = append(out.Skipped, zf.Name+" (symlink)")
			continue
		}
		if zf.UncompressedSize64 > maxExportScript {
			out.Skipped = append(out.Skipped, fmt.Sprintf("%s (%d bytes over the %d MB cap)", zf.Name, zf.UncompressedSize64, maxExportScript>>20))
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			return fmt.Errorf("%s: open %s: %w", archive, zf.Name, err)
		}
		body, err := readScriptBody(rc, zf.UncompressedSize64)
		rc.Close()
		if err != nil {
			return fmt.Errorf("%s: read %s: %w", archive, zf.Name, err)
		}
		if err := writeExported(dir, zf.Name, body); err != nil {
			return err
		}
		out.Scripts = append(out.Scripts, zf.Name)
		out.Written++
		out.Bytes += int64(len(body))
	}
	return nil
}

// readScriptBody reads at most maxExportScript bytes. The archive header already
// states the size, so the buffer is sized once instead of grown by ReadAll; a
// header that lies only wastes capacity, it never truncates the read.
func readScriptBody(rc io.Reader, hint uint64) ([]byte, error) {
	keep := min(hint, maxExportScript)
	body := make([]byte, 0, int(keep))
	tmp := make([]byte, 32<<10)
	lr := io.LimitReader(rc, maxExportScript)
	for {
		n, err := lr.Read(tmp)
		body = append(body, tmp[:n]...)
		if err == io.EOF {
			return body, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// writeExported writes one member under dir, refusing any path that escapes it.
func writeExported(dir, rel string, body []byte) error {
	clean := path.Clean(strings.TrimPrefix(rel, "/"))
	// ".." as a path element escapes; a name that merely starts with two dots
	// (..foo.js) is an ordinary member inside the tree. path.Clean does not
	// treat `\` as a separator, so a backslash name would ride through clean
	// and escape on Windows.
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || filepath.IsAbs(clean) || strings.Contains(clean, `\`) {
		return fmt.Errorf("archive member %q is not a safe path: it escapes the export directory", rel)
	}
	dst := filepath.Join(dir, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, body, 0o644)
}
