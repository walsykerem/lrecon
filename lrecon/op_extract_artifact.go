package main

import (
	"context"
	"os"
)

// final: extract_artifact. Output goes to -o DIR, never beside the archive and
// never into the working directory; without -o the CLI refuses (needs_arg) and
// an in-process caller gets a fresh directory under the system temp dir.
// ExtractAll keeps its checkMember and maxExtract/maxExtractAll guards, so a
// hostile member cannot escape or fill the disk.
func init() {
	registerOp(op{
		name:  "extract_artifact",
		route: "L",
		needs: true,
		desc:  "extract an archive (zip/apk/aab/ipa/asar) into -o DIR, honoring the existing member-path checks and size caps; nothing is written beside the archive",
		run: func(path string) (any, error) {
			// B9: ExtractAll walks every member; a container with many members or
			// a slow disk must not hold the caller past the op's own budget.
			res, err := runOpDeadlineCtx(path, func(ctx context.Context) (any, error) {
				d, err := Probe(path)
				if err != nil {
					return nil, err
				}
				switch d.Kind {
				case "zip", "apk", "aab", "ipa", "asar":
				default:
					return skipf("%s: %s is not an archive lrecon can extract (zip/apk/aab/ipa/asar only)", path, d.Kind), nil
				}
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				dir, err := exportDirDest("extract_artifact", path)
				if err != nil {
					return nil, err
				}
				// A directory this call creates is ours to roll back; one the
				// caller already had is merged into, and its other contents are
				// not ours to delete. ExtractAll applies the same rule for its
				// own failures (extract.go).
				_, statErr := os.Stat(dir)
				created := os.IsNotExist(statErr)
				if err := ExtractAllCtx(ctx, path, dir, &d); err != nil {
					return nil, err
				}
				if ctx.Err() != nil {
					if created {
						os.RemoveAll(dir)
					}
					return nil, ctx.Err()
				}
				return struct {
					Kind          string   `json:"kind"`
					Output        string   `json:"output"`
					Notes         []string `json:"notes,omitempty"`
					Skipped       []Skip   `json:"skipped,omitempty"`
					CapBytes      int64    `json:"cap_bytes,omitempty"`
					TotalCapBytes int64    `json:"total_cap_bytes,omitempty"`
				}{d.Kind, dir, d.Notes, d.Skipped, extractLimit(), extractTotalLimit()}, nil
			})
			return res, err
		},
	})
}
