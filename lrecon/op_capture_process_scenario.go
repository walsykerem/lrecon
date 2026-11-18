package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerOp(op{
		name:  "capture_process_scenario",
		route: "Y",
		desc:  "sample one live pid for 1 s with sample(1) and parse the Call graph (target = pid; darwin only)",
		needs: true,
		run:   captureProcessScenario,
	})
}

type rtFrame struct {
	Sym   string `json:"sym"`
	Lib   string `json:"lib"`
	Addr  string `json:"addr,omitempty"`
	Count int    `json:"count"`
}

type rtThread struct {
	ID     string    `json:"id"`
	Frames []rtFrame `json:"frames"`
}

type rtProcessCapture struct {
	PID       int        `json:"pid"`
	Path      string     `json:"path,omitempty"`
	Timestamp string     `json:"ts"`
	Threads   []rtThread `json:"threads"`
}

// sample(1) prints `      176 start  (in dyld) + 7184  [0x1f0d...]` inside a
// `Thread_<id>` block under `Call graph:`.
var (
	rtSampleThread = regexp.MustCompile(`^(?:\d+\s+)?Thread_(\S+)`)
	// A busy process makes sample(1) aggregate: marker runs stack up ("+ !"),
	// the offset becomes a list ("+ 28,68,...") and the bracket holds every
	// address of the aggregate ("[0x104dcc188,0x104dcc1b0,...]"). Requiring one
	// plain digit offset and one address silently dropped exactly those lines,
	// so the busier the target the fewer frames the capture kept.
	rtSampleFrame = regexp.MustCompile(`^\s*(?:[+!:|]+\s*)*(\d+)\s+(.+?)\s+\(in ([^)]*)\)(?:\s*\+\s*([0-9a-fA-Fx,.…\s]+?))?\s*(?:\[(0x[0-9a-fA-F]+)[^\]]*\])?\s*$`)
	rtSampleProc  = regexp.MustCompile(`^Process:\s+(.+?)\s+\[(\d+)\]`)
	rtSamplePath  = regexp.MustCompile(`^Path:\s+(.+?)\s*$`)
)

// captureProcessScenario is §y y12. sample(1) needs no root: its own signature
// carries com.apple.system-task-ports.read, and there is no ptrace. The linux
// branch was dropped from §y, so a non-darwin host skips rather than pretends.
func captureProcessScenario(target string) (any, error) {
	pid, err := strconv.Atoi(strings.TrimSpace(target))
	if err != nil || pid <= 0 {
		return nil, fmt.Errorf("target %q is not a pid", target)
	}
	// Signal 0 asks "does this pid exist" without touching it; sampling a dead
	// pid would produce an empty capture that reads like a quiet process.
	if !pidAlive(pid) {
		// No alternative tool can sample a process that ended, so naming
		// one (rtSampleAlt) would send the caller to the wrong place.
		return skipf("no live process with pid %d: nothing to sample", pid), nil
	}
	sample, sk := rtTool("sample", rtSampleAlt)
	if sk != nil {
		return sk, nil
	}
	ctx, cancel := rtCtx()
	defer cancel()
	tmp, err := os.CreateTemp("", "lrecon-sample-*.txt")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	// The file exists the moment CreateTemp returns, so the removal must not
	// wait on a successful Close: a failed Close would otherwise leave the
	// sample output (a full stack dump of a live process) in the temp dir.
	defer os.Remove(tmpName)
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if _, err := rtRun(ctx, sample, strconv.Itoa(pid), "1", "1", "-mayDie", "-file", tmpName); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(tmpName)
	if err != nil {
		return nil, err
	}
	caps, err := rtParseSample(string(b))
	if err != nil {
		return nil, err
	}
	caps.PID = pid
	caps.Timestamp = time.Now().UTC().Format(time.RFC3339)
	return caps, nil
}

func rtParseSample(out string) (rtProcessCapture, error) {
	var caps rtProcessCapture
	inGraph := false
	var cur *rtThread
	for _, l := range rtLines(out) {
		// sample(1) prints the short name on Process: and the executable path
		// on Path:; prefer the path and keep the name as the fallback.
		if m := rtSamplePath.FindStringSubmatch(l); m != nil {
			caps.Path = m[1]
			continue
		}
		if m := rtSampleProc.FindStringSubmatch(l); m != nil {
			if caps.Path == "" {
				caps.Path = m[1]
			}
			continue
		}
		if strings.HasPrefix(l, "Call graph:") {
			inGraph = true
			continue
		}
		if !inGraph {
			continue
		}
		if m := rtSampleThread.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			caps.Threads = append(caps.Threads, rtThread{ID: m[1]})
			cur = &caps.Threads[len(caps.Threads)-1]
			continue
		}
		m := rtSampleFrame.FindStringSubmatch(l)
		if m == nil || cur == nil {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return caps, fmt.Errorf("sample frame count %q: %w", m[1], err)
		}
		cur.Frames = append(cur.Frames, rtFrame{Sym: m[2], Lib: m[3], Addr: m[5], Count: n})
	}
	if !inGraph {
		return caps, errors.New("sample output has no Call graph: section (unsupported format?)")
	}
	return caps, nil
}
