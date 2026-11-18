package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// readUISteps vets a scenario file before adb is consulted, so a binary target
// is a bad argument even on a host with no device.
func readUISteps(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return nil, fmt.Errorf("%s must be a text scenario file: NUL byte at offset %d", path, i)
	}
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("%s must be a text scenario file: invalid UTF-8", path)
	}
	var steps []string
	for _, l := range rtLines(string(b)) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		steps = append(steps, l)
	}
	return steps, nil
}

func init() {
	registerOp(op{
		name:  "capture_native_ui_scenario",
		route: "Y",
		desc:  "run `input` steps from a file, screencap, then uiautomator dump until the XML stops changing (optional target = steps file)",
		run:   captureNativeUIScenario,
	})
}

// rtUIDump is the observed hierarchy: sha and node count, not a claim of one.
type rtUIDump struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
	Nodes  int    `json:"nodes"`
}

type rtUIScenario struct {
	Steps      []string     `json:"steps"`
	Screenshot rtScreenshot `json:"screenshot"`
	UI         *rtUIDump    `json:"ui"` // nil = never idle in 3 dumps
	Cleanup    string       `json:"cleanup,omitempty"`
	Note       string       `json:"note,omitempty"`
}

// rtUIDelay is the pause §y y11 puts between an input and the next observation
// (and between dump attempts). A variable so the test does not sleep for real.
var rtUIDelay = 250 * time.Millisecond

// captureNativeUIScenario is §y y11: input → 250 ms → screencap → uiautomator
// dump, retried until two consecutive dumps hash the same. `--compressed` is
// not passed: it drops views that are not important for accessibility, which
// is exactly the bounds map we want.
func captureNativeUIScenario(stepsFile string) (any, error) {
	// Read and vet the scenario before touching adb: a binary or non-text file
	// is a bad argument on any host, and the failure must not quote its bytes.
	steps, err := readUISteps(stepsFile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb)
	if err != nil || sk != nil {
		return sk, err
	}
	for i, s := range steps {
		// `input text` takes one argv; splitting the line keeps the caller's
		// quoting intent out of our hands, which is the documented contract.
		if _, err := rtAdbShell(ctx, adb, serial, append([]string{"input"}, strings.Fields(s)...)...); err != nil {
			return nil, fmt.Errorf("step %d (%.40q): %w", i+1, s, err)
		}
		time.Sleep(rtUIDelay)
	}
	shot, _, err := rtScreencap(ctx, adb, serial)
	if err != nil {
		return nil, err
	}
	res := rtUIScenario{Steps: steps, Screenshot: shot}
	// The dump file is named from the steps, not from the clock: the same
	// scenario must land on the same device path, so a failure text (which
	// carries the path) repeats verbatim across runs.
	stepSum := sha256.Sum256([]byte(strings.Join(steps, "\n")))
	remote := fmt.Sprintf("/data/local/tmp/ui-%s.xml", hex.EncodeToString(stepSum[:4]))
	// A name that repeats across runs is what makes a failure text comparable,
	// and it is also what makes a stale read possible: a file an earlier run
	// left behind would be cat'ed and hashed as this run's hierarchy. Clear it
	// before the first dump (best effort: the dump overwrites it anyway, and a
	// missing adb shows up on the dump line below).
	_, _ = rtAdbShell(ctx, adb, serial, "rm", "-f", remote)
	var prev string
	for attempt := range 3 {
		if attempt > 0 {
			time.Sleep(rtUIDelay)
		}
		if _, err := rtAdbShell(ctx, adb, serial, "uiautomator", "dump", remote); err != nil {
			return nil, err
		}
		xml, err := rtAdbShell(ctx, adb, serial, "cat", remote)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256([]byte(xml))
		sha := hex.EncodeToString(sum[:])
		if prev != "" && sha == prev {
			res.UI = &rtUIDump{SHA256: sha, Bytes: len(xml), Nodes: strings.Count(xml, "<node")}
			res.Note = fmt.Sprintf("idle after %d dumps", attempt+1)
			break
		}
		prev = sha
	}
	// The path repeats across runs, so a failed removal leaves a file that the
	// next run would have to clear again. It is a note, not a reason to throw
	// the capture away (observe_native_ui keeps the same fact in Cleanup).
	if _, err := rtAdbShell(ctx, adb, serial, "rm", "-f", remote); err != nil {
		res.Cleanup = err.Error()
	}
	if res.UI == nil {
		// §y y11: idle timeout means the scenario is not thrown away, the UI
		// half is reported as absent.
		res.Note = "ui:null: the hierarchy never repeated within 3 dumps; scenario kept"
	}
	return res, nil
}
