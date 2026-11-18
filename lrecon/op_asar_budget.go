package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"
)

// Item B9. The three Electron-facing ops used to run with no budget of their
// own: a 20 MB asar was lexed as if it were source, and the caller's 20 s
// timeout was the only limit. A bundle with many edges made it worse, because
// the line number was counted from the start of the file for every match. The
// budget below is inside the op, and an asar is read through a bounded window
// instead of as one unbounded source file. On timeout the refusal carries
// stage:"asar", so the caller knows which target shape ran out of time.

const (
	// maxAsarWebText bounds how much of a container is handed to the JS lexer.
	// An asar is not source: its header and binary members are not JavaScript,
	// so lexing more than a window buys no answer and costs memory and time.
	// 4 MiB keeps the worst case (a binary-heavy window) well inside the
	// per-op budget even on a slow disk.
	maxAsarWebText = 4 << 20
	// opDeadlineDefault leaves headroom under the 20 s ceiling the item names.
	opDeadlineDefault = 15 * time.Second
	// opDeadlineEnv lets a test or a slow machine move the budget without a
	// rebuild. 0 (or less) means the deadline is already spent.
	opDeadlineEnv = "LRECON_OP_DEADLINE"
)

// opTimeoutError is the only error the deadline runner returns. Its text is
// exactly "timeout" so classify() lands on kindTimeout, and stage is carried
// separately so the JSON envelope can name where the time went.
type opTimeoutError struct {
	stage  string
	budget time.Duration
}

func (e *opTimeoutError) Error() string { return "timeout" }

func isOpTimeout(err error) bool {
	var t *opTimeoutError
	return errors.As(err, &t)
}

// opDeadline reads the per-op budget, defaulting to opDeadlineDefault.
func opDeadline() time.Duration {
	v := strings.TrimSpace(os.Getenv(opDeadlineEnv))
	if v == "" {
		return opDeadlineDefault
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return opDeadlineDefault
	}
	return d
}

// targetStage names the target shape a timeout happened on. Only an asar earns
// a name of its own; everything else shares "input".
func targetStage(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return "input"
	}
	defer f.Close()
	var head [20]byte
	n, _ := io.ReadFull(f, head[:])
	if n >= 20 && isAsar(head[:n]) {
		return "asar"
	}
	return "input"
}

// runOpDeadline runs one op body under its own budget. The body runs in a
// goroutine so a lexer or an extract walk cannot hold the caller past the
// deadline; on timeout the stage is recorded for the refusal envelope and the
// process exits before the abandoned goroutine can write anything the caller
// would read.
func runOpDeadline(path string, body func() (any, error)) (any, error) {
	return runOpDeadlineCtx(path, func(context.Context) (any, error) { return body() })
}

// runOpDeadlineCtx is runOpDeadline for a body that can observe cancellation:
// on timeout ctx is cancelled, so the abandoned goroutine winds down instead of
// writing on into a result nobody will read.
func runOpDeadlineCtx(path string, body func(context.Context) (any, error)) (any, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget := opDeadline()
	// The stage is only ever reported by the timeout refusal, so it is named when
	// the deadline fires rather than when the op starts: reading the head of the
	// target up front bought an open() and 20 bytes on every successful run, and
	// the body opens the same file anyway.
	if budget <= 0 {
		stage := targetStage(path)
		setRefuseStage(stage)
		return nil, &opTimeoutError{stage: stage, budget: budget}
	}
	type outcome struct {
		res any
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := body(ctx)
		done <- outcome{res, err}
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case o := <-done:
		return o.res, o.err
	case <-timer.C:
		cancel()
		stage := targetStage(path)
		setRefuseStage(stage)
		return nil, &opTimeoutError{stage: stage, budget: budget}
	}
}

// readWebTargetText is readWebText with one extra bound: an asar is a
// container, not a script, so only maxAsarWebText of it is opened for lexing
// and truncated says the analysis saw a window rather than the whole file.
func readWebTargetText(p string) (string, bool, error) {
	if targetStage(p) != "asar" {
		return readWebText(p)
	}
	f, err := os.Open(p)
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxAsarWebText+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > maxAsarWebText {
		return string(b[:maxAsarWebText]), true, nil
	}
	return string(b), false, nil
}
