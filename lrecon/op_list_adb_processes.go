package main

import (
	"fmt"
	"strconv"
	"strings"
)

func init() {
	registerOp(op{
		name:  "list_adb_processes",
		route: "Y",
		desc:  "process table from `ps -A -o PID,USER,NAME,ARGS` on the attached device, falling back to plain `ps`",
		run:   listADBProcesses,
	})
}

type rtADBProcess struct {
	PID  string `json:"pid"`
	User string `json:"user"`
	Name string `json:"name"`
	Args string `json:"args,omitempty"`
}

type rtADBProcesses struct {
	Columns []string       `json:"columns"`
	Rows    []rtADBProcess `json:"rows"`
	Count   int            `json:"count"`
	Command string         `json:"command"`
}

// adbPSLayout names the columns one `ps` table turned out to have. -1 means
// the column is absent, so a projection never reads a field the layout does
// not carry.
type adbPSLayout struct {
	Columns []string
	pid     int
	user    int
	name    int
	args    int
}

// adbPSRow is one process row projected onto an adbPSLayout.
type adbPSRow struct {
	PID  string
	User string
	Name string
	Args string
}

// adbPSHeader recognises an -o header (`PID USER NAME ARGS`). PID and a name
// column must both be present; a line carrying only one of them is data, not a
// header, and is offered to adbPSInfer instead.
func adbPSHeader(f []string) (adbPSLayout, bool) {
	l := adbPSLayout{pid: -1, user: -1, name: -1, args: -1}
	for i, c := range f {
		switch strings.ToUpper(c) {
		case "PID":
			l.pid = i
		case "USER":
			l.user = i
		case "NAME", "CMD":
			l.name = i
		case "ARGS", "CMDLINE":
			if l.args < 0 {
				l.args = i
			}
		}
	}
	if l.pid < 0 || l.name < 0 {
		return adbPSLayout{}, false
	}
	l.Columns = f
	return l, true
}

// adbPSInfer reads the layout from the first data row of a headerless table.
// `ps -A -o …` on a build that drops the header still prints a numeric pid
// first; the legacy fixed-column table prints `USER PID PPID … NAME`, so the
// second field is the pid and the last one the name. Reading the legacy table
// as if it were the -o table turns the user into a pid, which is why the shape
// is decided once, here, and named in Columns.
func adbPSInfer(f []string) (adbPSLayout, bool) {
	if _, err := strconv.Atoi(f[0]); err == nil {
		l := adbPSLayout{pid: 0, user: -1, name: 1, args: -1, Columns: []string{"PID", "NAME"}}
		if len(f) >= 3 {
			l.user, l.name = 1, 2
			l.Columns = []string{"PID", "USER", "NAME"}
		}
		if len(f) >= 4 {
			l.args = 3
			l.Columns = []string{"PID", "USER", "NAME", "ARGS"}
		}
		return l, true
	}
	if len(f) >= 3 {
		if _, err := strconv.Atoi(f[1]); err == nil {
			cols := []string{"USER", "PID", "PPID", "NAME"}
			if len(f) == 9 {
				cols = []string{"USER", "PID", "PPID", "VSZ", "RSS", "WCHAN", "ADDR", "S", "NAME"}
			}
			return adbPSLayout{Columns: cols, pid: 1, user: 0, name: len(f) - 1, args: -1}, true
		}
	}
	return adbPSLayout{}, false
}

// adbPSTable parses one device `ps` table once and returns both the layout and
// the rows, so list_adb_processes (pid/user/name/args) and list_frida_processes
// (pid/name) cannot disagree about what a row means.
func adbPSTable(out string) (adbPSLayout, []adbPSRow) {
	var layout adbPSLayout
	var rows []adbPSRow
	decided := false
	for _, line := range rtLines(out) {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if !decided {
			if l, ok := adbPSHeader(f); ok {
				layout, decided = l, true
				continue
			}
			l, ok := adbPSInfer(f)
			if !ok {
				// The first line is neither a header nor a row: the output is
				// not a process table and nothing after it is read as one.
				continue
			}
			layout, decided = l, true
		}
		if layout.pid < 0 || layout.name < 0 || len(f) <= layout.pid || len(f) <= layout.name {
			continue
		}
		r := adbPSRow{PID: f[layout.pid], Name: f[layout.name]}
		if layout.user >= 0 && len(f) > layout.user {
			r.User = f[layout.user]
		}
		if layout.args >= 0 && len(f) > layout.args {
			r.Args = strings.Join(f[layout.args:], " ")
		} else {
			r.Name = strings.Join(f[layout.name:], " ")
		}
		rows = append(rows, r)
	}
	return layout, rows
}

// listADBProcesses is §y y32: toybox `ps -A -o …` first, plain `ps` only when
// that form is refused (older toolboxes).
func listADBProcesses(string) (any, error) {
	ctx, cancel := rtCtx()
	defer cancel()
	adb, sk := rtAdb()
	if sk != nil {
		return sk, nil
	}
	serial, sk, err := rtAdbSerial(ctx, adb, "ps -A -o PID,USER,NAME,ARGS")
	if err != nil || sk != nil {
		return sk, err
	}
	out, err := rtAdbShell(ctx, adb, serial, "ps", "-A", "-o", "PID,USER,NAME,ARGS")
	cmd := "ps -A -o PID,USER,NAME,ARGS"
	if err != nil || !strings.Contains(out, "PID") {
		fallback, ferr := rtAdbShell(ctx, adb, serial, "ps")
		if ferr != nil {
			return nil, fmt.Errorf("%v; fallback ps also failed: %w", err, ferr)
		}
		out, err = fallback, nil
		cmd = "ps"
	}
	layout, parsed := adbPSTable(out)
	res := rtADBProcesses{Command: cmd, Columns: layout.Columns}
	for _, r := range parsed {
		res.Rows = append(res.Rows, rtADBProcess{PID: r.PID, User: r.User, Name: r.Name, Args: r.Args})
	}
	res.Count = len(res.Rows)
	if res.Count == 0 {
		return nil, fmt.Errorf("%s printed no process rows: %s", cmd, rtFirstLine(out))
	}
	return res, nil
}
