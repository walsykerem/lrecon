package main

// procRow is one live process: the kernel's pid plus the command name it
// reports. The table is read in-process (sysctl on darwin, /proc on linux), so
// listing processes needs neither pgrep nor ps.
type procRow struct {
	PID  int    `json:"pid"`
	Comm string `json:"comm"`
}
