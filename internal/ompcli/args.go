package ompcli

import (
	"errors"
	"flag"
	"io"
	"strings"
	"time"
)

// global holds the flags every command accepts.
type global struct {
	json    bool
	url     string
	timeout time.Duration
}

// globalValueFlags are the global flags that take a value, so the top-level
// scan knows `--portal X` has one.
var globalValueFlags = map[string]bool{"portal": true, "timeout": true}

func newFlagSet(name string, g *global) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&g.json, "json", false, "print JSON instead of text")
	fs.StringVar(&g.url, "portal", "", "the portal's URL (default: OMP_URL, then the config file)")
	fs.DurationVar(&g.timeout, "timeout", 60*time.Second, "time limit for the whole command")
	return fs
}

var errHelp = errors.New("help")

// parseArgs parses flags and positional arguments in any order
// (`omp connect support --client claude` and `omp connect --client claude
// support` both work). "--" ends the flags.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, errHelp
			}
			return nil, usageErr("%s", strings.TrimPrefix(err.Error(), "flag provided but not defined: -")+flagHint(err))
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func flagHint(err error) string {
	if strings.HasPrefix(err.Error(), "flag provided but not defined") {
		return " is not a flag of this command (see --help)"
	}
	return ""
}

// splitGlobals moves the global flags that come before the command name
// behind it: `omp --json servers list` is `omp servers list --json`.
func splitGlobals(args []string) (cmd string, rest []string) {
	var lead []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "-") || a == "-" {
			return a, append(append([]string{}, args[i+1:]...), lead...)
		}
		name := strings.TrimLeft(a, "-")
		lead = append(lead, a)
		if !strings.Contains(name, "=") && globalValueFlags[name] && i+1 < len(args) {
			i++
			lead = append(lead, args[i])
		}
	}
	return "", lead
}

func needArgs(pos []string, n int, usage string) error {
	if len(pos) != n {
		return usageErr("usage: %s", usage)
	}
	return nil
}
