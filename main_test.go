package main

import (
	"flag"
	"io"
	"testing"
)

func TestVerbosityCountsRepeats(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want verbosity
	}{
		{"absent", nil, 0},
		{"once", []string{"-verbose"}, 1},
		{"twice", []string{"-verbose", "-verbose"}, 2},
		{"three times", []string{"-verbose", "-verbose", "-verbose"}, 3},
		{"explicitly off", []string{"-verbose", "-verbose=false"}, 0},
		{"off then on", []string{"-verbose=false", "-verbose"}, 1},
	}
	for _, tc := range cases {
		var level verbosity
		fs := flag.NewFlagSet("test", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		fs.Var(&level, "verbose", "verbose output")
		if err := fs.Parse(tc.args); err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if level != tc.want {
			t.Errorf("%s: level %d, want %d", tc.name, level, tc.want)
		}
	}
}

// A repeated flag must not swallow the next argument the way a
// non-boolean flag.Value would.
func TestVerbosityLeavesFollowingArgumentsAlone(t *testing.T) {
	var level verbosity
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Var(&level, "verbose", "verbose output")
	if err := fs.Parse([]string{"-verbose", "-verbose", "postmaster:secret@mail.example.org"}); err != nil {
		t.Fatal(err)
	}
	if level != 2 {
		t.Errorf("level %d, want 2", level)
	}
	if got := fs.Args(); len(got) != 1 || got[0] != "postmaster:secret@mail.example.org" {
		t.Errorf("positional arguments %v, want the connection string intact", got)
	}
}
