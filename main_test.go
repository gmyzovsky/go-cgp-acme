package main

import (
	"context"
	"flag"
	"io"
	"testing"
)

// Cleanup runs on a context of its own: go-cgp-api sends nothing on a
// context that is already done, so a challenge file deleted through the
// cancelled ctx would simply stay on the server.
func TestDetachedOutlivesItsParent(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	ctx, stop := detached(parent)
	defer stop()

	cancel()
	select {
	case <-ctx.Done():
		t.Fatal("detached context ended with its parent")
	default:
	}
	if err := ctx.Err(); err != nil {
		t.Errorf("Err = %v, want nil", err)
	}
	if _, ok := ctx.Deadline(); !ok {
		t.Error("detached context has no deadline; cleanup could hang forever")
	}
}

func TestIsLoopbackHost(t *testing.T) {
	cases := map[string]bool{
		"localhost":        true,
		"LOCALHOST":        true,
		"127.0.0.1":        true,
		"127.1.2.3":        true,
		"::1":              true,
		"10.0.0.1":         false,
		"mail.example.org": false,
		"":                 false,
	}
	for host, want := range cases {
		if got := isLoopbackHost(host); got != want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", host, got, want)
		}
	}
}

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
