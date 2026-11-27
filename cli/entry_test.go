package cli

import (
	"io"
	"os"
	"strings"
	"testing"
)

// runMain runs Main with os.Stdout captured, so tests neither spam the
// terminal nor depend on what is printed where.
func runMain(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = w
	code := Main(args)
	os.Stdout = saved
	w.Close()
	out, _ := io.ReadAll(r)
	return code, string(out)
}

// TestMainExitCodes covers every path that needs no device, no network and
// no keys. They all return the same status in both builds, so `exit` (a
// stub without -tags userspace) is covered too.
func TestMainExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{name: "no args", args: nil, want: 2},
		{name: "unknown subcommand", args: []string{"nope"}, want: 2},
		{name: "subcommand help", args: []string{"up", "-h"}, want: 0},
		{name: "bad flag", args: []string{"up", "-nope"}, want: 2},
		{name: "offer without link", args: []string{"offer"}, want: 1},
		{name: "exit without tunnel address", args: []string{"exit"}, want: 1},
		{name: "nostr-keygen without file", args: []string{"nostr-keygen"}, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _ := runMain(t, tt.args...)
			if code != tt.want {
				t.Errorf("Main(%q) = %d, want %d", tt.args, code, tt.want)
			}
		})
	}
}

func TestMainVersion(t *testing.T) {
	Version = "test-version"
	defer func() { Version = "dev" }()

	for _, arg := range []string{"version", "-version", "--version"} {
		code, out := runMain(t, arg)
		if code != 0 || strings.TrimSpace(out) != "calltun test-version" {
			t.Errorf("%s: code %d, out %q", arg, code, out)
		}
	}
}
