package main

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// excludedIfaces: the served device is excluded last, and exit — which has
// no device — must not grow an empty-name entry.
func TestExcludedIfaces(t *testing.T) {
	for _, tc := range []struct {
		flagVal, dev string
		want         []string
	}{
		{"eth9", "tun7", []string{"eth9", "tun7"}},
		{"eth9", "", []string{"eth9"}},
		{"", "", nil},
	} {
		if got := excludedIfaces(tc.flagVal, tc.dev); !slices.Equal(got, tc.want) {
			t.Errorf("excludedIfaces(%q, %q) = %q, want %q", tc.flagVal, tc.dev, got, tc.want)
		}
	}
}

// The transport selection shared by up and exit: --nostr is xor with ssh,
// and one of them is mandatory.
func TestCheckSignalingFlags(t *testing.T) {
	for _, tc := range []struct {
		name        string
		peer, alias string
		extra       []string
		wantErr     string
	}{
		{"ssh alias", "", "host", nil, ""},
		{"ssh in trailing args", "", "", []string{"-p", "2222", "host"}, ""},
		{"nostr", "npub1peer", "", nil, ""},
		{"xor", "npub1peer", "host", nil, "mutually exclusive"},
		{"none", "", "", nil, "is required"},
	} {
		err := checkSignalingFlags(&nostrFlags{peer: tc.peer}, tc.alias, tc.extra)
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("%s: got %v, want an error mentioning %q", tc.name, err, tc.wantErr)
		}
	}
}

// openSignaling with ssh needs --link (it names the peer's offer socket):
// the refusal must come before any ssh child is spawned.
func TestOpenSignalingNeedsLinkForSSH(t *testing.T) {
	_, teardown, err := openSignaling(&commonFlags{}, &nostrFlags{}, "alias", nil, "calltun")
	if err == nil || !strings.Contains(err.Error(), "--link") {
		t.Fatalf("want a --link refusal, got %v", err)
	}
	if teardown != nil {
		t.Fatal("nothing to tear down on refusal")
	}
}

// TestRunForever: failures rerun fn, success and external stop end it.
func TestRunForever(t *testing.T) {
	// Fail twice, then succeed.
	calls := 0
	err := runForever(context.Background(), func() error {
		calls++
		if calls < 3 {
			return errors.New("boom")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("runForever: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 calls, got %d", calls)
	}

	// Clean nil passes through immediately.
	calls = 0
	_ = runForever(context.Background(), func() error { calls++; return nil })
	if calls != 1 {
		t.Fatalf("clean run should not restart, got %d calls", calls)
	}

	// Cancelled ctx: the in-flight failure exits as a clean stop, and the
	// pause does not delay it.
	ctx, cancel := context.WithCancel(context.Background())
	calls = 0
	start := time.Now()
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	if err := runForever(ctx, func() error { calls++; return errors.New("boom") }); err != nil {
		t.Fatalf("external stop must be a clean exit, got %v", err)
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Fatalf("cancel during pause not honored promptly: %v", d)
	}
}
