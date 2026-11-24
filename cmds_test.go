package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

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
