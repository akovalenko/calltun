package main

import "testing"

func TestBudgetSanity(t *testing.T) {
	// The whole point of fire-and-forget: a full-size inner frame fits in
	// one RTP packet and the outer datagram stays path-MTU safe.
	if maxFrame < 1280 {
		t.Fatalf("maxFrame %d below IPv6 minimum MTU 1280", maxFrame)
	}
	if maxFrame > 1400 {
		t.Fatalf("maxFrame %d too close to the path MTU", maxFrame)
	}
}
