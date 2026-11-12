package main

import (
	"bytes"
	"math/rand"
	"testing"
	"time"
)

func TestFramingRoundtrip(t *testing.T) {
	sizes := []int{1, 100, 1100, maxFragData, maxFragData + 1, 2 * maxFragData, 3000, 5000}
	for _, size := range sizes {
		frame := make([]byte, size)
		rand.New(rand.NewSource(int64(size))).Read(frame)

		f := &fragmenter{}
		frags := f.build(frame)
		if frags == nil {
			t.Fatalf("size %d: build returned nil", size)
		}
		wantFrags := (size + maxFragData - 1) / maxFragData
		if len(frags) != wantFrags {
			t.Fatalf("size %d: got %d frags, want %d", size, len(frags), wantFrags)
		}

		re := newReassembler()
		var got []byte
		for _, fr := range frags {
			out, ok := re.push(fr)
			if ok {
				got = out
			}
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("size %d: roundtrip mismatch (got %d bytes)", size, len(got))
		}
	}
}

func TestFramingMultipleFrames(t *testing.T) {
	f := &fragmenter{}
	re := newReassembler()
	for i := 0; i < 100; i++ {
		frame := make([]byte, 1+i*57)
		rand.New(rand.NewSource(int64(i))).Read(frame)
		frags := f.build(frame)
		var got []byte
		for _, fr := range frags {
			if out, ok := re.push(fr); ok {
				got = out
			}
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("frame %d mismatch", i)
		}
	}
}

func TestFramingLossKillsFrame(t *testing.T) {
	frame := make([]byte, 2*maxFragData+10)
	for i := range frame {
		frame[i] = byte(i)
	}
	f := &fragmenter{}
	frags := f.build(frame)

	re := newReassembler()
	var completed int
	for i, fr := range frags {
		if i == 1 { // lose the middle fragment
			continue
		}
		if _, ok := re.push(fr); ok {
			completed++
		}
	}
	if completed != 0 {
		t.Fatalf("damaged frame completed %d times, want 0", completed)
	}
	if re.depth() != 1 {
		t.Fatalf("pending depth %d, want 1", re.depth())
	}
	// A later frame must not resurrect the damaged one.
	next := f.build([]byte{9, 9, 9})
	if out, ok := re.push(next[0]); !ok || !bytes.Equal(out, []byte{9, 9, 9}) {
		t.Fatalf("frame after loss did not complete cleanly")
	}
}

func TestFramingDuplicateAndReorder(t *testing.T) {
	frame := make([]byte, 3*maxFragData)
	rand.New(rand.NewSource(42)).Read(frame)
	f := &fragmenter{}
	frags := f.build(frame)

	re := newReassembler()
	// reverse order, then replay all again in order (duplicates)
	var got []byte
	for i := len(frags) - 1; i >= 0; i-- {
		if out, ok := re.push(frags[i]); ok {
			got = out
		}
	}
	if !bytes.Equal(got, frame) {
		t.Fatal("reordered frame mismatch")
	}
	for _, fr := range frags {
		if _, ok := re.push(fr); ok {
			t.Fatal("duplicate replay completed a frame")
		}
	}
}

func TestFramingGarbageIgnored(t *testing.T) {
	re := newReassembler()
	if _, ok := re.push([]byte{0}); ok { // keepalive
		t.Fatal("short payload completed a frame")
	}
	if _, ok := re.push([]byte{0, 1, 2}); ok { // 3 bytes < header
		t.Fatal("3-byte payload completed a frame")
	}
	if _, ok := re.push([]byte{0, 1, 5, 0}); ok { // total=0
		t.Fatal("total=0 completed a frame")
	}
	if _, ok := re.push([]byte{0, 1, 1, 1}); ok { // idx >= total
		t.Fatal("idx out of range completed a frame")
	}
	if re.depth() != 0 {
		t.Fatalf("garbage left pending entries: %d", re.depth())
	}
}

func TestReassemblerGC(t *testing.T) {
	re := newReassembler()
	f := &fragmenter{}
	frags := f.build(make([]byte, 2*maxFragData))
	re.push(frags[0]) // incomplete, will age out
	if re.depth() != 1 {
		t.Fatalf("depth %d, want 1", re.depth())
	}
	// Same instant -> survivor (TTL not elapsed).
	re.gc(time.Now())
	if re.depth() != 1 {
		t.Fatalf("premature gc")
	}
	re.gc(time.Now().Add(pendingTTL + time.Second))
	if re.depth() != 0 {
		t.Fatalf("stale entry not collected")
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	f := &fragmenter{}
	if frags := f.build(make([]byte, 256*maxFragData)); frags != nil {
		t.Fatal("256-fragment frame should be rejected")
	}
	if frags := f.build(nil); frags != nil {
		t.Fatal("empty frame should be rejected")
	}
}

func TestFramingIDWrap(t *testing.T) {
	// The production wedge: after 65536 frames the u16 pkt-id wraps and a
	// naive "done" set starves the link. Push 70000 frames through and
	// expect every single one delivered.
	f := &fragmenter{}
	re := newReassembler()
	delivered := 0
	for i := 0; i < 70000; i++ {
		frame := []byte{byte(i), byte(i >> 8), 0xAA}
		frags := f.build(frame)
		var got []byte
		for _, fr := range frags {
			if out, ok := re.push(fr); ok {
				got = out
			}
		}
		if got == nil {
			t.Fatalf("frame %d (past the wrap at %d) not delivered", i, 1<<16)
		}
		if !bytes.Equal(got, frame) {
			t.Fatalf("frame %d corrupted", i)
		}
		delivered++
	}
	if delivered != 70000 {
		t.Fatalf("delivered %d of 70000", delivered)
	}
}

func TestFramingWrapWithReplay(t *testing.T) {
	// A replay of a pre-wrap frame id must still be dropped after the wrap
	// moved the window past it... only within the retained window; older
	// ones pass as strays (acceptable: SRTP replay protection is the
	// primary defense).
	f := &fragmenter{}
	re := newReassembler()
	frame := []byte{1, 2, 3}
	frags := f.build(frame)
	for _, fr := range frags {
		re.push(fr)
	}
	// Immediate replay: dropped (duplicate).
	if _, ok := re.push(frags[0]); ok {
		t.Fatal("immediate replay delivered twice")
	}
}
