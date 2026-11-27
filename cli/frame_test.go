package cli

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

func TestRTPLayloadOffset(t *testing.T) {
	hdr := []byte{0x80, 0xE0, 0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 2}
	// plain 12-byte header
	p := append(append([]byte{}, hdr...), 1, 2, 3)
	off, n, ok := rtpPayload(p)
	if !ok || off != 12 || n != 3 {
		t.Fatalf("plain: off=%d n=%d ok=%v", off, n, ok)
	}
	// one CSRC
	p2 := append([]byte{0x81, 0xE0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2, 9, 9, 9, 9}, 4, 5)
	off, n, ok = rtpPayload(p2)
	if !ok || off != 16 || n != 2 {
		t.Fatalf("csrc: off=%d n=%d ok=%v", off, n, ok)
	}
	// extension: 1 word (X bit set)
	p3 := append(append([]byte{}, hdr...), 0xBE, 0xDE, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 7, 8)
	p3[0] |= 0x10
	off, n, ok = rtpPayload(p3)
	if !ok || off != 12+4+4 || n != 2 {
		t.Fatalf("ext: off=%d n=%d ok=%v", off, n, ok)
	}
	// padding: 2 pad bytes declared
	p4 := append(append([]byte{}, hdr...), 1, 2, 0, 0)
	p4[0] |= 0x20
	p4[len(p4)-1] = 2
	off, n, ok = rtpPayload(p4)
	if !ok || n != 2 {
		t.Fatalf("pad: off=%d n=%d ok=%v", off, n, ok)
	}
	// garbage
	if _, _, ok := rtpPayload([]byte{1, 2, 3}); ok {
		t.Fatal("short packet accepted")
	}
}
