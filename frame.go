package main

// Framing: a source frame (IP packet in tun mode, Ethernet frame in tap
// mode — opaque bytes either way) becomes one or more RTP payloads. Fragment
// header (big-endian): u16 pkt-id, u8 idx, u8 total. The receiver
// reassembles by pkt-id; an incomplete set is evicted by age or by load —
// no retransmission in v1, a lost fragment kills the whole source frame.

import (
	"encoding/binary"
	"time"
)

const (
	// outerBudget: max UDP payload per packet (WebRTC-safe, no IP frag).
	outerBudget = 1200
	rtpHdr      = 12 // base RTP header
	extHdr      = 8  // worst-case header extension (e.g. transport-cc)
	srtpTag     = 16 // worst-case SRTP auth tag (AEAD GCM)
	fragHdr     = 4
	// maxFragData is the largest source-frame chunk per RTP packet.
	maxFragData = outerBudget - rtpHdr - extHdr - srtpTag - fragHdr // 1160

	maxPending = 4096 // reassembly table size cap
	pendingTTL = 2 * time.Second
)

type fragmenter struct {
	next uint16
}

// build splits one frame into RTP payloads; returns nil if the frame needs
// more than 255 fragments (a misconfigured MTU upstream of us).
func (f *fragmenter) build(frame []byte) [][]byte {
	if len(frame) == 0 {
		return nil
	}
	total := (len(frame) + maxFragData - 1) / maxFragData
	if total > 255 {
		return nil
	}
	id := f.next
	f.next++
	out := make([][]byte, 0, total)
	for off, i := 0, 0; off < len(frame); off, i = off+maxFragData, i+1 {
		end := off + maxFragData
		if end > len(frame) {
			end = len(frame)
		}
		buf := make([]byte, fragHdr+end-off)
		binary.BigEndian.PutUint16(buf[0:2], id)
		buf[2] = uint8(i)
		buf[3] = uint8(total)
		copy(buf[fragHdr:], frame[off:end])
		out = append(out, buf)
	}
	return out
}

type reassembly struct {
	slots [][]byte
	got   int
	seen  time.Time
}

type reassembler struct {
	pending map[uint16]*reassembly
	// done holds recently completed ids so a replayed fragment set does not
	// reassemble into a second copy of the same frame (SRTP replay
	// protection already eats exact packet duplicates; this is the
	// belt-and-braces for reordered replays).
	done map[uint16]time.Time
}

func newReassembler() *reassembler {
	return &reassembler{
		pending: make(map[uint16]*reassembly),
		done:    make(map[uint16]time.Time),
	}
}

// push feeds one RTP payload; it returns the complete frame when the last
// missing fragment arrives. Duplicate and out-of-range fragments are
// ignored; payload shorter than the fragment header is noise (keepalives).
func (r *reassembler) push(payload []byte) ([]byte, bool) {
	if len(payload) < fragHdr {
		return nil, false
	}
	id := binary.BigEndian.Uint16(payload[0:2])
	idx := payload[2]
	total := payload[3]
	if total == 0 || idx >= total {
		return nil, false
	}
	if _, recent := r.done[id]; recent {
		return nil, false
	}
	e := r.pending[id]
	if e == nil {
		if len(r.pending) >= maxPending {
			r.gc(time.Now())
		}
		e = &reassembly{slots: make([][]byte, total)}
		r.pending[id] = e
	}
	if e.slots[idx] != nil {
		return nil, false // duplicate
	}
	e.slots[idx] = payload[fragHdr:]
	e.got++
	e.seen = time.Now()
	if e.got < int(total) {
		return nil, false
	}
	delete(r.pending, id)
	r.done[id] = time.Now()
	size := 0
	for _, s := range e.slots {
		size += len(s)
	}
	out := make([]byte, 0, size)
	for _, s := range e.slots {
		out = append(out, s...)
	}
	return out, true
}

func (r *reassembler) gc(now time.Time) {
	for id, e := range r.pending {
		if now.Sub(e.seen) > pendingTTL {
			delete(r.pending, id)
		}
	}
	for id, at := range r.done {
		if now.Sub(at) > pendingTTL {
			delete(r.done, id)
		}
	}
}

// depth returns the number of incomplete sets (for stats/logging).
func (r *reassembler) depth() int { return len(r.pending) }
