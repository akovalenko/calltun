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

// reassembler dedups delivered pkt-ids with a wrap-tolerant ring: the
// fragmenter's u16 id wraps every 65536 frames (~70 MB of traffic), and a
// plain "done" set then starves the link — every post-wrap id collides
// with a stale pre-wrap entry and the frame is dropped as a duplicate
// (observed in production: two independent wedges, both with rx frozen at
// ~70.7 MB; keepalives passed because they bypass reassembly).
const dupWindowBits = 2048 // recently-delivered id window

type reassembler struct {
	pending map[uint16]*reassembly
	lastID  int32 // highest id seen, unwrapped across 16-bit rollovers
	ring    [dupWindowBits / 64]uint64
}

func newReassembler() *reassembler {
	return &reassembler{pending: make(map[uint16]*reassembly)}
}

// isDelivered reports (wrap-aware, read-only) whether the frame with
// this pkt-id was already completed.
func (r *reassembler) isDelivered(id uint16) bool {
	d := int32(id) - int32(uint16(r.lastID))
	if d > 0 {
		return false // ahead of the head: cannot be delivered yet
	}
	// d == 0: the head itself, always marked when lastID advanced.
	back := int(-d)
	if back >= dupWindowBits {
		return false // older than the retained window — let it through
	}
	return bitSet(&r.ring, back)
}

// markDelivered records a completed frame's id, advancing the window.
func (r *reassembler) markDelivered(id uint16) {
	d := int32(id) - int32(uint16(r.lastID))
	if d > 0 {
		if int(d) >= dupWindowBits {
			r.ring = [dupWindowBits / 64]uint64{}
		} else {
			shiftRing(&r.ring, int(d))
		}
		r.lastID += d
		setBit(&r.ring, 0)
		return
	}
	if d == 0 {
		setBit(&r.ring, 0)
		return
	}
	back := int(-d)
	if back < dupWindowBits {
		setBit(&r.ring, back)
	}
}

func shiftRing(r *[dupWindowBits / 64]uint64, n int) {
	words := n / 64
	bits := uint(n % 64)
	if words > 0 {
		copy(r[:len(r)-words], r[words:])
		for i := len(r) - words; i < len(r); i++ {
			r[i] = 0
		}
	}
	if bits > 0 {
		carry := uint64(0)
		for i := len(r) - 1; i >= 0; i-- {
			next := r[i] >> (64 - bits)
			r[i] = (r[i] << bits) | carry
			carry = next
		}
	}
}

func setBit(r *[dupWindowBits / 64]uint64, back int) { r[back/64] |= 1 << (back % 64) }
func bitSet(r *[dupWindowBits / 64]uint64, back int) bool {
	return r[back/64]&(1<<(back%64)) != 0
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
	if r.isDelivered(id) {
		return nil, false // replay of a completed frame
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
	r.markDelivered(id)
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
}

// depth returns the number of incomplete sets (for stats/logging).
func (r *reassembler) depth() int { return len(r.pending) }
