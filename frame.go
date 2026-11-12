package main

// Fire-and-forget framing: one source frame (IP packet / Ethernet frame)
// maps to exactly ONE RTP packet — no fragment ids, no reassembly, no
// dedup rings. A frame larger than the budget is dropped and counted;
// the device MTU gate at attach makes that a loud misconfiguration error
// instead of silent TCP death (MSS follows the interface MTU, so an
// oversized segment class would be lost entirely, with nothing to show
// for it).
//
// History: the v0 fragmenter/reassembler (u16 pkt-id, idx/total, pending
// map, delivered-id ring) produced two production wedges — a done-set
// starving on id wrap at exactly 65536 frames (~70.7 MB), and a stale
// pending/dedup cascade freezing the link again around the third wrap
// under iperf load. With the MTU gate, one-packet-per-frame is strictly
// simpler and loses nothing in practice.

const (
	// outerUDP is the max UDP payload we emit (path-MTU safe: the whole
	// datagram stays under 1500 with headers and the SRTP tag).
	outerUDP = 1420
	rtpHdr   = 12 // base RTP header
	extHdr   = 8  // worst-case header extension
	srtpTag  = 16 // worst-case SRTP auth tag (AEAD GCM)
	// maxFrame is the largest source frame that fits one RTP packet.
	// 1360 also accommodates IPv6's minimum MTU of 1280 inside.
	maxFrame = outerUDP - rtpHdr - extHdr - srtpTag
)
