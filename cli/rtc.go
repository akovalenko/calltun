package cli

// WebRTC setup: a single m=video line, one VP8 codec, no data channels at
// all — after the DTLS handshake the wire carries only RTP/RTCP plus ICE
// consent checks, exactly like a call. Both directions are RTP tracks; the
// payload is opaque bytes (fragmented IP packets / Ethernet frames).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sync"

	"github.com/pion/interceptor"
	"github.com/pion/interceptor/pkg/report"
	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// pionLogger returns the pion LoggerFactory: with CALLTUN_PIONLOG=1 every
// subsystem logs at trace level to stderr (SRTP decrypt failures and demux
// drops are invisible at our level).
func pionLogger() logging.LoggerFactory {
	f := logging.NewDefaultLoggerFactory()
	if os.Getenv("CALLTUN_PIONLOG") != "" {
		f.DefaultLogLevel = logging.LogLevelTrace
	}
	return f
}

const (
	payloadType = 96   // dynamic PT, VP8 in real calls
	tsStep      = 3000 // ~33ms of 90kHz "frame duration" per source frame
)

type peer struct {
	pc         *webrtc.PeerConnection
	track      *webrtc.TrackLocalStaticRTP // our outgoing track
	remote     chan *webrtc.TrackRemote    // first incoming track
	states     chan webrtc.ICEConnectionState
	gatherDone chan struct{}
}

// release closes the PeerConnection and frees what it holds: an ICE agent
// keeps its goroutines and sockets until then (12 goroutines per failed
// exchange, measured). A crash-only run never needs it — process exit is
// the teardown — but --forever reruns sessions in place, and every failed
// or finished attempt would otherwise leave one agent behind. Idempotent.
func (p *peer) release() {
	if p == nil || p.pc == nil {
		return
	}
	_ = p.pc.Close()
	p.pc = nil
}

// settingHook adjusts the SettingEngine after the candidate filters; nil in
// production. The in-process exit test uses it for loopback-only candidates:
// the default configuration hides loopback from ICE, and a sandbox has no
// other interface.
var settingHook func(*webrtc.SettingEngine)

// newPeer builds the m=video-only PeerConnection. excludeIfs are interface
// names never to gather candidates on: the tunnel device(s) this daemon
// serves, plus anything the operator knows is reachable only THROUGH a
// tunnel (other links of a mesh) — media sent to such an address is routed
// into the tunnel and eaten by our own reader.
func newPeer(stun []string, excludeIfs, pinIfs []string) (*peer, error) {
	m := &webrtc.MediaEngine{}
	vp8 := webrtc.RTPCodecParameters{
		RTPCodecCapability: webrtc.RTPCodecCapability{
			MimeType:  webrtc.MimeTypeVP8,
			ClockRate: 90000,
		},
		PayloadType: payloadType,
	}
	if err := m.RegisterCodec(vp8, webrtc.RTPCodecTypeVideo); err != nil {
		return nil, err
	}

	ir := &interceptor.Registry{}
	if os.Getenv("CALLTUN_FULL_INTERCEPTORS") != "" {
		// A/B canary: pion's default set (adds the NACK generator/responder
		// pair and TWCC). Default is reports-only: v0 wants no
		// retransmissions, and the NACK pair poisons streams under loss
		// (see README lessons).
		if err := webrtc.RegisterDefaultInterceptors(m, ir); err != nil {
			return nil, err
		}
	} else {
		if f, err := report.NewReceiverInterceptor(); err == nil {
			ir.Add(f)
		}
		if f, err := report.NewSenderInterceptor(); err == nil {
			ir.Add(f)
		}
	}

	se := webrtc.SettingEngine{}
	se.LoggerFactory = pionLogger()
	switch {
	case len(pinIfs) > 0:
		// Allowlist: gather ONLY on these interfaces. The robust inverse
		// of the exclusion list — with many links on one host (fallback
		// tunnels) enumerating every dangerous interface is fragile,
		// while pinning the WAN interface makes media loops impossible
		// by construction. srflx candidates are still derived from these
		// sockets, so STUN traversal is unaffected.
		good := make(map[string]bool, len(pinIfs))
		for _, n := range pinIfs {
			good[n] = true
		}
		se.SetInterfaceFilter(func(name string) bool { return good[name] })
	case len(excludeIfs) > 0:
		bad := make(map[string]bool, len(excludeIfs))
		for _, n := range excludeIfs {
			bad[n] = true
		}
		se.SetInterfaceFilter(func(name string) bool { return !bad[name] })
	}
	if settingHook != nil {
		settingHook(&se)
	}
	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(ir),
		webrtc.WithSettingEngine(se),
	)

	cfg := webrtc.Configuration{}
	if len(stun) > 0 {
		cfg.ICEServers = []webrtc.ICEServer{{URLs: stun}}
	}
	pc, err := api.NewPeerConnection(cfg)
	if err != nil {
		return nil, err
	}

	track, err := webrtc.NewTrackLocalStaticRTP(
		webrtc.RTPCodecCapability{MimeType: webrtc.MimeTypeVP8, ClockRate: 90000},
		"video0", "calltun",
	)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if _, err := pc.AddTrack(track); err != nil {
		pc.Close()
		return nil, err
	}

	p := &peer{
		pc:         pc,
		track:      track,
		remote:     make(chan *webrtc.TrackRemote, 1),
		states:     make(chan webrtc.ICEConnectionState, 16),
		gatherDone: make(chan struct{}),
	}
	pc.OnTrack(func(t *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		select {
		case p.remote <- t:
		default: // already bound
		}
	})
	pc.OnICEConnectionStateChange(func(s webrtc.ICEConnectionState) {
		lg.Info("ice state", "state", s.String())
		select {
		case p.states <- s:
		default:
		}
	})
	pc.OnICEGatheringStateChange(func(s webrtc.ICEGatheringState) {
		if s == webrtc.ICEGatheringStateComplete {
			close(p.gatherDone)
		}
	})
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		lg.Info("pc state", "state", s.String())
	})
	return p, nil
}

// waitConnected blocks until ICE reports connected (or fails/disconnects).
func (p *peer) waitConnected(ctx context.Context) error {
	for {
		select {
		case s := <-p.states:
			switch s {
			case webrtc.ICEConnectionStateConnected:
				return nil
			case webrtc.ICEConnectionStateFailed, webrtc.ICEConnectionStateDisconnected,
				webrtc.ICEConnectionStateClosed:
				return fmt.Errorf("ice %s before connect", s)
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// rtpWriter turns source frames into RTP packets on our outgoing track.
// All writes are serialized: the data goroutine and the keepalive goroutine
// share the track, and pion's WriteRTP/SRTP encryptor is not safe for
// concurrent use (racing writes corrupt packets; the peer drops them on
// auth failure).
type rtpWriter struct {
	mu    sync.Mutex
	track *webrtc.TrackLocalStaticRTP
	seq   uint16
	ts    uint32
	ssrc  uint32
}

func newRTPWriter(track *webrtc.TrackLocalStaticRTP) *rtpWriter {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return &rtpWriter{track: track, ts: randUint32(), ssrc: binary.BigEndian.Uint32(b[:])}
}

func randUint32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// writeFrame sends one source frame as one RTP packet (marker set, like
// the last packet of a video frame). The same seq discipline as
// keepalive: send with the current value, then increment — a mismatched
// discipline collides seqs and the peer's SRTP replay filter eats the
// data.
func (w *rtpWriter) writeFrame(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			Marker:         true,
			PayloadType:    payloadType,
			SequenceNumber: w.seq,
			Timestamp:      w.ts,
			SSRC:           w.ssrc,
		},
		Payload: frame,
	}
	w.seq++
	w.ts += tsStep
	return w.track.WriteRTP(pkt)
}

// keepalive sends a sub-header packet (dropped by the receiver) to bind the
// peer's OnTrack and to keep the NAT mapping fresh on an idle link.
// keepalive uses the SAME seq discipline as writeFrags: send with the
// current value, then increment. A mismatched discipline collides seqs
// with data packets, and the peer's SRTP replay filter silently eats the
// data ("duplicated packet").
func (w *rtpWriter) keepalive() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	seq := w.seq
	w.seq++
	_ = seq
	return w.track.WriteRTP(&rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    payloadType,
			SequenceNumber: seq,
			Timestamp:      w.ts,
			SSRC:           w.ssrc,
		},
		Payload: []byte{0},
	})
}

// deadState reports whether an ICE state is unrecoverable for this link.
// Disconnected is deliberately NOT fatal: under bulk load the consent
// checks starve, the agent flaps to disconnected and can recover to
// connected on its own — observed live: 2 minutes into an iperf run the
// link "fell", only because the daemon treated the flap as terminal.
func deadState(s webrtc.ICEConnectionState) bool {
	return s == webrtc.ICEConnectionStateFailed ||
		s == webrtc.ICEConnectionStateClosed
}
