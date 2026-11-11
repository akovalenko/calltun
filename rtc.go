package main

// WebRTC setup: a single m=video line, one VP8 codec, no data channels at
// all — after the DTLS handshake the wire carries only RTP/RTCP plus ICE
// consent checks, exactly like a call. Both directions are RTP tracks; the
// payload is opaque bytes (fragmented IP packets / Ethernet frames).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

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

func newPeer(stun []string) (*peer, error) {
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
	if err := webrtc.RegisterDefaultInterceptors(m, ir); err != nil {
		return nil, err
	}

	api := webrtc.NewAPI(
		webrtc.WithMediaEngine(m),
		webrtc.WithInterceptorRegistry(ir),
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
		return nil, err
	}
	if _, err := pc.AddTrack(track); err != nil {
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
type rtpWriter struct {
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

// writeFrags sends the RTP payloads of one source frame (same timestamp,
// marker set on the last fragment, sequence numbers contiguous).
func (w *rtpWriter) writeFrags(frags [][]byte) error {
	for i, payload := range frags {
		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				Marker:         i == len(frags)-1,
				PayloadType:    payloadType,
				SequenceNumber: w.seq,
				Timestamp:      w.ts,
				SSRC:           w.ssrc,
			},
			Payload: payload,
		}
		w.seq++
		if err := w.track.WriteRTP(pkt); err != nil {
			return err
		}
	}
	w.ts += tsStep
	return nil
}

// keepalive sends a sub-header packet (dropped by the receiver) to bind the
// peer's OnTrack and to keep the NAT mapping fresh on an idle link.
func (w *rtpWriter) keepalive() error {
	w.seq++
	return w.track.WriteRTP(&rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    payloadType,
			SequenceNumber: w.seq,
			Timestamp:      w.ts,
			SSRC:           w.ssrc,
		},
		Payload: []byte{0},
	})
}

// deadState reports whether an ICE state is unrecoverable for this link.
func deadState(s webrtc.ICEConnectionState) bool {
	return s == webrtc.ICEConnectionStateFailed ||
		s == webrtc.ICEConnectionStateDisconnected ||
		s == webrtc.ICEConnectionStateClosed
}
