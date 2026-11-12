package main

// The tunnel proper: TUN device <-> RTP track, both directions, until the
// link dies (ICE state, device error, signal). Crash-only: any failure
// returns an error, the process exits non-zero, systemd restarts it.

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

const (
	keepaliveEvery = 1 * time.Second
	remoteBindWait = 15 * time.Second // until the peer's first packet binds OnTrack
	statsEvery     = 30 * time.Second
	readBufSize    = 65536
)

type counters struct {
	txFrames  atomic.Uint64
	txBytes   atomic.Uint64
	txDropped atomic.Uint64 // oversized / build failures
	rxFrames  atomic.Uint64
	rxBytes   atomic.Uint64
	rxJunk    atomic.Uint64 // short payloads, bad headers (incl. peer keepalives)
}

func runTunnel(ctx context.Context, p *peer, dev io.ReadWriteCloser) error {
	w := newRTPWriter(p.track)
	frag := &fragmenter{}
	re := newReassembler()
	var c counters
	errCh := make(chan error, 3)

	// Keepalives must flow before the remote track binds: the peer's
	// OnTrack fires on our first RTP packet, and vice versa.
	go func() {
		t := time.NewTicker(keepaliveEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := w.keepalive(); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// Wait for the remote track to bind (our keepalives trigger the peer's
	// OnTrack, and its keepalives trigger ours).
	var remote *webrtc.TrackRemote
	select {
	case remote = <-p.remote:
	case <-time.After(remoteBindWait):
		return errors.New("remote track did not bind (no RTP from peer)")
	case <-ctx.Done():
		return ctx.Err()
	}
	lg.Info("remote track bound", "kind", remote.Kind().String(), "ssrc", remote.SSRC())

	// dev -> RTP
	go func() {
		buf := make([]byte, readBufSize)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errCh <- err
				return
			}
			frame := buf[:n]
			frags := frag.build(frame)
			if frags == nil {
				c.txDropped.Add(1)
				continue
			}
			if err := w.writeFrags(frags); err != nil {
				errCh <- err
				return
			}
			lg.Debug("tx frame", "len", n, "frags", len(frags))
			c.txFrames.Add(1)
			c.txBytes.Add(uint64(n))
		}
	}()

	// RTP -> dev
	go func() {
		for {
			pkt, _, err := remote.ReadRTP()
			if err != nil {
				errCh <- err
				return
			}
			lg.Debug("rx rtp", "seq", pkt.SequenceNumber, "len", len(pkt.Payload), "marker", pkt.Marker, "ssrc", pkt.SSRC)
			frame, ok := re.push(pkt.Payload)
			if !ok {
				if len(pkt.Payload) < fragHdr {
					c.rxJunk.Add(1)
					lg.Debug("rx short payload (keepalive)", "len", len(pkt.Payload))
				} else {
					lg.Debug("rx fragment not completing a frame",
						"id", uint16(pkt.Payload[0])<<8|uint16(pkt.Payload[1]),
						"idx", pkt.Payload[2], "total", pkt.Payload[3], "depth", re.depth())
				}
				continue
			}
			if _, err := dev.Write(frame); err != nil {
				errCh <- err
				return
			}
			c.rxFrames.Add(1)
			c.rxBytes.Add(uint64(len(frame)))
		}
	}()

	stats := time.NewTicker(statsEvery)
	defer stats.Stop()

	for {
		select {
		case <-ctx.Done():
			lg.Info("shutting down",
				"tx_frames", c.txFrames.Load(), "tx_bytes", c.txBytes.Load(),
				"rx_frames", c.rxFrames.Load(), "rx_bytes", c.rxBytes.Load())
			return nil
		case err := <-errCh:
			return err
		case s := <-p.states:
			if deadState(s) {
				return errors.New("ice " + s.String())
			}
		case <-stats.C:
			lg.Info("stats",
				"tx_frames", c.txFrames.Load(), "tx_bytes", c.txBytes.Load(), "tx_dropped", c.txDropped.Load(),
				"rx_frames", c.rxFrames.Load(), "rx_bytes", c.rxBytes.Load(), "rx_junk", c.rxJunk.Load(),
				"reasm_depth", re.depth())
		}
	}
}
