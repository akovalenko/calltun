package cli

// The tunnel proper: TUN device <-> RTP track, both directions, until the
// link dies (ICE state, device error, signal). Crash-only: any failure
// returns an error, the process exits non-zero, systemd restarts it.

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"
)

// rtpPayload locates the RTP payload in a decrypted packet: offset and
// length, honoring CSRC list, header extension and padding (RFC 3550).
func rtpPayload(p []byte) (off, length int, ok bool) {
	if len(p) < 12 || p[0]&0xC0 != 0x80 { // version 2
		return 0, 0, false
	}
	off = 12 + 4*int(p[0]&0x0F) // CSRC count
	if p[0]&0x10 != 0 {         // extension bit
		if len(p) < off+4 {
			return 0, 0, false
		}
		off += 4 + 4*int(binary.BigEndian.Uint16(p[off+2:off+4]))
	}
	if off > len(p) {
		return 0, 0, false
	}
	end := len(p)
	if p[0]&0x20 != 0 && end > off { // padding bit: last byte = pad count
		pad := int(p[end-1])
		if pad > end-off {
			return 0, 0, false
		}
		end -= pad
	}
	return off, end - off, true
}

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
			if n > maxFrame {
				c.txDropped.Add(1)
				continue
			}
			if err := w.writeFrame(frame); err != nil {
				// This is an unreliable transport by design: under buffer
				// pressure drop the frame, back off briefly, keep the
				// link alive — never die on a transient write error.
				c.txDropped.Add(1)
				lg.Warn("tx write failed, dropping frame", "err", err)
				select {
				case <-ctx.Done():
					errCh <- err
					return
				case <-time.After(10 * time.Millisecond):
				}
				continue
			}
			c.txFrames.Add(1)
			c.txBytes.Add(uint64(n))
		}
	}()

	// RTP -> dev. Read (not ReadRTP) into one reused buffer: ReadRTP
	// allocates a receiveMTU slice plus an rtp.Packet per packet; the
	// payload offset is parsed manually and dev.Write is a synchronous
	// syscall, so the buffer is safely reusable right after it returns.
	go func() {
		b := make([]byte, 2048) // > our max UDP payload (~1420)
		for {
			n, _, err := remote.Read(b)
			if err != nil {
				errCh <- err
				return
			}
			off, plen, ok := rtpPayload(b[:n])
			if !ok || plen < 2 {
				c.rxJunk.Add(1) // keepalive or malformed
				continue
			}
			lg.Debug("rx rtp", "seq", binary.BigEndian.Uint16(b[2:4]), "len", plen)
			if _, err := dev.Write(b[off : off+plen]); err != nil {
				errCh <- err
				return
			}
			c.rxFrames.Add(1)
			c.rxBytes.Add(uint64(plen))
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
			if s == webrtc.ICEConnectionStateDisconnected {
				lg.Warn("ice disconnected (consent flap?); riding it out")
			}
		case <-stats.C:
			lg.Info("stats",
				"tx_frames", c.txFrames.Load(), "tx_bytes", c.txBytes.Load(), "tx_dropped", c.txDropped.Load(),
				"rx_frames", c.rxFrames.Load(), "rx_bytes", c.rxBytes.Load(), "rx_junk", c.rxJunk.Load())
		}
	}
}
