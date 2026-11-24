package main

// Signaling: the offer/answer exchange, transport-agnostic. The two
// transports are the SSH stdio pipe (up side) or local unix socket (offer
// bridge -> accept daemon) — sigConn — and the nostr relay fan (nostrFan);
// both implement sigTransport. No trickle: each side waits for ICE
// gathering to complete and sends the whole SDP in one message. The
// Attempt field correlates messages of one exchange on the async nostr
// transport (the ssh stream correlates implicitly and ignores it).

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/pion/webrtc/v4"
)

// sigTransport is the bidirectional message surface an exchange runs on.
type sigTransport interface {
	send(m sigMsg) error
	recvCtx(ctx context.Context) (sigMsg, error)
	Close() error
}

type sigMsg struct {
	Type    string `json:"type"`              // offer | answer | ready | abort
	SDP     string `json:"sdp,omitempty"`     // full SDP for offer/answer
	Err     string `json:"err,omitempty"`     // human-readable abort reason
	Attempt string `json:"attempt,omitempty"` // exchange id: initiator mints, responder echoes
}

type sigConn struct {
	r *bufio.Reader
	w *bufio.Writer
	c io.Closer
}

func newSigConn(rwc io.ReadWriteCloser) *sigConn {
	return &sigConn{
		r: bufio.NewReaderSize(rwc, 16*1024),
		w: bufio.NewWriterSize(rwc, 16*1024),
		c: rwc,
	}
}

func (s *sigConn) send(m sigMsg) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err := s.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return s.w.Flush()
}

func (s *sigConn) recv() (sigMsg, error) {
	var m sigMsg
	line, err := s.r.ReadBytes('\n')
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(line, &m); err != nil {
		return m, fmt.Errorf("bad signaling message: %w", err)
	}
	return m, nil
}

// recvCtx is recv with a deadline: a blocking read alone would hang the
// whole exchange forever (ssh pipes carry no deadlines), wedging both
// daemons past every context timeout.
func (s *sigConn) recvCtx(ctx context.Context) (sigMsg, error) {
	type res struct {
		m   sigMsg
		err error
	}
	ch := make(chan res, 1)
	go func() {
		m, err := s.recv()
		ch <- res{m, err}
	}()
	select {
	case r := <-ch:
		return r.m, r.err
	case <-ctx.Done():
		return sigMsg{}, ctx.Err()
	}
}

func (s *sigConn) Close() error { return s.c.Close() }

const sigReadyTimeout = 15 * time.Second

// signalInitiator runs the offer/answer exchange on the `up` side: send the
// offer (after gathering), apply the answer, wait for ICE to connect, then
// a final ready/ready handshake. The transport is closed by the caller.
func signalInitiator(ctx context.Context, c sigTransport, p *peer) error {
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}
	select {
	case <-p.gatherDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	attempt := newAttemptId()
	if err := c.send(sigMsg{Type: "offer", SDP: p.pc.LocalDescription().SDP, Attempt: attempt}); err != nil {
		return fmt.Errorf("send offer: %w", err)
	}
	lg.Debug("offer sent", "attempt", attempt, "sdp", p.pc.LocalDescription().SDP)

	ans, err := c.recvCtx(ctx)
	if err != nil {
		return fmt.Errorf("recv answer: %w", err)
	}
	switch ans.Type {
	case "answer":
	case "abort":
		return fmt.Errorf("peer aborted: %s", ans.Err)
	default:
		return fmt.Errorf("expected answer, got %q", ans.Type)
	}
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer, SDP: ans.SDP,
	}); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}
	if err := p.waitConnected(ctx); err != nil {
		return err
	}
	if err := c.send(sigMsg{Type: "ready", Attempt: attempt}); err != nil {
		return fmt.Errorf("send ready: %w", err)
	}
	return readyHandshake(ctx, c, attempt)
}

// signalResponder is the accept-daemon half, symmetric to signalInitiator.
// Split into recvOffer + responderExchange: the nostr accept path waits
// for an offer under an unbounded context (like the ssh socket Accept)
// and mints the exchange deadline only when one lands.
func signalResponder(ctx context.Context, c sigTransport, p *peer) error {
	off, err := recvOffer(ctx, c)
	if err != nil {
		return err
	}
	return responderExchange(ctx, c, p, off)
}

// recvOffer waits for the offer message and rejects anything else.
func recvOffer(ctx context.Context, c sigTransport) (sigMsg, error) {
	off, err := c.recvCtx(ctx)
	if err != nil {
		return sigMsg{}, fmt.Errorf("recv offer: %w", err)
	}
	if off.Type != "offer" {
		return sigMsg{}, sendAbortf(c, off.Attempt, "expected offer, got %q", off.Type)
	}
	return off, nil
}

// responderExchange answers the offer and brings the link up.
func responderExchange(ctx context.Context, c sigTransport, p *peer, off sigMsg) error {
	if err := p.pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeOffer, SDP: off.SDP,
	}); err != nil {
		return sendAbortf(c, off.Attempt, "bad offer: %v", err)
	}
	answer, err := p.pc.CreateAnswer(nil)
	if err != nil {
		return sendAbortf(c, off.Attempt, "create answer: %v", err)
	}
	if err := p.pc.SetLocalDescription(answer); err != nil {
		return sendAbortf(c, off.Attempt, "set local description: %v", err)
	}
	select {
	case <-p.gatherDone:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := c.send(sigMsg{Type: "answer", SDP: p.pc.LocalDescription().SDP, Attempt: off.Attempt}); err != nil {
		return fmt.Errorf("send answer: %w", err)
	}
	lg.Debug("answer sent", "attempt", off.Attempt, "sdp", p.pc.LocalDescription().SDP)
	if err := p.waitConnected(ctx); err != nil {
		return err
	}
	if err := c.send(sigMsg{Type: "ready", Attempt: off.Attempt}); err != nil {
		return fmt.Errorf("send ready: %w", err)
	}
	return readyHandshake(ctx, c, off.Attempt)
}

// readyHandshake waits for the peer's ready, bounded: both ICE states are
// already connected, so a missing ready must not wedge the link. On the
// nostr transport a stray message for another attempt may still surface —
// warn and keep waiting rather than failing a connected link.
func readyHandshake(ctx context.Context, c sigTransport, attempt string) error {
	rctx, cancel := context.WithTimeout(ctx, sigReadyTimeout)
	defer cancel()
	for {
		m, err := c.recvCtx(rctx)
		if err != nil {
			// Both ICE states are connected; a peer that closed its transport
			// right after sending ready must not wedge the link.
			lg.Warn("peer ready not received; proceeding (ICE is connected)", "err", err)
			return nil
		}
		switch m.Type {
		case "ready":
			return nil
		case "abort":
			return fmt.Errorf("peer aborted: %s", m.Err)
		default:
			lg.Warn("unexpected message during ready handshake, ignored", "type", m.Type)
		}
	}
}

// sendAbortf reports an error to the peer before failing.
func sendAbortf(c sigTransport, attempt string, format string, args ...any) error {
	msg := fmt.Sprintf(format, args...)
	_ = c.send(sigMsg{Type: "abort", Err: msg, Attempt: attempt})
	return fmt.Errorf("%s", msg)
}
