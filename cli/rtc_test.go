package cli

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
)

var logOnce sync.Once

// testLog installs the debug logger once for the whole test binary. Pion's
// callbacks outlive the test that created them and go on reading the
// logger, so re-assigning it per test is a data race under -race.
func testLog() {
	logOnce.Do(func() { initLog(true) })
}

// useLoopbackOnly gathers ICE candidates on loopback and nowhere else: the
// default configuration hides loopback, and a sandbox has no other
// interface.
func useLoopbackOnly(t *testing.T) {
	t.Helper()
	old := settingHook
	settingHook = func(se *webrtc.SettingEngine) {
		se.SetIncludeLoopbackCandidate(true)
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
		se.SetInterfaceFilter(func(name string) bool { return name == "lo" })
	}
	t.Cleanup(func() { settingHook = old })
}

// stubTransport is a signaling transport whose peer says one fixed thing
// (or nothing) and is never there for ICE.
type stubTransport struct{ reply sigMsg }

func (s stubTransport) send(sigMsg) error { return nil }

func (s stubTransport) recvCtx(context.Context) (sigMsg, error) {
	if s.reply.Type != "" {
		return s.reply, nil
	}
	return sigMsg{}, context.DeadlineExceeded
}

func (s stubTransport) Close() error { return nil }

func mustPeer(t *testing.T) *peer {
	t.Helper()
	p, err := newPeer(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func waitGathered(t *testing.T, p *peer) {
	t.Helper()
	select {
	case <-p.gatherDone:
	case <-time.After(10 * time.Second):
		t.Fatal("ice gathering did not finish")
	}
}

// goneOffer is an offer made by a peer that closed right afterwards:
// whoever answers it starts ICE against nobody.
func goneOffer(t *testing.T) sigMsg {
	t.Helper()
	p := mustPeer(t)
	defer p.release()
	offer, err := p.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	waitGathered(t, p)
	return sigMsg{Type: "offer", SDP: p.pc.LocalDescription().SDP, Attempt: "gone"}
}

// goneAnswer is a valid answer from a pair that closed right afterwards:
// the initiator applies it and starts ICE — against nobody.
func goneAnswer(t *testing.T) sigMsg {
	t.Helper()
	offerer, answerer := mustPeer(t), mustPeer(t)
	defer offerer.release()
	defer answerer.release()
	offer, err := offerer.pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := offerer.pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	waitGathered(t, offerer)
	if err := answerer.pc.SetRemoteDescription(*offerer.pc.LocalDescription()); err != nil {
		t.Fatal(err)
	}
	answer, err := answerer.pc.CreateAnswer(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := answerer.pc.SetLocalDescription(answer); err != nil {
		t.Fatal(err)
	}
	waitGathered(t, answerer)
	return sigMsg{Type: "answer", SDP: answerer.pc.LocalDescription().SDP}
}

// A failed attempt must not outlive itself. --forever reruns sessions in
// one process, and a PeerConnection that nobody closed keeps its ICE agent:
// goroutines and sockets, 12 goroutines per failed exchange measured. Both
// roles are covered — the session helper on the initiator side, the
// daemon's own release on the responder side.
func TestFailedAttemptsReleasePeer(t *testing.T) {
	testLog()
	useLoopbackOnly(t)

	// Warm-up: whatever pion and the Go runtime start globally is running,
	// so the baseline below is the steady state.
	warm := mustPeer(t)
	wctx, wcancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	_ = responderExchange(wctx, stubTransport{}, warm, goneOffer(t))
	wcancel()
	warm.release()
	goroutines := func() int {
		time.Sleep(1500 * time.Millisecond)
		runtime.GC()
		return runtime.NumGoroutine()
	}
	before := goroutines()

	const attempts = 2
	for i := 0; i < attempts; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		_, err := initiatorSession(ctx, &commonFlags{stun: "none", iceWait: "1s"}, stubTransport{reply: goneAnswer(t)}, nil, "", "", nil)
		cancel()
		if err == nil {
			t.Fatal("initiator: want the session to fail without a live peer")
		}

		p := mustPeer(t)
		ctx, cancel = context.WithTimeout(context.Background(), 700*time.Millisecond)
		err = responderExchange(ctx, stubTransport{}, p, goneOffer(t))
		cancel()
		if err == nil {
			t.Fatal("responder: want the exchange to fail without a live peer")
		}
		p.release() // what accept defers for the whole run
	}

	after := goroutines()
	if leaked := after - before; leaked >= 12 {
		t.Fatalf("%d goroutines leaked after %d failed attempts in each role (before %d, after %d)", leaked, attempts, before, after)
	}
}
