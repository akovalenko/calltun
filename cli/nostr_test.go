package cli

// Tests for the nostr signaling transport: the wrap/unwrap/filter path
// (crypto real, relays faked by direct ingest), the attempt correlation
// and settle-newest logic (pure channel feeding), and — when a `nak`
// binary is on PATH — a loopback relay e2e. A live exchange against the
// curated public relays runs under CALLTUN_NOSTR_LIVE=1 (throwaway keys).

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// TestMain gives the package tests a live logger: fan code logs drops and
// reconnects, and a nil lg would panic. Discarded by default; set
// CALLTUN_TEST_LOG=1 to see the fan's debug chatter on stderr.
func TestMain(m *testing.M) {
	w := io.Discard
	level := slog.LevelInfo
	if os.Getenv("CALLTUN_TEST_LOG") != "" {
		w = os.Stderr
		level = slog.LevelDebug
	}
	lg = slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
	os.Exit(m.Run())
}

func testFan(t *testing.T) (*nostrFan, *nostrFan) {
	t.Helper()
	skA := nostr.GeneratePrivateKey()
	skB := nostr.GeneratePrivateKey()
	pubA, _ := nostr.GetPublicKey(skA)
	pubB, _ := nostr.GetPublicKey(skB)
	// Fans without readers (no relays): the channel and the correlation
	// logic are what these tests drive.
	newF := func(sk, pub, peer string) *nostrFan {
		return &nostrFan{
			sk: sk, pub: pub, peer: peer,
			ctx:       context.Background(),
			events:    make(chan fanEvent, 64),
			seen:      map[string]struct{}{},
			supersede: make(chan struct{}),
		}
	}
	return newF(skA, pubA, pubB), newF(skB, pubB, pubA)
}

func feed(t *testing.T, f *nostrFan, sk, peer string, m sigMsg, at time.Time) {
	t.Helper()
	wrap, err := wrapSignal(sk, peer, m, at)
	if err != nil {
		t.Fatalf("wrapSignal: %v", err)
	}
	ev := wrap
	fe, drop := f.ingest(&ev)
	if drop {
		t.Fatalf("ingest dropped a legitimate message (type %s)", m.Type)
	}
	f.events <- fe // what the relay reader would do
}

func TestNostrWrapRoundtrip(t *testing.T) {
	fa, fb := testFan(t)
	offer := sigMsg{Type: "offer", SDP: "v=0\r\n-fake-", Attempt: "aa11223344556677"}
	now := time.Now()
	feed(t, fb, fa.sk, fb.pub, offer, now)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// Responder await: settle window runs 1.5s; the newest offer returns.
	got, err := fb.recvEvent(ctx)
	if err != nil {
		t.Fatalf("recvEvent: %v", err)
	}
	if got.msg.Type != "offer" || got.msg.SDP != offer.SDP || got.msg.Attempt != offer.Attempt {
		t.Fatalf("roundtrip mismatch: %+v", got.msg)
	}
	if fb.currentAttempt() != offer.Attempt {
		t.Fatalf("attempt not adopted after offer delivery")
	}
}

func TestNostrIngestFilters(t *testing.T) {
	fa, fb := testFan(t)
	skEve := nostr.GeneratePrivateKey()
	now := time.Now()

	// Wrong recipient: a wrap addressed to A cannot be ingested by B's fan.
	w, err := wrapSignal(fa.sk, fa.pub, sigMsg{Type: "offer", Attempt: "x"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, drop := fb.ingest(&w); !drop {
		t.Fatal("wrap for another recipient was not dropped")
	}

	// Non-peer sender: B unwraps fine but the rumor author is Eve.
	feedDrop := func(sk, toPub string, m sigMsg, at time.Time) bool {
		w, err := wrapSignal(sk, toPub, m, at)
		if err != nil {
			t.Fatal(err)
		}
		_, drop := fb.ingest(&w)
		return drop
	}
	if !feedDrop(skEve, fb.pub, sigMsg{Type: "offer", Attempt: "y"}, now) {
		t.Fatal("offer from a non-peer key was not dropped")
	}

	// Past the TTL.
	if !feedDrop(fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "z"}, now.Add(-offerTTL-time.Minute)) {
		t.Fatal("stale offer was not dropped")
	}

	// Fresh, from the peer: passes.
	if feedDrop(fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "w"}, now) {
		t.Fatal("legitimate offer was dropped")
	}

	// Duplicate of the same rumor (same id from another relay): dropped.
	if !feedDrop(fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "w"}, now) {
		// Same content+mint -> same rumor id; the wrap differs (nonce key)
		// but the rumor inside is identical, so id-dedupe must bite.
		t.Fatal("duplicate rumor was not dropped")
	}
}

func TestNostrAttemptCorrelation(t *testing.T) {
	fa, fb := testFan(t)
	now := time.Now()

	// Responder adopts the newest of two buffered offers and then only
	// passes messages echoing that attempt.
	old := sigMsg{Type: "offer", Attempt: "old", SDP: "o1"}
	new_ := sigMsg{Type: "offer", Attempt: "new", SDP: "o2"}
	feed(t, fb, fa.sk, fb.pub, old, now.Add(-2*time.Second))
	feed(t, fb, fa.sk, fb.pub, new_, now)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := fb.recvEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.msg.Attempt != "new" {
		t.Fatalf("settle did not pick the newest offer: %+v", got.msg)
	}

	// Responder after adoption: a stray answer for another attempt is
	// skipped, the matching ready passes.
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "answer", Attempt: "zzz", SDP: "stale"}, now)
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "ready", Attempt: "new"}, now)
	m, err := fb.recvCtx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "ready" || m.Attempt != "new" {
		t.Fatalf("correlation passed the wrong message: %+v", m)
	}

	// Initiator side: adopts its own attempt (as send does), stale
	// answers are skipped, the current one passes.
	fa.adopt("a2")
	feed(t, fa, fb.sk, fa.pub, sigMsg{Type: "answer", Attempt: "a1", SDP: "stale"}, now)
	feed(t, fa, fb.sk, fa.pub, sigMsg{Type: "answer", Attempt: "a2", SDP: "fresh"}, now)
	m, err = fa.recvCtx(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "answer" || m.Attempt != "a2" || m.SDP != "fresh" {
		t.Fatalf("initiator got the wrong answer: %+v", m)
	}
}

// TestNostrSupersede: after adopting an offer, a NEWER one from the peer
// latches the supersede signal (from the ingest path — nobody reads the
// channel during an ICE wait); an older one does not.
func TestNostrSupersede(t *testing.T) {
	fa, fb := testFan(t)
	now := time.Now()

	// Responder adopts via the settle path.
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "live", SDP: "o1"}, now)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := fb.recvEvent(ctx); err != nil {
		t.Fatal(err)
	}

	// Older unseen offer: must NOT supersede (slow backfill from a
	// second relay arrives after adoption all the time).
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "older", SDP: "o0"}, now.Add(-3*time.Second))
	select {
	case <-fb.Superseded():
		t.Fatal("older offer raised supersede")
	default:
	}

	// Newer offer: ingest latches supersede even with nobody reading.
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "newest", SDP: "o2"}, now.Add(2*time.Second))
	select {
	case <-fb.Superseded():
	default:
		t.Fatal("newer offer did not raise supersede")
	}
}

// TestNostrSettleDebounce: an offer arriving within the quiet window
// extends it — the responder answers the newest, not the first.
func TestNostrSettleDebounce(t *testing.T) {
	fa, fb := testFan(t)
	now := time.Now()
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "first", SDP: "o1"}, now)
	time.Sleep(800 * time.Millisecond) // inside the 1.5s quiet window
	feed(t, fb, fa.sk, fb.pub, sigMsg{Type: "offer", Attempt: "second", SDP: "o2"}, now)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	t0 := time.Now()
	got, err := fb.recvEvent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(t0)
	if got.msg.Attempt != "second" {
		t.Fatalf("debounce did not extend to the newer offer: %+v", got.msg)
	}
	if elapsed < 1400*time.Millisecond {
		t.Fatalf("quiet window did not restart on the second offer: %v", elapsed)
	}
}

// TestNostrWrapSizeGate: an oversized SDP (many-candidate host) fails
// loudly before publishing, with the --if advice in the message.
func TestNostrWrapSizeGate(t *testing.T) {
	fa, _ := testFan(t)
	fa.relays = nil // the gate must fire before any relay is contacted
	var big strings.Builder
	big.WriteString("v=0\r\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&big, "a=candidate:%d 1 udp 2130706431 10.231.%d.%d 40000 typ host\r\n", i, i/250, i%250)
	}
	err := fa.send(sigMsg{Type: "offer", SDP: big.String(), Attempt: "big"})
	if err == nil || !strings.Contains(err.Error(), "--if") {
		t.Fatalf("oversized wrap not gated with advice: %v", err)
	}
	// A normal single-interface SDP passes the gate (and fails later at
	// publish — no relays configured — proving the gate itself let it by).
	err = fa.send(sigMsg{Type: "offer", SDP: "v=0\r\na=candidate:1 1 udp 1 10.0.0.1 4000 typ host\r\n", Attempt: "ok"})
	if err == nil || strings.Contains(err.Error(), "--if") {
		t.Fatalf("normal wrap wrongly gated or unexpectedly published: %v", err)
	}
}

// TestNostrNakE2E runs the transport against a local `nak serve` relay:
// offer/answer/ready exchange between two fans, plus duplicate delivery
// (two subscriptions see the same events) and a superseding offer.
func TestNostrNakE2E(t *testing.T) {
	nak, err := exec.LookPath("nak")
	if err != nil {
		t.Skip("nak binary not on PATH")
	}
	port := 14879
	relay := fmt.Sprintf("ws://127.0.0.1:%d", port)
	cmd := exec.Command(nak, "serve", fmt.Sprintf("--port=%d", port))
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Skipf("nak serve: %v", err)
	}
	defer cmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	skA := nostr.GeneratePrivateKey()
	skB := nostr.GeneratePrivateKey()
	pubA, _ := nostr.GetPublicKey(skA)
	pubB, _ := nostr.GetPublicKey(skB)
	fa, err := newNostrFan(skA, pubB, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	fb, err := newNostrFan(skB, pubA, []string{relay})
	if err != nil {
		t.Fatal(err)
	}
	defer fb.Close()
	time.Sleep(700 * time.Millisecond) // let subscriptions settle

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Two offers, the newer one wins; then answer and ready both ways.
	if err := fa.send(sigMsg{Type: "offer", SDP: "o-old", Attempt: "a1"}); err != nil {
		t.Fatalf("send offer1: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := fa.send(sigMsg{Type: "offer", SDP: "o-new", Attempt: "a2"}); err != nil {
		t.Fatalf("send offer2: %v", err)
	}
	off, err := fb.recvCtx(ctx)
	if err != nil {
		t.Fatalf("responder recv: %v", err)
	}
	if off.Attempt != "a2" {
		t.Fatalf("responder did not pick the newest offer: %+v", off)
	}
	if err := fb.send(sigMsg{Type: "answer", SDP: "ans", Attempt: off.Attempt}); err != nil {
		t.Fatalf("send answer: %v", err)
	}
	ans, err := fa.recvCtx(ctx)
	if err != nil {
		t.Fatalf("initiator recv answer: %v", err)
	}
	if ans.Type != "answer" || ans.Attempt != "a2" || ans.SDP != "ans" {
		t.Fatalf("bad answer: %+v", ans)
	}
	if err := fa.send(sigMsg{Type: "ready", Attempt: "a2"}); err != nil {
		t.Fatal(err)
	}
	if err := fb.send(sigMsg{Type: "ready", Attempt: "a2"}); err != nil {
		t.Fatal(err)
	}
	if m, err := fb.recvCtx(ctx); err != nil || m.Type != "ready" {
		t.Fatalf("responder ready: %+v %v", m, err)
	}
	if m, err := fa.recvCtx(ctx); err != nil || m.Type != "ready" {
		t.Fatalf("initiator ready: %+v %v", m, err)
	}

	// A newer offer after adoption latches supersede on the responder,
	// from the ingest path — nobody is reading fb's channel here.
	if err := fa.send(sigMsg{Type: "offer", SDP: "o3", Attempt: "a3"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-fb.Superseded():
	case <-time.After(5 * time.Second):
		t.Fatal("supersede not latched after a newer offer")
	}
}

// TestNostrLiveE2E: a full exchange against the real public relays with
// throwaway keys. Doubles as a relay-health probe; opt-in:
//
//	CALLTUN_NOSTR_LIVE=1 go test -run TestNostrLiveE2E
func TestNostrLiveE2E(t *testing.T) {
	if os.Getenv("CALLTUN_NOSTR_LIVE") == "" {
		t.Skip("set CALLTUN_NOSTR_LIVE=1 to run against public relays")
	}
	skA := nostr.GeneratePrivateKey()
	skB := nostr.GeneratePrivateKey()
	pubA, _ := nostr.GetPublicKey(skA)
	pubB, _ := nostr.GetPublicKey(skB)
	relays := splitList(defaultNostrRelays)
	fa, err := newNostrFan(skA, pubB, relays)
	if err != nil {
		t.Fatal(err)
	}
	defer fa.Close()
	fb, err := newNostrFan(skB, pubA, relays)
	if err != nil {
		t.Fatal(err)
	}
	defer fb.Close()
	time.Sleep(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	attempt := newAttemptId()
	if err := fa.send(sigMsg{Type: "offer", SDP: "live-probe", Attempt: attempt}); err != nil {
		t.Fatalf("publish offer: %v", err)
	}
	off, err := fb.recvCtx(ctx)
	if err != nil {
		t.Fatalf("recv offer: %v", err)
	}
	if off.Attempt != attempt {
		t.Fatalf("attempt mismatch: %+v", off)
	}
	if err := fb.send(sigMsg{Type: "answer", SDP: "live-answer", Attempt: attempt}); err != nil {
		t.Fatalf("publish answer: %v", err)
	}
	ans, err := fa.recvCtx(ctx)
	if err != nil {
		t.Fatalf("recv answer: %v", err)
	}
	if ans.SDP != "live-answer" {
		t.Fatalf("bad answer: %+v", ans)
	}
}
