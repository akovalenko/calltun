package cli

// nostr.go — the nostr signaling transport: the same sigMsg line-JSON
// (offer/answer/ready/abort) carried inside NIP-59 gift wraps (kind 1059)
// across a fan of public relays. On the wire this is indistinguishable
// from ordinary nostr DM traffic: the gift wrap is the standard carriage,
// and the inner rumor kind (21124, calltun signaling) is visible only to
// the configured peer — both sides know each other's key, which also
// authenticates the exchange (the seal inside a wrap is signed by the
// sender's real key and checked on unwrap).
//
// Relays never sync events with each other, so every message is published
// to ALL configured relays and read from whichever are alive; duplicates
// are dropped by rumor id. Store-and-forward buys short responder
// downtime: an offer waits on the relays, bounded by offerTTL — ICE
// candidates in a long-stale offer would be dead anyway.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
	"github.com/nbd-wtf/go-nostr/nip59"
)

const (
	// rumorKindSignal is the inner rumor kind. Anything in the application
	// range works — only the peer ever sees it; it is never published raw.
	rumorKindSignal = 21124

	// wrapBackdate: go-nostr's gift wrap backdates wraps and seals by
	// 60s*rand(0..600) — up to 10h (the lib's comment says "6 hours", the
	// math says 10; trust the math, verified live). The read filter must
	// reach that far back even for a fresh exchange, or randomly
	// backdated wraps get silently filtered out.
	wrapBackdate = 10*time.Hour + 5*time.Minute

	// offerTTL bounds how old a rumor may be to still be considered:
	// buffered offers older than this are dropped on ingest.
	offerTTL = 10 * time.Minute

	// offerSettle: when a responder's subscription backfills several
	// offers (an initiator's systemd retries pile up on the relays),
	// debounce — answer the newest after this much quiet since the LAST
	// offer, capped by offerSettleMax from the first.
	offerSettle    = 1500 * time.Millisecond
	offerSettleMax = 4 * time.Second

	// publishStraggler: once one relay has accepted, wait at most this
	// long for the rest before moving on — a dead relay in the fan must
	// not add its connect timeout to every publish.
	publishStraggler = 2 * time.Second

	publishTimeout  = 15 * time.Second
	relayBackoffMax = 30 * time.Second
	relayLiveReset  = time.Minute // connected this long -> backoff resets

	// Gift-wrap size gates: the strictest observed public relay
	// (purplerelay.com) rejects encrypted content over 8192 bytes.
	wrapContentMax  = 8192
	wrapContentWarn = 6000
)

// defaultNostrRelays — curated like the STUN list: free public relays
// that serve kind 1059 both ways without NIP-42 auth, verified live by
// an empirical probe (read EOSE + publish OK, throwaway keys) on
// 2026-11-24; relay.damus.io — down (503) that day. Candidates that
// also passed: nostr.mom, relay.noswhere.com. Override with --relays.
const defaultNostrRelays = "wss://relay.primal.net,wss://nos.lol,wss://purplerelay.com"

// nostrFlags carries the nostr transport flags, shared by up and accept.
// --nostr (the peer's key) selects the nostr transport; xor with --ssh.
type nostrFlags struct {
	peer    string // peer identity: npub or 64-hex pubkey
	keyFile string // our secret key file: hex or nsec, one line
	relays  string // comma list of wss URLs
}

func (n *nostrFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&n.peer, "nostr", "", "nostr signaling: peer key (npub or hex); selects the nostr transport instead of ssh")
	fs.StringVar(&n.keyFile, "nostr-key", "", "nostr signaling: our secret key file (hex or nsec, 0600)")
	fs.StringVar(&n.relays, "relays", defaultNostrRelays, "nostr signaling: comma list of relay URLs")
}

// fanEvent is one unwrapped, authenticated, deduplicated rumor from any
// relay in the fan, with its (honest, non-backdated) created_at.
type fanEvent struct {
	msg sigMsg
	at  time.Time
}

// nostrFan is a signaling transport over a fan of nostr relays. It
// implements the same send/recvCtx surface as sigConn, so the exchange
// logic in signal.go runs unmodified over either transport.
//
// Correlation between the two async store-and-forward halves is by the
// sigMsg Attempt field: the fan adopts an attempt id when it delivers an
// offer (responder) or sends one (initiator), and from then on recv only
// passes messages echoing that attempt — the nostr analogue of "messages
// on the same ssh stream".
type nostrFan struct {
	sk, pub string // our identity
	peer    string // peer pubkey, hex
	relays  []string

	events chan fanEvent
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu        sync.Mutex
	attempt   string              // "" until adopted; then the only attempt recv passes
	attemptAt time.Time           // created_at of the adopted offer
	seen      map[string]struct{} // rumor ids already ingested

	supersedeOnce sync.Once
	supersede     chan struct{} // closed when an offer NEWER than the adopted one arrives
}

func newNostrFan(sk, peer string, relays []string) (*nostrFan, error) {
	pub, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, fmt.Errorf("nostr key: %w", err)
	}
	f := &nostrFan{
		sk: sk, pub: pub, peer: peer, relays: relays,
		events:    make(chan fanEvent, 64),
		seen:      make(map[string]struct{}),
		supersede: make(chan struct{}),
	}
	f.ctx, f.cancel = context.WithCancel(context.Background())
	for _, url := range relays {
		f.wg.Add(1)
		go f.reader(url)
	}
	return f, nil
}

// reader keeps one subscription per relay alive for the fan's lifetime,
// reconnecting with capped exponential backoff (reset after a connection
// has stayed up for relayLiveReset).
func (f *nostrFan) reader(url string) {
	defer f.wg.Done()
	backoff := 2 * time.Second
	for f.ctx.Err() == nil {
		lived, err := f.readOnce(url)
		if f.ctx.Err() != nil {
			return
		}
		if lived >= relayLiveReset {
			backoff = 2 * time.Second
		}
		lg.Warn("nostr relay reader stopped, retrying", "relay", url, "err", err, "backoff", backoff)
		select {
		case <-time.After(backoff):
		case <-f.ctx.Done():
			return
		}
		if backoff < relayBackoffMax {
			backoff *= 2
			if backoff > relayBackoffMax {
				backoff = relayBackoffMax
			}
		}
	}
}

// readOnce serves one connection lifetime; returns how long the
// connection lasted and why it ended.
func (f *nostrFan) readOnce(url string) (time.Duration, error) {
	start := time.Now()
	r, err := nostr.RelayConnect(f.ctx, url)
	if err != nil {
		return 0, fmt.Errorf("connect: %w", err)
	}
	since := nostr.Timestamp(time.Now().Add(-wrapBackdate).Unix())
	sub, err := r.Subscribe(f.ctx, nostr.Filters{{
		Kinds: []int{nostr.KindGiftWrap},
		Tags:  nostr.TagMap{"p": []string{f.pub}},
		Since: &since,
	}})
	if err != nil {
		return time.Since(start), fmt.Errorf("subscribe: %w", err)
	}
	for {
		select {
		case ev, ok := <-sub.Events:
			if !ok {
				return time.Since(start), fmt.Errorf("subscription ended")
			}
			lg.Debug("nostr: event from relay", "relay", url, "id", ev.ID)
			if fe, drop := f.ingest(ev); !drop {
				select {
				case f.events <- fe:
				case <-f.ctx.Done():
					return time.Since(start), f.ctx.Err()
				}
			}
		case <-f.ctx.Done():
			return time.Since(start), f.ctx.Err()
		}
	}
}

// ingest unwraps a gift wrap and decides whether it enters the channel.
// Anything not decryptable by us, not from our peer, not our rumor kind,
// duplicated, stale or unparsable is dropped (debug log) — the fan must
// never hand the exchange logic anything but a clean, current,
// peer-authenticated message.
func (f *nostrFan) ingest(ev *nostr.Event) (fe fanEvent, drop bool) {
	decrypt := func(other, ciphertext string) (string, error) {
		ck, err := nip44.GenerateConversationKey(other, f.sk)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ciphertext, ck)
	}
	rumor, err := nip59.GiftUnwrap(*ev, decrypt)
	if err != nil {
		lg.Debug("nostr: wrap not for us / bad", "err", err)
		return fe, true
	}
	if rumor.PubKey != f.peer {
		lg.Debug("nostr: rumor from non-peer key, dropped", "from", rumor.PubKey)
		return fe, true
	}
	if rumor.Kind != rumorKindSignal {
		lg.Debug("nostr: rumor kind is not signaling", "kind", rumor.Kind)
		return fe, true
	}
	f.mu.Lock()
	if _, dup := f.seen[rumor.ID]; dup {
		f.mu.Unlock()
		return fe, true
	}
	f.seen[rumor.ID] = struct{}{}
	f.mu.Unlock()
	if age := time.Since(rumor.CreatedAt.Time()); age > offerTTL {
		lg.Debug("nostr: rumor past TTL, dropped", "age", age)
		return fe, true
	}
	var m sigMsg
	if err := json.Unmarshal([]byte(rumor.Content), &m); err != nil {
		lg.Debug("nostr: rumor content not a signaling message", "err", err)
		return fe, true
	}
	fe = fanEvent{msg: m, at: rumor.CreatedAt.Time()}
	// Supersede detection lives here, not in recvEvent: during the ICE
	// wait nobody reads the channel, so a newer offer must raise the
	// signal from the reader path. An offer from the peer newer than the
	// one we adopted means the initiator has moved on — our session is a
	// zombie; the caller aborts and the restart answers the fresh one.
	f.mu.Lock()
	adopted, adoptedAt := f.attempt, f.attemptAt
	f.mu.Unlock()
	if adopted != "" && m.Type == "offer" && !fe.at.Before(adoptedAt) {
		f.markSuperseded()
		lg.Warn("nostr: newer offer arrived, session superseded", "attempt", m.Attempt)
	}
	return fe, false
}

// wrapSignal gift-wraps a signaling message addressed to the peer; the
// rumor carries an honest created_at (NIP-59 backdates only the seal and
// the wrap). Split out of send for tests.
func wrapSignal(sk, peer string, m sigMsg, at time.Time) (nostr.Event, error) {
	content, err := json.Marshal(m)
	if err != nil {
		return nostr.Event{}, err
	}
	rumor := nostr.Event{
		Kind:      rumorKindSignal,
		Content:   string(content),
		CreatedAt: nostr.Timestamp(at.Unix()),
		Tags:      nostr.Tags{nostr.Tag{"p", peer}},
	}
	encrypt := func(plaintext string) (string, error) {
		ck, err := nip44.GenerateConversationKey(peer, sk)
		if err != nil {
			return "", err
		}
		return nip44.Encrypt(plaintext, ck)
	}
	sign := func(ev *nostr.Event) error { return ev.Sign(sk) }
	return nip59.GiftWrap(rumor, peer, encrypt, sign, nil)
}

// send wraps and publishes m to every relay; at least one must accept.
func (f *nostrFan) send(m sigMsg) error {
	wrap, err := wrapSignal(f.sk, f.peer, m, nostr.Now().Time())
	if err != nil {
		return fmt.Errorf("gift wrap: %w", err)
	}

	// Gift-wrap size gate, the MTU-gate philosophy at the signaling layer:
	// a many-interface host gathers a candidate per interface, the SDP
	// bloats, and the strictest public relays reject oversized encrypted
	// content outright (purplerelay: 8192 bytes, observed live) — while a
	// multi-KB "DM" is also a fingerprint among ordinary ones. Fail loudly
	// with the fix (--if) instead of proceeding fragile; warn earlier.
	cands := strings.Count(m.SDP, "a=candidate:")
	if n := len(wrap.Content); n > wrapContentMax {
		return fmt.Errorf("gift wrap is %d bytes, over the relay limit %d (%s: %d ICE candidates) — pin --if to fewer interfaces",
			n, wrapContentMax, m.Type, cands)
	}
	if n := len(wrap.Content); n > wrapContentWarn {
		lg.Warn("nostr: large gift wrap", "bytes", n, "candidates", cands,
			"hint", "pin --if to fewer interfaces to stay small")
	}
	lg.Debug("nostr: wrap built", "bytes", len(wrap.Content), "candidates", cands, "type", m.Type)

	if m.Type == "offer" {
		// A re-offer is a new exchange: the fan follows the LATEST attempt
		// it sent. Normally one offer per process (crash-only), but the
		// fan stays correct if reused across attempts.
		f.setAttempt(m.Attempt, nostr.Now().Time())
	}

	fanCtx, cancel := context.WithTimeout(context.Background(), publishTimeout)
	defer cancel()
	type res struct {
		url string
		err error
	}
	resCh := make(chan res, len(f.relays))
	for _, url := range f.relays {
		go func(url string) {
			r, err := nostr.RelayConnect(fanCtx, url)
			if err != nil {
				resCh <- res{url, fmt.Errorf("connect: %w", err)}
				return
			}
			if err := r.Publish(fanCtx, wrap); err != nil {
				resCh <- res{url, fmt.Errorf("publish: %w", err)}
				return
			}
			resCh <- res{url, nil}
		}(url)
	}
	var lastErr error
	accepted, done := 0, 0
	// Once one relay has accepted, wait at most publishStraggler for the
	// rest — a dead relay must not add its connect timeout to every
	// publish while the exchange is already provably delivered.
	straggler := time.NewTimer(time.Hour)
	if !straggler.Stop() {
		<-straggler.C
	}
	defer straggler.Stop()
	for done < len(f.relays) {
		select {
		case r := <-resCh:
			done++
			if r.err != nil {
				lg.Warn("nostr publish failed", "relay", r.url, "err", r.err)
				lastErr = r.err
			} else {
				if accepted == 0 {
					straggler.Reset(publishStraggler)
				}
				accepted++
			}
		case <-straggler.C:
			lg.Debug("nostr publish: moving on (first accept + grace)",
				"accepted", accepted, "of", len(f.relays))
			return nil
		}
	}
	if accepted == 0 {
		return fmt.Errorf("nostr: no relay accepted the %s: %v", m.Type, lastErr)
	}
	lg.Debug("nostr published", "type", m.Type, "relays_ok", accepted, "of", len(f.relays))
	return nil
}

// recvCtx hands the exchange the next relevant message, honoring ctx.
func (f *nostrFan) recvCtx(ctx context.Context) (sigMsg, error) {
	fe, err := f.recvEvent(ctx)
	if err != nil {
		return sigMsg{}, err
	}
	return fe.msg, nil
}

// recvEvent implements the fan's correlation policy on the merged event
// channel:
//   - before an attempt is adopted (responder side), offers are
//     debounced — the newest is delivered after a short quiet window
//     since the LAST offer (capped from the first): a responder coming
//     back online finds the initiator's whole retry pile on the relays
//     and must answer the live attempt, not an arbitrary old one;
//   - afterwards, only messages echoing the adopted attempt pass (the
//     initiator's answer/abort, the responder's ready); an offer NEWER
//     than the adopted one raises the supersede signal instead — the
//     initiator has moved on, the current session is a zombie.
func (f *nostrFan) recvEvent(ctx context.Context) (fanEvent, error) {
	if f.currentAttempt() != "" {
		adoptedAt := f.attemptTime()
		for {
			select {
			case fe := <-f.events:
				if fe.msg.Attempt == f.currentAttempt() {
					return fe, nil
				}
				if fe.msg.Type == "offer" && !fe.at.Before(adoptedAt) {
					f.markSuperseded()
					lg.Warn("nostr: newer offer arrived, session superseded", "attempt", fe.msg.Attempt)
					return fanEvent{}, fmt.Errorf("superseded by newer offer")
				}
				lg.Debug("nostr: message for another attempt, dropped", "type", fe.msg.Type)
			case <-ctx.Done():
				return fanEvent{}, ctx.Err()
			case <-f.ctx.Done():
				return fanEvent{}, fmt.Errorf("nostr fan shut down")
			}
		}
	}
	// Responder awaiting an offer: debounce for the newest.
	var best *fanEvent
	settle := time.NewTimer(time.Hour)
	if !settle.Stop() {
		<-settle.C
	}
	defer settle.Stop()
	var first time.Time
	for {
		select {
		case fe := <-f.events:
			if fe.msg.Type != "offer" {
				lg.Debug("nostr: non-offer before any offer, dropped", "type", fe.msg.Type)
				continue
			}
			if best == nil {
				first = time.Now()
			} else if time.Since(first) >= offerSettleMax {
				// cap reached: take this last (newest) one and go
				if !fe.at.Before(best.at) {
					best = &fe
				}
				f.adoptOffer(best)
				return *best, nil
			}
			// Debounce: restart the quiet window on every offer, so a
			// live offer arriving right after the backfill is included;
			// the cap bounds the total wait from the first offer.
			settle.Reset(offerSettle)
			// Newest wins, with arrival order breaking same-second ties
			// (nostr timestamps are second-granular; a later arrival from
			// the subscription is the later publication).
			if best == nil || !fe.at.Before(best.at) {
				best = &fe
			}
		case <-settle.C:
			if best != nil {
				f.adoptOffer(best)
				return *best, nil
			}
		case <-ctx.Done():
			return fanEvent{}, ctx.Err()
		case <-f.ctx.Done():
			return fanEvent{}, fmt.Errorf("nostr fan shut down")
		}
	}
}

func (f *nostrFan) currentAttempt() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attempt
}

func (f *nostrFan) attemptTime() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.attemptAt
}

// adoptOffer adopts the settled offer's attempt as the current exchange.
func (f *nostrFan) adoptOffer(best *fanEvent) {
	f.mu.Lock()
	f.attempt = best.msg.Attempt
	f.attemptAt = best.at
	f.mu.Unlock()
}

// markSuperseded latches the supersede signal (idempotent).
func (f *nostrFan) markSuperseded() {
	f.supersedeOnce.Do(func() { close(f.supersede) })
}

// Superseded fires when an offer newer than the adopted one arrives —
// the caller should abort the session promptly: answering the zombie
// burns a full ICE wait for nothing, the restart answers the fresh one.
func (f *nostrFan) Superseded() <-chan struct{} { return f.supersede }

func (f *nostrFan) adopt(attempt string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attempt == "" && attempt != "" {
		f.attempt = attempt
	}
}

// setAttempt overwrites the correlation attempt (a re-offer supersedes),
// stamping the new exchange's offer time for supersede comparison.
func (f *nostrFan) setAttempt(attempt string, at time.Time) {
	if attempt == "" {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.attempt = attempt
	f.attemptAt = at
}

func (f *nostrFan) Close() error {
	f.cancel()
	f.wg.Wait()
	return nil
}

// --- keys, flags, wiring helpers ---

// parseNostrIdentity maps npub/nsec bech32 or plain hex to hex.
func parseNostrIdentity(s string) (string, error) {
	s = strings.TrimSpace(s)
	if prefix, data, err := nip19.Decode(s); err == nil {
		switch prefix {
		case "npub", "nsec":
			switch v := data.(type) {
			case string:
				return v, nil
			case []byte:
				return hex.EncodeToString(v), nil
			}
		}
		return "", fmt.Errorf("unexpected bech32 prefix %q", prefix)
	}
	if len(s) == 64 && isHex(s) {
		return s, nil
	}
	return "", fmt.Errorf("not an npub/nsec/hex key")
}

func isHex(s string) bool {
	_, err := hex.DecodeString(s)
	return err == nil
}

// loadNostrKey reads our secret key: hex or nsec, one line, 0600 advised.
func loadNostrKey(path string) (sk string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sk, err = parseNostrIdentity(strings.TrimSpace(string(b)))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	if pub, err := nostr.GetPublicKey(sk); err != nil || pub == "" {
		return "", fmt.Errorf("%s: not a valid secret key", path)
	}
	return sk, nil
}

// newAttemptId mints a random signaling attempt id.
func newAttemptId() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err) // crypto/rand failure is unrecoverable here
	}
	return hex.EncodeToString(b[:])
}

// nostrTransport validates the flags and builds the fan.
func nostrTransport(nf *nostrFlags) (*nostrFan, error) {
	if nf.peer == "" {
		return nil, fmt.Errorf("--nostr (peer key) is required for the nostr transport")
	}
	if nf.keyFile == "" {
		return nil, fmt.Errorf("--nostr-key is required with --nostr")
	}
	peer, err := parseNostrIdentity(nf.peer)
	if err != nil {
		return nil, fmt.Errorf("--nostr: %w", err)
	}
	sk, err := loadNostrKey(nf.keyFile)
	if err != nil {
		return nil, err
	}
	relays := splitList(nf.relays)
	if len(relays) == 0 {
		relays = splitList(defaultNostrRelays)
	}
	fan, err := newNostrFan(sk, peer, relays)
	if err != nil {
		return nil, err
	}
	pub, _ := nostr.GetPublicKey(sk)
	lg.Info("nostr signaling fan up", "pub", pub, "peer", peer, "relays", len(relays))
	return fan, nil
}

// cmdNostrKeygen mints a nostr identity for a link endpoint: writes the
// secret (hex, 0600) to the given path and prints npub/nsec.
func cmdNostrKeygen(ctx context.Context, args []string) error {
	if len(args) != 1 || args[0] == "" {
		return fmt.Errorf("usage: calltun nostr-keygen <keyfile>")
	}
	path := args[0]
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	sk := nostr.GeneratePrivateKey()
	if err := os.WriteFile(path, []byte(sk+"\n"), 0o600); err != nil {
		return err
	}
	pub, err := nostr.GetPublicKey(sk)
	if err != nil {
		return err
	}
	npub, _ := nip19.EncodePublicKey(pub)
	nsec, _ := nip19.EncodePrivateKey(sk)
	fmt.Printf("secret: %s\n", nsec)
	fmt.Printf("pub:   %s (%s)\n", npub, pub)
	return nil
}
