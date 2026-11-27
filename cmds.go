package main

// Subcommands. The signaling plane is deliberately decoupled from the link
// lifetime: after ICE connects and ready/ready is exchanged, the SSH session
// (up) / socket connection (accept) is closed and the daemons keep the link.
// Tor circuits die every few minutes; the link must not follow them.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	sigSessionTimeout = 60 * time.Second // whole offer/answer exchange
	sshTeardownWait   = 3 * time.Second
)

func cmdUp(ctx context.Context, args []string) error {
	fs := newFlagSet("up")
	var c commonFlags
	var nf nostrFlags
	var sshAlias, offerCmd, noIf, pinIf string
	registerCommon(fs, &c)
	nf.register(fs)
	fs.StringVar(&sshAlias, "ssh", "", "ssh destination (alias from ssh_config); xor with a destination in the trailing args")
	fs.StringVar(&offerCmd, "offer-cmd", "calltun", "remote calltun binary (path or command) for the offer bridge")
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on (default: --dev)")
	fs.StringVar(&pinIf, "if", "", "pin ICE candidates to these interfaces ONLY (overrides --no-if)")
	fs.Parse(args)
	// Everything after "--" goes to ssh verbatim (options and/or the
	// destination): -J hop, -p port, -i key, ProxyJump garlands.
	extraSSH := fs.Args()
	initLog(c.verbose)

	if err := checkSignalingFlags(&nf, sshAlias, extraSSH); err != nil {
		return err
	}
	name, tap, err := resolveDevice(&c)
	if err != nil {
		return err
	}
	if pins := pinnedIfaces(pinIf, name); containsStr(pins, name) {
		return fmt.Errorf("--if must not include the served device %s (media would loop into its own reader)", name)
	}
	lg.Info("calltun up starting", "link", c.link, "dev", name, "mode", modeName(tap),
		"ssh", sshAlias, "ssh_extra", len(extraSSH), "nostr", nf.peer != "", "forever", c.forever)

	// One run = attach + transport + exchange + tunnel; --forever reruns
	// the whole thing on any failure, mirroring the unit's Restart=
	// semantics without systemd (crash-only: a restart is a fresh session).
	runOnce := func() error {
		dev, err := attachTun(name, tap)
		if err != nil {
			return err
		}
		defer dev.Close()
		lg.Info("device attached", "dev", name)

		sess, teardown, err := openSignaling(&c, &nf, sshAlias, extraSSH, offerCmd)
		if err != nil {
			return err
		}
		p, err := initiatorSession(ctx, &c, sess, teardown, name, pinIf, excludedIfaces(noIf, name))
		if err != nil {
			return err
		}
		return runTunnel(ctx, p, dev)
	}
	if c.forever {
		return runForever(ctx, runOnce)
	}
	return runOnce()
}

// sshSignaling spawns the SSH signaling transport: the peer runs `offer`,
// a dumb stdio bridge to its accept daemon's unix socket. extraSSH args
// sit between our base options and the destination, so a full ssh garland
// (-J hop, -p, -i, ...) works; the destination may live there instead of
// --ssh. The returned teardown waits out (then kills) the ssh child.
func sshSignaling(c *commonFlags, sshAlias string, extraSSH []string, offerCmd string) (sigTransport, func(), error) {
	remoteCmd := fmt.Sprintf("%s offer --link %s", offerCmd, c.link)
	argv := []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=15"}
	argv = append(argv, extraSSH...)
	if sshAlias != "" {
		argv = append(argv, sshAlias)
	}
	argv = append(argv, remoteCmd)
	cmd := exec.Command("ssh", argv...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("spawn ssh: %w", err)
	}
	teardown := func() {
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(sshTeardownWait):
			_ = cmd.Process.Kill()
		}
	}
	return newSigConn(readWriteCloser{Reader: stdout, Writer: stdin, Closer: stdin}), teardown, nil
}

// checkSignalingFlags validates the transport selection shared by the
// initiator modes (up, exit): --nostr is xor with --ssh (or a destination in
// the trailing args), and one of them is mandatory.
func checkSignalingFlags(nf *nostrFlags, sshAlias string, extraSSH []string) error {
	if nf.peer != "" && (sshAlias != "" || len(extraSSH) > 0) {
		return fmt.Errorf("--nostr and --ssh are mutually exclusive")
	}
	if nf.peer == "" && sshAlias == "" && len(extraSSH) == 0 {
		return fmt.Errorf("--ssh (or --nostr) is required")
	}
	return nil
}

// openSignaling brings up the signaling transport the flags select: the
// nostr fan (--nostr), or an ssh child running the peer's offer bridge
// (--ssh and/or a destination in the trailing args). The returned teardown
// belongs to the caller (nil for nostr); the transport itself is closed by
// initiatorSession.
func openSignaling(c *commonFlags, nf *nostrFlags, sshAlias string, extraSSH []string, offerCmd string) (sigTransport, func(), error) {
	if nf.peer != "" {
		fan, err := nostrTransport(nf)
		if err != nil {
			return nil, nil, err
		}
		return fan, nil, nil
	}
	if c.link == "" {
		return nil, nil, fmt.Errorf("--link is required with ssh signaling: it names the peer's offer socket")
	}
	return sshSignaling(c, sshAlias, extraSSH, offerCmd)
}

// initiatorSession brings an initiator from zero to an established link:
// the peer is built, the offer/answer exchanged over the given transport,
// and the transport torn down. On success the returned peer has a live
// data plane and needs no signaling anymore.
func initiatorSession(ctx context.Context, c *commonFlags, sess sigTransport, teardown func(), dev, pinIf string, excluded []string) (*peer, error) {
	pins := pinnedIfaces(pinIf, dev)
	p, err := newPeer(stunServers(c.stun), excluded, pins)
	if err != nil {
		return nil, err
	}
	iceWait, err := time.ParseDuration(c.iceWait)
	if err != nil {
		return nil, fmt.Errorf("--ice-timeout: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, sigSessionTimeout+iceWait)
	defer cancel()

	sigErr := signalInitiator(sctx, sess, p)

	// Tear the signaling transport down regardless of the outcome; after a
	// successful exchange the link no longer needs it.
	sess.Close()
	if teardown != nil {
		teardown()
	}
	if sigErr != nil {
		return nil, fmt.Errorf("signaling: %w", sigErr)
	}
	lg.Info("signaling complete, transport closed")
	return p, nil
}

func cmdAccept(ctx context.Context, args []string) error {
	fs := newFlagSet("accept")
	var c commonFlags
	var nf nostrFlags
	var noIf, pinIf string
	registerCommon(fs, &c)
	nf.register(fs)
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on (default: --dev)")
	fs.StringVar(&pinIf, "if", "", "pin ICE candidates to these interfaces ONLY (overrides --no-if)")
	fs.Parse(args)
	initLog(c.verbose)

	name, tap, err := resolveDevice(&c)
	if err != nil {
		return err
	}
	if pins := pinnedIfaces(pinIf, name); containsStr(pins, name) {
		return fmt.Errorf("--if must not include the served device %s (media would loop into its own reader)", name)
	}
	lg.Info("calltun accept starting", "link", c.link, "dev", name, "mode", modeName(tap),
		"nostr", nf.peer != "", "forever", c.forever)

	// One run = attach + one signaling session + tunnel; --forever reruns
	// it on any failure, the in-process counterpart of the unit's
	// Restart= (crash-only: a restart is a fresh session).
	runOnce := func() error {
		dev, err := attachTun(name, tap)
		if err != nil {
			return err
		}
		defer dev.Close()
		lg.Info("device attached", "dev", name)

		pins := pinnedIfaces(pinIf, name)
		p, err := newPeer(stunServers(c.stun), excludedIfaces(noIf, name), pins)
		if err != nil {
			return err
		}
		iceWait, err := time.ParseDuration(c.iceWait)
		if err != nil {
			return fmt.Errorf("--ice-timeout: %w", err)
		}
		sctx, cancel := context.WithTimeout(ctx, sigSessionTimeout+iceWait)
		defer cancel()

		// Nostr transport: no local socket, no offer bridge — the daemon
		// itself watches the relay fan for an offer (one session per run,
		// crash-only, same as the socket path below). The idle wait for an
		// offer is unbounded (restarts are somebody else's job, exactly
		// like the ssh Accept below); the exchange deadline starts when an
		// offer lands.
		if nf.peer != "" {
			fan, err := nostrTransport(&nf)
			if err != nil {
				return err
			}
			lg.Info("waiting for signaling", "transport", "nostr")
			off, err := recvOffer(ctx, fan)
			if err != nil {
				fan.Close()
				return fmt.Errorf("signaling: %w", err)
			}
			xc, xcancel := context.WithTimeout(ctx, sigSessionTimeout+iceWait)
			defer xcancel()
			// A newer offer than the adopted one means the initiator moved
			// on — abort at once instead of burning the ICE wait on a zombie
			// exchange; the restart (systemd or --forever) answers the
			// fresh one.
			go func() {
				select {
				case <-fan.Superseded():
					lg.Warn("nostr: session superseded by a newer offer")
					xcancel()
				case <-xc.Done():
				}
			}()
			sigErr := responderExchange(xc, fan, p, off)
			fan.Close()
			if sigErr != nil {
				return fmt.Errorf("signaling: %w", sigErr)
			}
			lg.Info("signaling complete, fan closed")
			return runTunnel(ctx, p, dev)
		}

		// One signaling session per daemon life: a new link means a fresh unit
		// run (crash-only). Stale socket files from a previous run are removed.
		path := sockPath(c.link)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
		}
		_ = os.Remove(path)
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			return fmt.Errorf("listen %s: %w", path, err)
		}
		defer os.Remove(path)

		connCh := make(chan net.Conn, 1)
		errCh := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			// One session per daemon life (crash-only). Closing the listener
			// right away REFUSES later dialers instead of parking them in the
			// listen backlog where nobody would ever read them — a wedged
			// initiator then fails fast and systemd retries both ends.
			ln.Close()
			connCh <- conn
		}()
		lg.Info("waiting for signaling", "socket", path)

		var conn net.Conn
		select {
		case conn = <-connCh:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}

		sess := newSigConn(conn)
		sigErr := signalResponder(sctx, sess, p)
		sess.Close()
		if sigErr != nil {
			return fmt.Errorf("signaling: %w", sigErr)
		}
		lg.Info("signaling complete, session closed")

		return runTunnel(ctx, p, dev)
	}
	if c.forever {
		return runForever(ctx, runOnce)
	}
	return runOnce()
}

// runForever reruns fn until it returns nil or ctx is done — the
// in-process counterpart of the units' Restart=always (crash-only: every
// failure path is a fresh session, from device attach to tunnel). An
// external stop is a clean exit (exit code 0), same as under systemd;
// restartPause keeps a hard-failing fn from spinning hot.
func runForever(ctx context.Context, fn func() error) error {
	const restartPause = time.Second
	for attempt := 1; ; attempt++ {
		err := fn()
		if err == nil || ctx.Err() != nil {
			return nil
		}
		lg.Warn("run failed, restarting in place", "attempt", attempt, "err", err)
		select {
		case <-time.After(restartPause):
		case <-ctx.Done():
			return nil
		}
	}
}

func cmdOffer(ctx context.Context, args []string) error {
	fs := newFlagSet("offer")
	var link string
	fs.StringVar(&link, "link", "", "link name (must match the accept daemon)")
	fs.Parse(args)
	initLog(false)
	if link == "" {
		return fmt.Errorf("--link is required")
	}

	path := sockPath(link)
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fmt.Errorf("dial %s (accept daemon running?): %w", path, err)
	}
	defer conn.Close()

	// Dumb bridge: ssh stdio <-> accept daemon socket. Closing stdin (ssh
	// session teardown) ends us and unblocks the daemon's reader.
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, os.Stdin)
		conn.CloseWrite()
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(os.Stdout, conn)
		errCh <- err
	}()
	select {
	case err := <-errCh:
		if err != nil && err != io.EOF {
			return err
		}
		<-errCh // drain the second copier
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("calltun "+name, flag.ExitOnError)
	return fs
}

func modeName(tap bool) string {
	if tap {
		return "tap"
	}
	return "tun"
}

// readWriteCloser glues an ssh child's stdout (read) and stdin (write).
type readWriteCloser struct {
	io.Reader
	io.Writer
	io.Closer
}

// pinnedIfaces resolves the pin (allowlist): --if wins, CALLTUN_IF is
// the fallback. Pinning to the served device itself is refused — media
// would loop into our own reader.
func pinnedIfaces(flagVal, dev string) []string {
	list := splitList(flagVal)
	if len(list) == 0 {
		list = splitList(os.Getenv("CALLTUN_IF"))
	}
	return list
}

// excludedIfaces resolves the interface-exclusion list: --no-if wins,
// CALLTUN_NO_IF is the fallback (units set it via an EnvironmentFile),
// and the served device is always excluded last (exit has none).
func excludedIfaces(flagVal, dev string) []string {
	list := splitList(flagVal)
	if len(list) == 0 {
		list = splitList(os.Getenv("CALLTUN_NO_IF"))
	}
	// exit serves no device, hence the empty dev there.
	if dev != "" && !containsStr(list, dev) {
		list = append(list, dev)
	}
	return list
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
