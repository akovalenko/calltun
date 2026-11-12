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
	var sshAlias, offerCmd, noIf string
	registerCommon(fs, &c)
	fs.StringVar(&sshAlias, "ssh", "", "ssh destination (alias from ssh_config); required")
	fs.StringVar(&offerCmd, "offer-cmd", "calltun", "remote calltun binary (path or command) for the offer bridge")
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on (default: --dev)")
	fs.Parse(args)
	initLog(c.verbose)

	if sshAlias == "" {
		return fmt.Errorf("--ssh is required")
	}
	name, tap, err := resolveDevice(&c)
	if err != nil {
		return err
	}
	lg.Info("calltun up starting", "link", c.link, "dev", name, "mode", modeName(tap), "ssh", sshAlias)

	dev, err := attachDevice(name, tap)
	if err != nil {
		return err
	}
	defer dev.Close()
	lg.Info("device attached", "dev", name)

	excluded := excludedIfaces(noIf, name)
	p, err := newPeer(stunURLs(c.stun), excluded)
	if err != nil {
		return err
	}
	iceWait, err := time.ParseDuration(c.iceWait)
	if err != nil {
		return fmt.Errorf("--ice-timeout: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, sigSessionTimeout+iceWait)
	defer cancel()

	// Spawn the SSH signaling transport: the peer runs `offer`, a dumb
	// stdio bridge to its accept daemon's unix socket.
	remoteCmd := fmt.Sprintf("%s offer --link %s", offerCmd, c.link)
	cmd := exec.Command("ssh",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=15",
		sshAlias, remoteCmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("spawn ssh %s: %w", sshAlias, err)
	}

	sess := newSigConn(readWriteCloser{Reader: stdout, Writer: stdin, Closer: stdin})
	sigErr := signalInitiator(sctx, sess, p)

	// Tear the signaling transport down regardless of the outcome; after a
	// successful exchange the link no longer needs it.
	sess.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(sshTeardownWait):
		_ = cmd.Process.Kill()
	}
	if sigErr != nil {
		return fmt.Errorf("signaling: %w", sigErr)
	}
	lg.Info("signaling complete, ssh transport closed")

	return runTunnel(ctx, p, dev)
}

func cmdAccept(ctx context.Context, args []string) error {
	fs := newFlagSet("accept")
	var c commonFlags
	var noIf string
	registerCommon(fs, &c)
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on (default: --dev)")
	fs.Parse(args)
	initLog(c.verbose)

	name, tap, err := resolveDevice(&c)
	if err != nil {
		return err
	}
	lg.Info("calltun accept starting", "link", c.link, "dev", name, "mode", modeName(tap))

	dev, err := attachDevice(name, tap)
	if err != nil {
		return err
	}
	defer dev.Close()
	lg.Info("device attached", "dev", name)

	excluded := excludedIfaces(noIf, name)
	p, err := newPeer(stunURLs(c.stun), excluded)
	if err != nil {
		return err
	}
	iceWait, err := time.ParseDuration(c.iceWait)
	if err != nil {
		return fmt.Errorf("--ice-timeout: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, sigSessionTimeout+iceWait)
	defer cancel()

	// One signaling session per daemon life: a new link means a fresh unit
	// run (crash-only). Stale socket files from a previous run are removed.
	path := sockPath(c.link)
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

// excludedIfaces resolves the interface-exclusion list: --no-if wins,
// CALLTUN_NO_IF is the fallback (units set it via an EnvironmentFile),
// and the served device is always excluded last.
func excludedIfaces(flagVal, dev string) []string {
	list := splitList(flagVal)
	if len(list) == 0 {
		list = splitList(os.Getenv("CALLTUN_NO_IF"))
	}
	if !containsStr(list, dev) {
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
