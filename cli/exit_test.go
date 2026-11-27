//go:build userspace

package cli

// exit_test.go — in-process end-to-end for exit mode, without root or a
// TUN. The peer's applications are played by a second gVisor stack (in
// production a stock accept behind a TUN), linked to the exit over a real
// PeerConnection on loopback; signaling rides a loopback TCP pair where ssh
// or nostr would be. The exit side runs exitSession — what cmdExit runs per
// attempt — so "--forever: one session after another in one process" is the
// same code here.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const (
	exitAddr     = "10.187.52.19" // the exit's address inside the link
	peerAddr     = "10.187.52.18" // the peer's address inside the link
	fakeHost     = "10.9.9.9"     // where the peer's applications connect
	linkUpWait   = 30 * time.Second
	ioWait       = 60 * time.Second
	deadLinkWait = 60 * time.Second // for the exit to give up on a vanished peer
)

// newPeerStack builds the opposite end of the link for the test: a plain
// stack with one address and a default route through the channel NIC, so
// that its applications' packets come out as frames and return frames are
// delivered back to them. The frame plumbing is exitStack's.
func newPeerStack(ctx context.Context, addr string) (*exitStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(maxFrame), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, toErr(err)
	}
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(net.ParseIP(addr).To4()),
			PrefixLen: 32,
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, toErr(err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return &exitStack{ep: ep, s: s, ctx: ctx}, nil
}

// useLoopbackDial aims the exit's real dials at the loopback: a sandbox has
// nowhere else to dial. The netstack drops loopback destinations on
// arrival, so the applications connect to fakeHost instead; the port is kept.
func useLoopbackDial(t *testing.T) {
	t.Helper()
	old := exitDial
	exitDial = func(network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return net.DialTimeout(network, net.JoinHostPort("127.0.0.1", port), dialTimeout)
	}
	t.Cleanup(func() { exitDial = old })
}

func portOf(t *testing.T, addr string) uint16 {
	t.Helper()
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return uint16(n)
}

// serveEcho starts a real echo server on the loopback the exit dials into,
// and returns the port it listens on.
func serveEcho(t *testing.T, network string) uint16 {
	t.Helper()
	var addr string
	switch network {
	case "tcp":
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				go func() { defer c.Close(); io.Copy(c, c) }()
			}
		}()
		addr = l.Addr().String()
	case "udp":
		c, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		go func() {
			buf := make([]byte, 65536)
			for {
				n, from, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				c.WriteTo(buf[:n], from)
			}
		}()
		addr = c.LocalAddr().String()
	default:
		t.Fatalf("unsupported network %q", network)
	}
	return portOf(t, addr)
}

// serveAfterFin is a server that answers only once the client has finished
// sending: it reads up to the FIN, then reports how much came before it.
func serveAfterFin(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		data, err := io.ReadAll(c)
		if err != nil {
			fmt.Fprintf(c, "read error after %d bytes: %v", len(data), err)
			return
		}
		fmt.Fprintf(c, "read %d bytes up to the FIN", len(data))
	}()
	return portOf(t, l.Addr().String())
}

// peerSide is the stock responder end of the in-memory link: a peer with a
// plain stack, where the tests' applications play.
type peerSide struct {
	pc   *peer
	dev  *exitStack
	errs chan error
}

func startPeerSide(ctx context.Context) (*peerSide, error) {
	pc, err := newPeer(nil, nil, nil)
	if err != nil {
		return nil, err
	}
	dev, err := newPeerStack(ctx, peerAddr)
	if err != nil {
		pc.release()
		return nil, err
	}
	return &peerSide{pc: pc, dev: dev, errs: make(chan error, 1)}, nil
}

// serve answers the exchange, then runs the tunnel until the link dies;
// the outcome lands on errs.
func (ps *peerSide) serve(ctx context.Context, sig sigTransport) {
	err := signalResponder(ctx, sig, ps.pc)
	if err == nil {
		err = runTunnel(ctx, ps.pc, ps.dev)
	}
	ps.errs <- err
}

func (ps *peerSide) close() {
	ps.pc.release()
	ps.dev.Close()
}

// duplexPair is the signaling channel's stand-in: a loopback TCP pair, with
// buffering in both directions. net.Pipe would do if signaling were strictly
// half-duplex, but the ready/ready handshake writes both ways at once and a
// synchronous pipe deadlocks on it.
func duplexPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	dialed := make(chan error, 1)
	var client net.Conn
	go func() {
		c, err := net.Dial("tcp", l.Addr().String())
		client = c
		dialed <- err
	}()
	server, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if err := <-dialed; err != nil {
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close(); client.Close() })
	return server, client
}

// startExitLink runs one exit session — what cmdExit runs per attempt —
// against a fresh peer, signaling over a loopback duplex pair. It returns
// the peer (its stack is where the tests' applications connect) and the
// channel the exit session ends in.
func startExitLink(t *testing.T, ctx context.Context) (*peerSide, <-chan error) {
	t.Helper()
	ps, err := startPeerSide(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ps.close)
	exitSig, peerSig := duplexPair(t)
	go ps.serve(ctx, newSigConn(peerSig))

	exitErr := make(chan error, 1)
	go func() {
		// The flag defaults as cmdExit would have them (stun none: loopback
		// candidates only).
		exitErr <- exitSession(ctx, &commonFlags{stun: "none", iceWait: "30s"}, newSigConn(exitSig), nil, exitAddr, "", nil)
	}()
	return ps, exitErr
}

// dialThrough polls a TCP connect through the link until it comes up —
// until the remote track binds, frames are simply dropped. A link that ends
// first fails the test.
func dialThrough(t *testing.T, ctx context.Context, dev *exitStack, port uint16, linkErrs ...<-chan error) *gonet.TCPConn {
	t.Helper()
	dst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP(fakeHost).To4()), Port: port}
	for deadline := time.Now().Add(linkUpWait); ; {
		dctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := gonet.DialContextTCP(dctx, dev.s, dst, ipv4.ProtocolNumber)
		cancel()
		if err == nil {
			return conn
		}
		for _, ch := range linkErrs {
			select {
			case e := <-ch:
				t.Fatalf("link ended: %v", e)
			default:
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("link did not come up: %v", err)
		}
	}
}

func TestExitEndToEnd(t *testing.T) {
	testLog()
	useLoopbackOnly(t)
	useLoopbackDial(t)
	tcpPort := serveEcho(t, "tcp")
	udpPort := serveEcho(t, "udp")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ps, exitErr := startExitLink(t, ctx)
	peerErr := ps.errs

	// TCP: 1 MiB both ways through the exit. The size matters: with the
	// unbounded-read bug (see nsStream.readStep) anything from a few hundred
	// KiB up hangs a flow almost surely, while small payloads slip through.
	conn := dialThrough(t, ctx, ps.dev, tcpPort, exitErr, peerErr)
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(ioWait)); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1024<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		writeErr <- err
	}()
	got := make([]byte, len(payload))
	if n, err := io.ReadFull(conn, got); err != nil {
		// How much arrived is the first question when a flow stalls short.
		t.Fatalf("tcp echo through the exit: %v after %d of %d bytes", err, n, len(payload))
	}
	if err := <-writeErr; err != nil {
		t.Fatalf("tcp write through the exit: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("tcp payload corrupted through the exit")
	}

	// UDP: three datagrams through the exit's session NAT, the last one
	// close to the frame budget.
	udpDst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP(fakeHost).To4()), Port: udpPort}
	udpConn, err := gonet.DialUDP(ps.dev.s, nil, &udpDst, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udpConn.Close() })
	for _, n := range []int{64, 1000, 1300} {
		msg := make([]byte, n)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		if err := udpConn.SetReadDeadline(time.Now().Add(ioWait)); err != nil {
			t.Fatal(err)
		}
		if _, err := udpConn.Write(msg); err != nil {
			t.Fatalf("udp write (%d bytes) through the exit: %v", n, err)
		}
		got := make([]byte, n)
		m, err := udpConn.Read(got)
		if err != nil {
			t.Fatalf("udp echo (%d bytes) through the exit: %v", n, err)
		}
		if !bytes.Equal(got[:m], msg) {
			t.Fatalf("udp payload (%d bytes) corrupted through the exit", n)
		}
	}

	for _, ch := range []<-chan error{exitErr, peerErr} {
		select {
		case err := <-ch:
			t.Fatalf("link ended: %v", err)
		default:
		}
	}
}

// A request ended with a FIN must still get its reply: the server here
// answers only after the client has said "no more data". Closing the real
// connection whole on the first finished direction used to cut such
// replies off.
func TestExitHalfClose(t *testing.T) {
	testLog()
	useLoopbackOnly(t)
	useLoopbackDial(t)
	port := serveAfterFin(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ps, exitErr := startExitLink(t, ctx)

	conn := dialThrough(t, ctx, ps.dev, port, exitErr, ps.errs)
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(ioWait)); err != nil {
		t.Fatal(err)
	}
	request := bytes.Repeat([]byte("the request, then a FIN\n"), 3000)
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("request through the exit: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("half-close into the link: %v", err)
	}
	reply, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reply after the FIN: %v", err)
	}
	if want := fmt.Sprintf("read %d bytes up to the FIN", len(request)); string(reply) != want {
		t.Fatalf("reply after the FIN:\n  got  %q\n  want %q", reply, want)
	}
}

// --forever reruns the exit session in place; nothing of a finished run
// may survive into the next one. Each restart carries a round trip, and
// the goroutine count returns to its baseline (an unreleased
// PeerConnection alone keeps 12).
func TestExitRestartsInPlace(t *testing.T) {
	testLog()
	useLoopbackOnly(t)
	useLoopbackDial(t)
	port := serveEcho(t, "tcp")

	// Warm-up: whatever pion and the netstack start globally is running,
	// so the baseline below is the steady state.
	t.Run("warm-up", func(t *testing.T) { restartExit(t, port, false) })
	counted := func() int {
		time.Sleep(2 * time.Second)
		runtime.GC()
		return runtime.NumGoroutine()
	}
	before := counted()

	// The last run ends the way --forever cares about: the peer vanishes,
	// the exit notices on its own and fails; the others are stopped from
	// outside.
	const restarts = 3
	for i := 0; i < restarts; i++ {
		t.Run(fmt.Sprintf("restart-%d", i), func(t *testing.T) {
			restartExit(t, port, i == restarts-1)
		})
	}

	after := counted()
	if leaked := after - before; leaked >= 12 {
		t.Fatalf("%d goroutines leaked over %d restarts (before %d, after %d)", leaked, restarts, before, after)
	}
}

// restartExit runs one exit session against a fresh peer, checks a round
// trip through it, then ends it.
func restartExit(t *testing.T, port uint16, deadLink bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ps, exitErr := startExitLink(t, ctx)

	conn := dialThrough(t, ctx, ps.dev, port, exitErr, ps.errs)
	msg := bytes.Repeat([]byte("still here after the restart\n"), 2400)
	if err := conn.SetDeadline(time.Now().Add(ioWait)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write through the restarted exit: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("echo through the restarted exit: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("payload corrupted through the restarted exit")
	}
	conn.Close()

	if deadLink {
		ps.pc.release() // the peer is gone
		select {
		case err := <-exitErr:
			if err == nil {
				t.Fatal("a dead link must end the exit session with an error")
			}
		case <-time.After(deadLinkWait):
			t.Fatal("the exit did not give up on the vanished peer")
		}
		return
	}
	select {
	case err := <-exitErr:
		t.Fatalf("exit session ended early: %v", err)
	default:
	}
	cancel()
	select {
	case <-exitErr:
	case <-time.After(10 * time.Second):
		t.Fatal("exit session did not stop on cancel")
	}
}
