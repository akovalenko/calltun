//go:build userspace

package main

// exit_test.go — in-process end-to-end for exit mode, without root or a TUN.
// The peer's applications are played by a second gVisor stack (in production
// a stock accept behind a TUN), linked to the exit stack over a real
// PeerConnection on loopback; signaling rides an in-memory pipe where ssh or
// nostr would be. TCP and UDP flows must terminate at the exit and
// re-originate as real dials to their destinations.

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
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
	exitAddr   = "10.187.52.19" // the exit's address inside the link
	peerAddr   = "10.187.52.18" // the peer's address inside the link
	fakeHost   = "10.9.9.9"     // where the peer's applications connect
	linkUpWait = 30 * time.Second
	ioWait     = 60 * time.Second
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

func TestExitEndToEnd(t *testing.T) {
	initLog(true)
	oldHook := settingHook
	settingHook = func(se *webrtc.SettingEngine) {
		// A sandbox has only loopback, and the default configuration hides
		// it from ICE: gather there, and nowhere else.
		se.SetIncludeLoopbackCandidate(true)
		se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
		se.SetInterfaceFilter(func(name string) bool { return name == "lo" })
	}
	t.Cleanup(func() { settingHook = oldHook })

	// The applications connect to a non-loopback address: the netstack drops
	// loopback destinations on arrival. The real dials land on the loopback
	// echo servers — in a sandbox there is nowhere else to dial.
	tcpPort := serveEcho(t, "tcp")
	udpPort := serveEcho(t, "udp")
	oldDial := exitDial
	exitDial = func(network, addr string) (net.Conn, error) {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		return net.DialTimeout(network, net.JoinHostPort("127.0.0.1", port), dialTimeout)
	}
	t.Cleanup(func() { exitDial = oldDial })

	ctx, cancel := context.WithCancel(context.Background())
	exitSide, err := newPeer(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	peerSide, err := newPeer(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	exitDev, err := newExitStack(ctx, exitAddr)
	if err != nil {
		t.Fatal(err)
	}
	peerDev, err := newPeerStack(ctx, peerAddr)
	if err != nil {
		t.Fatal(err)
	}
	sigExit, sigPeer := net.Pipe()
	defer func() {
		cancel()
		exitSide.pc.Close()
		peerSide.pc.Close()
		sigExit.Close()
		sigPeer.Close()
		exitDev.Close()
		peerDev.Close()
	}()

	go signalResponder(ctx, newSigConn(sigExit), exitSide)
	go signalInitiator(ctx, newSigConn(sigPeer), peerSide)
	errCh := make(chan error, 2)
	go func() { errCh <- runTunnel(ctx, exitSide, exitDev) }()
	go func() { errCh <- runTunnel(ctx, peerSide, peerDev) }()

	// Bring-up: poll a TCP connect through the link — until the remote track
	// binds, frames are simply dropped.
	tcpDst := tcpip.FullAddress{Addr: tcpip.AddrFromSlice(net.ParseIP(fakeHost).To4()), Port: tcpPort}
	var conn *gonet.TCPConn
	for deadline := time.Now().Add(linkUpWait); ; {
		dctx, dcancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err = gonet.DialContextTCP(dctx, peerDev.s, tcpDst, ipv4.ProtocolNumber)
		dcancel()
		if err == nil {
			break
		}
		select {
		case e := <-errCh:
			t.Fatalf("tunnel ended: %v", e)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("link did not come up: %v", err)
		}
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(ioWait)); err != nil {
		t.Fatal(err)
	}

	// TCP: 1 MiB both ways through the exit. The size matters: with the
	// unbounded-read bug (see nsStream.readOnce) anything from a few hundred
	// KiB up hangs a flow almost surely, while small payloads slip through.
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
	udpConn, err := gonet.DialUDP(peerDev.s, nil, &udpDst, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
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

	select {
	case err := <-errCh:
		t.Fatalf("tunnel ended: %v", err)
	default:
	}
}
