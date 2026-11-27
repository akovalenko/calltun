//go:build userspace

package cli

// exit mode: the "clean box" side of a censored acceptor. No TUN, no root:
// IP frames from the link are fed into a gVisor netstack with address
// spoofing enabled, so TCP/UDP flows to ANY destination are terminated in
// userspace and re-originated as real dial()s — a tun2socks-style exit,
// with the RTP receiver instead of a TUN as the frame source. The peer
// (the carefully configured machine) runs a stock accept with a TUN and
// routes whatever it wants through the link.
//
// Signaling is the initiator's, exactly as in up: the exit dials — over
// ssh (--ssh, the peer's forced command) or nostr (--nostr). --forever
// reruns the session in place, as in up: each run gets a fresh netstack,
// and everything the previous run created is released.
//
// TCP half-close passes through: a FIN from the peer reaches the server as
// a FIN and the reply that follows it is not cut off.
//
// ICMP is not forwarded (no ping through the exit); TCP and UDP only.
// Destinations inside 127/8 are dropped by the netstack on arrival (gVisor's
// martian filter), so the exit's own loopback services are not reachable
// through the link.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID       = 1
	udpIdleTTL  = 75 * time.Second
	dialTimeout = 15 * time.Second
)

// exitDial opens the real connection a terminated flow is re-originated as.
// A variable so the in-process test can aim the dials at the loopback: a
// sandbox has nothing else, and the netstack itself drops loopback
// destinations arriving on the NIC as martian packets.
var exitDial = func(network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: dialTimeout}).Dial(network, addr)
}

func cmdExit(ctx context.Context, args []string) error {
	fs := newFlagSet("exit")
	var c commonFlags
	var nf nostrFlags
	var sshAlias, offerCmd, noIf, pinIf, tunnelAddr string
	registerCommon(fs, &c)
	nf.register(fs)
	fs.StringVar(&sshAlias, "ssh", "", "ssh destination (alias from ssh_config); xor with a destination in the trailing args")
	fs.StringVar(&offerCmd, "offer-cmd", "calltun", "remote calltun binary for the offer bridge")
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on")
	fs.StringVar(&pinIf, "if", "", "pin ICE candidates to these interfaces ONLY (overrides --no-if)")
	fs.StringVar(&tunnelAddr, "tunnel-addr", "", "this side's IP inside the link (e.g. 10.187.52.18); required")
	if err := parseFlags(fs, args); err != nil {
		return err
	}
	// Everything after "--" goes to ssh verbatim (options and/or the
	// destination): -J hop, -p port, -i key.
	extraSSH := fs.Args()
	initLog(c.verbose)

	if tunnelAddr == "" {
		return fmt.Errorf("--tunnel-addr is required")
	}
	if err := checkSignalingFlags(&nf, sshAlias, extraSSH); err != nil {
		return err
	}
	lg.Info("calltun exit starting", "link", c.link, "tunnel-addr", tunnelAddr,
		"ssh", sshAlias, "ssh_extra", len(extraSSH), "nostr", nf.peer != "", "forever", c.forever)

	// No served device: the empty name only means "nothing to self-exclude".
	excluded := excludedIfaces(noIf, "")
	// One run = transport + exchange + tunnel; --forever reruns it on any
	// failure, as in up, each time over a fresh netstack.
	runOnce := func() error {
		sess, teardown, err := openSignaling(&c, &nf, sshAlias, extraSSH, offerCmd)
		if err != nil {
			return err
		}
		return exitSession(ctx, &c, sess, teardown, tunnelAddr, pinIf, excluded)
	}
	if c.forever {
		return runForever(ctx, runOnce)
	}
	return runOnce()
}

// exitSession is one exit run: a fresh netstack, the signaling exchange on
// the given transport, then the tunnel until the link dies. Whatever the
// run created is released on the way out, so runs can follow each other in
// one process (--forever).
func exitSession(ctx context.Context, c *commonFlags, sess sigTransport, teardown func(), tunnelAddr, pinIf string, excluded []string) error {
	dev, err := newExitStack(ctx, tunnelAddr)
	if err != nil {
		// The transport is already open: nobody else is left to close it.
		sess.Close()
		if teardown != nil {
			teardown()
		}
		return err
	}
	defer dev.Close()
	p, err := initiatorSession(ctx, c, sess, teardown, "", pinIf, excluded)
	if err != nil {
		return err
	}
	defer p.release()
	return runTunnel(ctx, p, dev)
}

// exitStack ties the gVisor stack to a tun-shaped frame device.
type exitStack struct {
	ep  *channel.Endpoint
	s   *stack.Stack
	ctx context.Context
}

// newExitStack builds the stack: raw-IP channel NIC with spoofing and
// promiscuous mode (accept flows to any destination), TCP and UDP
// forwarders re-originating every flow as a real dial.
func newExitStack(ctx context.Context, tunnelAddr string) (*exitStack, error) {
	ip := net.ParseIP(tunnelAddr)
	if ip == nil {
		return nil, fmt.Errorf("bad --tunnel-addr %q", tunnelAddr)
	}
	var proto tcpip.NetworkProtocolNumber
	var addr tcpip.Address
	if v4 := ip.To4(); v4 != nil {
		proto, addr = ipv4.ProtocolNumber, tcpip.AddrFromSlice(v4)
	} else {
		proto, addr = ipv6.ProtocolNumber, tcpip.AddrFromSlice(ip.To16())
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(maxFrame), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	// The two magic knobs: pretend every destination is local, so the
	// forwarders see flows to arbitrary addresses (the tun2socks trick).
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	if err := s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 128, // /32 for v4, /128 for v6: only our own address
		},
	}, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	tcpFwd := tcp.NewForwarder(s, 0, 1<<16, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		dst := &net.TCPAddr{IP: net.IP(id.LocalAddress.AsSlice()), Port: int(id.LocalPort)}
		forwardTCP(r, dst)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		dst := &net.UDPAddr{IP: net.IP(id.LocalAddress.AsSlice()), Port: int(id.LocalPort)}
		forwardUDP(r, dst)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return &exitStack{ep: ep, s: s, ctx: ctx}, nil
}

// Read blocks until the stack emits a frame (return traffic toward the peer).
func (e *exitStack) Read(p []byte) (int, error) {
	pkt := e.ep.ReadContext(e.ctx)
	if pkt == nil {
		return 0, fmt.Errorf("netstack link closed")
	}
	defer pkt.DecRef()
	buf := pkt.ToBuffer()
	n := buf.Size()
	if n > int64(len(p)) {
		n = int64(len(p))
	}
	if n > 0 {
		// buffer.ReadAt reports io.EOF after a complete read at the end
		// of the buffer — that is success, not an error.
		if _, err := buf.ReadAt(p[:n], 0); err != nil && err != io.EOF {
			return 0, fmt.Errorf("netstack read: %w", err)
		}
	}
	return int(n), nil
}

// Write feeds one IP frame (arrived via RTP) into the stack.
func (e *exitStack) Write(frame []byte) (int, error) {
	if len(frame) == 0 {
		return 0, nil
	}
	var proto tcpip.NetworkProtocolNumber
	switch frame[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return 0, fmt.Errorf("not an IP frame")
	}
	own := make([]byte, len(frame)) // netstack keeps the buffer
	copy(own, frame)
	e.ep.InjectInbound(proto, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(own),
	}))
	return len(frame), nil
}

// Close tears the stack down: its endpoints close, which ends the forwarder
// sessions and their real dials. The channel endpoint is ours to stop — a
// stack does not close link endpoints — and stopping it wakes the frame
// reader; Wait then lets the workers finish before a next run starts.
func (e *exitStack) Close() error {
	e.s.Close()
	e.ep.Close()
	e.s.Wait()
	return nil
}

// --- connected-endpoint <-> io.ReadWriteCloser adapter ---

type nsStream struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

var errWouldBlock = errors.New("netstack: operation would block")

// Read pulls data (a TCP chunk or one UDP datagram) from the endpoint.
func (s *nsStream) Read(p []byte) (int, error) {
	for {
		n, err := s.readStep(p)
		if err != errWouldBlock {
			return n, err
		}
		entry, ch := waiter.NewChannelEntry(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
		s.wq.EventRegister(&entry)
		// Re-check after registering (missed-wakeup dance).
		n, err = s.readStep(p)
		if err != errWouldBlock {
			s.wq.EventUnregister(&entry)
			return n, err
		}
		<-ch
		s.wq.EventUnregister(&entry)
	}
}

// readStep is one non-blocking read of at most len(p) bytes: io.EOF at the
// peer's FIN (all of its data drained), errWouldBlock when nothing is
// pending, any other endpoint condition as an error.
//
// The endpoint copies as much as the writer takes, so the writer must be
// bounded by p. Reading into an unbounded buffer and returning its first
// len(p) bytes — as this used to — dropped the rest: a flow through the
// exit silently lost data whenever more than the reader's buffer (io.Copy's
// 32 KiB) was queued at once, and the peer then waited for the lost tail
// forever. Caught by the in-process e2e: 256 KiB uploads hung in roughly a
// third of the runs, a few KiB short.
func (s *nsStream) readStep(p []byte) (int, error) {
	w := tcpip.SliceWriter(p)
	res, err := s.ep.Read(&w, tcpip.ReadOptions{})
	switch err.(type) {
	case nil:
		return int(res.Count), nil
	case *tcpip.ErrClosedForReceive:
		return 0, io.EOF
	case *tcpip.ErrWouldBlock:
		return 0, errWouldBlock
	default:
		return 0, toErr(err)
	}
}

// CloseWrite sends a FIN to the peer and leaves the read side open. Needed
// for half-close: a peer that finished its request may still be waiting
// for the reply.
func (s *nsStream) CloseWrite() error {
	if err := s.ep.Shutdown(tcpip.ShutdownWrite); err != nil {
		return toErr(err)
	}
	return nil
}

func (s *nsStream) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 32<<10 {
			chunk = chunk[:32<<10]
		}
		n64, err := s.ep.Write(bytes.NewReader(chunk), tcpip.WriteOptions{})
		if _, block := err.(*tcpip.ErrWouldBlock); block {
			entry, ch := waiter.NewChannelEntry(waiter.EventOut | waiter.EventErr | waiter.EventHUp)
			s.wq.EventRegister(&entry)
			n64, err = s.ep.Write(bytes.NewReader(chunk), tcpip.WriteOptions{})
			if _, still := err.(*tcpip.ErrWouldBlock); still {
				<-ch
				s.wq.EventUnregister(&entry)
				continue
			}
			s.wq.EventUnregister(&entry)
		}
		if err != nil {
			return total, toErr(err)
		}
		total += int(n64)
		p = p[int(n64):]
	}
	return total, nil
}

func (s *nsStream) Close() error {
	s.ep.Close()
	return nil
}

func toErr(e tcpip.Error) error {
	if e == nil {
		return nil
	}
	return fmt.Errorf("netstack: %s", e.String())
}

// --- TCP forwarder ---

func forwardTCP(r *tcp.ForwarderRequest, dst *net.TCPAddr) {
	wq := waiter.Queue{}
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		r.Complete(true)
		return
	}
	real, derr := exitDial("tcp", dst.String())
	if derr != nil {
		// Complete answers the peer, but the endpoint is ours to close.
		ep.Close()
		r.Complete(true)
		return
	}
	lg.Info("exit tcp session", "dst", dst)
	local := &nsStream{ep: ep, wq: &wq}
	go pumpTCP(real, local)
}

// pumpTCP couples the peer's flow with the real connection until both
// directions are over. A direction that ends cleanly half-closes its
// destination: the peer's FIN reaches the server as a FIN, the server's
// EOF reaches the peer as one. Closing whole on the first finished
// direction — as this used to — cut off every reply that came after the
// peer's own FIN (a request ended with "no more data"). A direction that
// ends with an error tears the session down whole.
func pumpTCP(real net.Conn, local *nsStream) {
	var once sync.Once
	abort := func() { once.Do(func() { real.Close(); local.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := io.Copy(real, local); err == nil {
			closeWrite(real)
		} else {
			abort()
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.Copy(local, real); err == nil {
			_ = local.CloseWrite()
		} else {
			abort()
		}
	}()
	wg.Wait()
	real.Close()
	local.Close()
}

// closeWrite half-closes the real connection when it can be, and closes it
// whole when it cannot.
func closeWrite(real net.Conn) {
	if hc, ok := real.(interface{ CloseWrite() error }); ok {
		if hc.CloseWrite() == nil {
			return
		}
	}
	real.Close()
}

// --- UDP forwarder (session NAT) ---

type udpKey struct{ src, dst string }

type udpSession struct {
	local *nsStream
	real  net.Conn
}

var (
	udpMu    sync.Mutex
	udpTable = map[udpKey]*udpSession{}
)

// forwardUDP serves one NEW udp flow: a connected endpoint is registered
// for the 4-tuple (later datagrams of the flow are delivered straight to
// it, not back here) and pumped to a real connected UDP socket. Sessions
// die on idle timeout.
func forwardUDP(r *udp.ForwarderRequest, dst *net.UDPAddr) {
	id := r.ID()
	key := udpKey{
		src: fmt.Sprintf("%s:%d", id.RemoteAddress, id.RemotePort),
		dst: fmt.Sprintf("%s:%d", id.LocalAddress, id.LocalPort),
	}
	wq := waiter.Queue{}
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return
	}
	real, derr := exitDial("udp", dst.String())
	if derr != nil {
		ep.Close()
		return
	}
	sess := &udpSession{local: &nsStream{ep: ep, wq: &wq}, real: real}
	udpMu.Lock()
	udpTable[key] = sess
	udpMu.Unlock()
	lg.Info("exit udp session", "dst", dst)

	go func() { // real -> tunnel
		buf := make([]byte, 2048)
		for {
			sess.real.SetReadDeadline(time.Now().Add(udpIdleTTL))
			n, err := sess.real.Read(buf)
			if err != nil {
				break
			}
			if _, err := sess.local.Write(buf[:n]); err != nil {
				break
			}
		}
	}()
	go func() { // tunnel -> real
		buf := make([]byte, 2048)
		for {
			n, err := sess.local.Read(buf)
			if err != nil || n == 0 {
				break
			}
			if _, err := sess.real.Write(buf[:n]); err != nil {
				break
			}
		}
		cleanupUDP(key, sess)
	}()
}

func cleanupUDP(key udpKey, sess *udpSession) {
	sess.local.Close()
	sess.real.Close()
	udpMu.Lock()
	if cur, ok := udpTable[key]; ok && cur == sess {
		delete(udpTable, key)
	}
	udpMu.Unlock()
}
