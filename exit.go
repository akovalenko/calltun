//go:build userspace

package main

// exit mode: the "clean box" side of a censored acceptor. No TUN, no root:
// IP frames from the link are fed into a gVisor netstack with address
// spoofing enabled, so TCP/UDP flows to ANY destination are terminated in
// userspace and re-originated as real dial()s — a tun2socks-style exit,
// with the RTP receiver instead of a TUN as the frame source. The peer
// (the carefully configured machine) runs a stock accept with a TUN and
// routes whatever it wants through the link.
//
// ICMP is not forwarded (no ping through the exit); TCP and UDP only.

import (
	"bytes"
	"context"
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

func cmdExit(ctx context.Context, args []string) error {
	fs := newFlagSet("exit")
	var c commonFlags
	var sshAlias, offerCmd, noIf, pinIf, tunnelAddr string
	registerCommon(fs, &c)
	fs.StringVar(&sshAlias, "ssh", "", "ssh destination; xor with a destination in the trailing args after --")
	fs.StringVar(&offerCmd, "offer-cmd", "calltun", "remote calltun binary for the offer bridge")
	fs.StringVar(&noIf, "no-if", "", "comma list of interfaces to never gather ICE candidates on")
	fs.StringVar(&pinIf, "if", "", "pin ICE candidates to these interfaces ONLY (overrides --no-if)")
	fs.StringVar(&tunnelAddr, "tunnel-addr", "", "this side's IP inside the link (e.g. 10.187.52.18); required")
	fs.Parse(args)
	// Everything after "--" goes to ssh verbatim (options and/or the
	// destination): -J hop, -p port, -i key.
	extraSSH := fs.Args()
	initLog(c.verbose)

	if tunnelAddr == "" {
		return fmt.Errorf("--tunnel-addr is required")
	}
	if sshAlias == "" && len(extraSSH) == 0 {
		return fmt.Errorf("--ssh (or a destination in the trailing args after --) is required")
	}

	dev, err := newExitStack(ctx, tunnelAddr)
	if err != nil {
		return err
	}
	lg.Info("calltun exit starting", "link", c.link, "tunnel-addr", tunnelAddr, "ssh", sshAlias, "ssh_extra", len(extraSSH))

	p, err := initiatorSession(ctx, &c, sshAlias, extraSSH, offerCmd, c.link, pinIf, splitList(noIf))
	if err != nil {
		return err
	}
	return runTunnel(ctx, p, dev)
}

// exitStack ties the gVisor stack to a tun-shaped frame device.
type exitStack struct {
	ep  *channel.Endpoint
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
	return &exitStack{ep: ep, ctx: ctx}, nil
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

func (e *exitStack) Close() error { return nil }

// --- connected-endpoint <-> io.ReadWriteCloser adapter ---

type nsStream struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

// Read pulls data (a TCP chunk or one UDP datagram) from the endpoint.
func (s *nsStream) Read(p []byte) (int, error) {
	for {
		var buf bytes.Buffer
		res, err := s.ep.Read(&buf, tcpip.ReadOptions{})
		if err == nil {
			return buf.Read(p)
		}
		if _, block := err.(*tcpip.ErrWouldBlock); !block {
			return 0, toErr(err)
		}
		entry, ch := waiter.NewChannelEntry(waiter.EventIn | waiter.EventErr | waiter.EventHUp)
		s.wq.EventRegister(&entry)
		// Re-check after registering (missed-wakeup dance).
		var b2 bytes.Buffer
		res, err = s.ep.Read(&b2, tcpip.ReadOptions{})
		if err == nil {
			s.wq.EventUnregister(&entry)
			return b2.Read(p)
		}
		if _, block := err.(*tcpip.ErrWouldBlock); !block {
			s.wq.EventUnregister(&entry)
			return 0, toErr(err)
		}
		<-ch
		s.wq.EventUnregister(&entry)
		_ = res
	}
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
	real, derr := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", dst.String())
	if derr != nil {
		r.Complete(true)
		return
	}
	lg.Info("exit tcp session", "dst", dst)
	local := &nsStream{ep: ep, wq: &wq}
	go func() {
		done := make(chan struct{}, 2)
		go func() { io.Copy(real, local); real.Close(); done <- struct{}{} }()
		go func() { io.Copy(local, real); local.Close(); done <- struct{}{} }()
		<-done
		<-done
	}()
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
	real, derr := (&net.Dialer{Timeout: dialTimeout}).Dial("udp", dst.String())
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
