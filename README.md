# calltun

A point-to-point link between two hosts over WebRTC, carrying IP packets
(or Ethernet frames in tap mode) **inside the payload of real RTP**, so the
flow looks like a video call on the wire. A modest weron counterpart with
three deliberate differences:

- **signaling is peer-to-peer over SSH** (possibly via tor — that is just
  an ssh_config alias, calltun knows nothing about tor), **or over nostr**
  (NIP-17 DMs via a fan of public relays) — no signaling server either
  way;
- **no TURN, ever** — the link lives when UDP hole punching works and dies
  (systemd restarts it) when it does not;
- **media, not data channels**: after the DTLS handshake the wire carries
  only RTP/RTCP plus ICE consent checks, exactly like a call. Data-channel
  traffic (weron's transport) is a pure DTLS stream — distinguishable from
  a call by the first byte of every packet (RFC 7983 demux: DTLS 20–63,
  RTP/RTCP 128–191), no decryption needed.

The tunnel device is created and configured **externally** (ifupdown /
iproute2): calltun attaches to an existing persistent TUN/TAP and never
touches addresses, routes or MTU. Peer authentication comes free: the SDP
travels over SSH, so the DTLS fingerprint arrives without a MITM surface.

## Signaling over nostr (second transport)

`--nostr PEER --nostr-key FILE` on `up`/`accept` (xor with `--ssh`)
switches signaling to public nostr relays: offer/answer ride inside
NIP-17 gift wraps (kind 1059), so on the wire they are ordinary nostr DM
traffic; the inner rumor kind (21124) is visible only to the peer. Both
sides configure each other's key (`calltun nostr-keygen FILE` mints one),
which authenticates the exchange — the seal inside a wrap is signed by
the sender's real key, checked on unwrap; no MITM surface, same as SSH.
Relays never sync with each other, so every message is published to ALL
configured relays and read from whichever are alive (`--relays`, default:
curated public pair); duplicates drop by event id, exchanges correlate by
a random attempt id minted per `up` run. Store-and-forward covers short
responder downtime (offers carry a 10-minute TTL — a stale offer's ICE
candidates are dead anyway, the initiator retries with a fresh one). A
responder coming back online backfills the initiator's whole retry pile
and answers the newest offer after a short settle window. Exchange
latency: seconds (measured live: 5.3 s offer→answer through
relay.damus.io + nos.lol).

## Modes

- `calltun exit` (the one mode that needs the userspace build: `go build
  -tags userspace`, for gVisor) `--link NAME --tunnel-addr 10.x.y.z
  --ssh ... [-- <ssh args>]` or `--nostr PEER --nostr-key FILE` — the "clean
  box" side: one binary, no root, no TUN. Signaling is the same as in `up`,
  ssh or nostr. Frames from the link feed a gVisor netstack with address
  spoofing; TCP/UDP flows to any destination terminate in userspace and
  re-originate as real dials (tun2socks-style exit). UDP is a session NAT
  with idle expiry; ICMP is not forwarded, and neither are destinations
  inside 127/8 (gVisor drops them as martian on a non-loopback NIC, so the
  exit's own loopback services are not reachable through the link). TCP
  half-close passes through: a FIN from the peer reaches the server as a
  FIN, and the reply that follows it is not cut off. Everything after `--`
  goes to ssh verbatim (jump hosts, ports, keys) — also in `up`. Covered by
  in-process e2e (`go test -tags userspace`): a second netstack plays the
  peer over a loopback PeerConnection — 1 MiB of TCP and UDP both ways, a
  half-closed request, sessions restarted in one process.
- `calltun up --link NAME --ssh ALIAS [--offer-cmd calltun]` — initiator
  daemon: spawns `ssh ALIAS calltun offer --link NAME` per attempt,
  exchanges offer/answer (non-trickle), waits for ICE to connect, then the
  ssh session closes and the link runs standalone.
- `calltun accept --link NAME` — responder daemon: listens on
  `/run/calltun/NAME.sock`, serves one signaling session per run
  (crash-only: a new link is a fresh unit run).
- `calltun offer --link NAME` — a dumb stdio bridge run by sshd (forced
  command) between the ssh session and the accept daemon's socket.
- `calltun version` — print the version (set by
  `-ldflags "-X github.com/akovalenko/calltun/cli.Version=..."`).

The command line lives in package `cli`: `cli.Main(args)` takes the
arguments without `argv[0]` and returns the exit status, so a multi-call
binary can embed calltun as an applet (no `os.Exit`, no `flag.CommandLine`).

Common flags: `--dev` (default `--link`), `--mode tun|tap` (default by
device-name prefix), `--stun LIST` (default `stun.cloudflare.com:3478`;
`none` = host candidates only). Google STUN got selectively blocked from
one of our production ISPs with no other UDP impact — anycast Cloudflare
held up everywhere, `--ice-timeout`, `-v`.
`--no-if A,B` — interfaces never to gather ICE candidates on (defaults to
the served device; see "candidate exclusion" below). `CALLTUN_NO_IF` is
the env fallback for unit-driven daemons. `--if eth0` (env `CALLTUN_IF`)
pins gathering to the listed interfaces ONLY — the allowlist wins over
the exclusion list and is the robust choice for hosts running several
links (fallback tunnels on one acceptor): pinning the WAN interface
makes media loops through sibling tunnels impossible by construction.
Pin lists containing the served device are refused at startup.
`--forever` (up/accept/exit) — rerun the session in place on any failure:
attach to tunnel (exit: a fresh netstack), a fresh signaling exchange each
time — the units' `Restart=always` without systemd, for manual
experiments. A finished attempt is released in full, the PeerConnection
first of all: its ICE agent keeps goroutines and sockets until closed.
External SIGTERM is still a clean exit.
`CALLTUN_PIONLOG=1` — pion subsystem trace logging. `CALLTUN_FD=<n>`
(with `CALLTUN_MTU=<bytes>`) — instead of attaching a device locally,
adopt the tun/tap descriptor a privileged helper attached elsewhere and
inherited to us on exec (`nsm tunfd`, see plans/calltun.md): the daemon
then lives in the underlay namespace while the device — with its
addresses and the default route — sits inside another one.

## Deployment sketch

See `examples/`: two template units (`calltun-up@`, `calltun-accept@`), an
`/etc/network/interfaces` fragment (persistent device owned by the
`calltun` user, MTU 1360, peer subnet routed into the tunnel) and the
`restrict,command="... offer --link ct0"` authorized_keys line. The unit
ordering follows the `ssh -w` recipe (After/Wants/BindsTo on the
`.device` unit, carrier check in ExecStartPost, Restart=on-failure).

## Framing: fire-and-forget

One source frame = ONE RTP packet, no fragment ids, no reassembly, no
dedup structures. A frame larger than the budget is dropped and counted,
and the device MTU gate at attach refuses to start on a misconfigured
MTU — otherwise oversized frames would vanish silently and TCP inside
(MSS from the interface MTU) would die with no evidence. The gate
accepts MTU up to 1384 (1500 path minus outer headers, worst case); 1370
is the recommended figure — it matches wg-inside-vxlan conventions, so
migrated infra keeps its visible MTU.

This simplicity is a scar, not just a taste: the v0 fragmenter/
reassembler (u16 pkt-id, pending map, delivered-id ring) produced three
production wedges, all in the ~70-215 MB range — a done-set starving on
the id wrap at exactly 65536 frames, and stale-pending/ring cascades
freezing the link again under iperf. Telemetry finally showed pion
delivering single-fragment frames to ReadRTP while the reassembler
rejected them as duplicates. The layer's only real function — carrying
frames larger than one packet — never operates when the MTU is right.

With MTU 1360 the budget also accommodates inner IPv6 (minimum MTU
1280). Measured on the production link (lnvps <-> home, real NAT): iperf
595 MB at 111 Mbit/s completing cleanly, pings 0% loss after, counter
past 475k frames with no wraps to count anymore.

tcpdump on the media path shows `0x80` RTP headers with PT 96 (VP8's usual
payload type) and marker bits — by packet type, indistinguishable from a
VP8 video call. RTCP SR/RR flow too (part of any real call). What is NOT
imitated: pacing — a real codec sends at a steady 30–50 pps, a bulk
transfer bursts; a behavioral DPI can tell. Padding/pacing to CBR is a v2
item.

## Lessons baked into the code


- **One sequence-number discipline per SSRC.** Two writers with different
  increment-vs-send orders collide seq numbers; the peer's SRTP replay
  filter eats the data silently (pion logs `duplicated packet` only under
  trace). Symptom from hell: keepalives pass, data never does.
- **Fire-and-forget framing.** Every fragment-id / reassembly scheme is
  a state machine living across 16-bit wraps; each wrap is a wedge
  factory under loss. With a correct MTU every frame fits one packet —
  delete the machine, gate the MTU loudly.
- **ICE candidate exclusion** (`--no-if`): a candidate whose address is
  routed through a tunnel sends the media into that tunnel — on a
  same-host bench always, in a multi-hop mesh whenever the peer is
  reachable via another link. Never gather on tunnel-routed interfaces.
- **Raw fd for /dev/net/tun** (no `os.File`/netpoll), the wireguard-go
  pattern. An early bench run saw `read /dev/net/tun: not pollable` with
  another thread TCGETS2+close on the fd per strace; the os.File canary
  later passed on both go1.26.4 and go1.27.4 in the same topology, so no
  Go-version attribution survived — raw I/O stays as robustness by
  construction.

## Non-goals (v0)

No TURN/relay (by design), no built-in congestion control (like
WireGuard: a bulk UDP flow can starve the downlink), no retransmission
(v2: NACK over RTCP APP), no pacing/padding (v2), one link = one session
= one device (mesh = one pair each, external routing).
