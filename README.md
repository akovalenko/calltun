# calltun

A point-to-point link between two hosts over WebRTC, carrying IP packets
(or Ethernet frames in tap mode) **inside the payload of real RTP**, so the
flow looks like a video call on the wire. A modest weron counterpart with
three deliberate differences:

- **signaling is peer-to-peer over SSH** (possibly via tor — that is just
  an ssh_config alias, calltun knows nothing about tor); no signaling
  server;
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

## Modes

- `calltun up --link NAME --ssh ALIAS [--offer-cmd calltun]` — initiator
  daemon: spawns `ssh ALIAS calltun offer --link NAME` per attempt,
  exchanges offer/answer (non-trickle), waits for ICE to connect, then the
  ssh session closes and the link runs standalone.
- `calltun accept --link NAME` — responder daemon: listens on
  `/run/calltun/NAME.sock`, serves one signaling session per run
  (crash-only: a new link is a fresh unit run).
- `calltun offer --link NAME` — a dumb stdio bridge run by sshd (forced
  command) between the ssh session and the accept daemon's socket.

Common flags: `--dev` (default `--link`), `--mode tun|tap` (default by
device-name prefix), `--stun LIST` (default `stun.l.google.com:19302`,
`none` = host candidates only), `--ice-timeout`, `-v`.
`--no-if A,B` — interfaces never to gather ICE candidates on (defaults to
the served device; see "candidate exclusion" below).
`CALLTUN_PIONLOG=1` — pion subsystem trace logging; `CALLTUN_OSFILE=1` —
the os.File tun path, kept as a regression canary.

## Deployment sketch

See `examples/`: two template units (`calltun-up@`, `calltun-accept@`), an
`/etc/network/interfaces` fragment (persistent device owned by the
`calltun` user, MTU 1100, peer subnet routed into the tunnel) and the
`restrict,command="... offer --link ct0"` authorized_keys line. The unit
ordering follows the `ssh -w` recipe (After/Wants/BindsTo on the
`.device` unit, carrier check in ExecStartPost, Restart=on-failure).

## Bench

`scripts/bench-arch.sh` (root) builds a same-host e2e bench: two netns
with the tun devices moved in and a veth pair to the main netns as the
media path. netns are required — on a single kernel any local address is
in the local routing table, so ICMP replies to the "peer" ride lo and
never traverse the reverse tunnel.

Measured there (v0): ping 0% loss both directions, 2000/3000-byte frames
fragment and reassemble, ~140 Mbit/s over TCP (nc/dd probe). With 10%
emulated loss in each direction: small pings lose ~1-(0.9·0.9), a
3000-byte ping (3 fragments each way) ~1-0.9⁶ — graceful, no wedging,
no ARQ by design (TCP inside the tunnel recovers; a NACK layer is a v2
item).

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
