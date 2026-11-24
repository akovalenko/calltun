#!/bin/bash
# bench-arch-nostr.sh — nostr-signaling e2e on the bench host: the same
# netns/veth media topology as bench-arch.sh, but the offer/answer rides
# in NIP-17 gift wraps through a local nak relay (main ns) instead of the
# ssh forced-command path. Phase 2 exercises store-and-forward: the
# responder starts AFTER the initiator's offer is already on the relay.
# Run as root on the bench host (developed on arch).
set -euo pipefail

CALLTUN=${CALLTUN:-/root/calltun/calltun-nostr}
NAK=${NAK:-/root/calltun/nak}
LINK=ct0
NAKPORT=10547

command -v ip >/dev/null || { echo "iproute2 required"; exit 1; }
[ -x "$CALLTUN" ] || { echo "$CALLTUN not found (build and deploy first)"; exit 1; }
[ -x "$NAK" ] || { echo "$NAK not found"; exit 1; }

cleanup() {
    pkill -x "$(basename "$CALLTUN")" 2>/dev/null || true
    pkill -x nak 2>/dev/null || true
    ip netns del ct-a 2>/dev/null || true
    ip netns del ct-b 2>/dev/null || true
    ip link del vetham 2>/dev/null || true
    ip link del vethbm 2>/dev/null || true
    ip tuntap del dev ctun0 mode tun 2>/dev/null || true
    ip tuntap del dev ctun1 mode tun 2>/dev/null || true
}
trap cleanup EXIT
cleanup
sleep 0.3

ip tuntap add dev ctun0 mode tun
ip tuntap add dev ctun1 mode tun
ip netns add ct-a
ip netns add ct-b
ip link set ctun0 netns ct-a
ip link set ctun1 netns ct-b
ip link add veth-a type veth peer name vetham
ip link add veth-b type veth peer name vethbm
ip link set veth-a netns ct-a
ip link set veth-b netns ct-b

ip addr add 10.231.20.1/24 dev vetham; ip link set vetham up
ip addr add 10.231.21.1/24 dev vethbm; ip link set vethbm up

ip netns exec ct-a ip link set lo up
ip netns exec ct-a ip addr add 10.231.20.2/24 dev veth-a
ip netns exec ct-a ip link set veth-a up
ip netns exec ct-a ip route add default via 10.231.20.1
ip netns exec ct-a ip link set ctun0 mtu 1370
ip netns exec ct-a ip addr add 10.231.0.1/24 dev ctun0
ip netns exec ct-a ip link set ctun0 up
ip netns exec ct-a ip route add 10.231.1.0/24 dev ctun0

ip netns exec ct-b ip link set lo up
ip netns exec ct-b ip addr add 10.231.21.2/24 dev veth-b
ip netns exec ct-b ip link set veth-b up
ip netns exec ct-b ip route add default via 10.231.21.1
ip netns exec ct-b ip link set ctun1 mtu 1370
ip netns exec ct-b ip addr add 10.231.1.1/24 dev ctun1
ip netns exec ct-b ip link set ctun1 up
ip netns exec ct-b ip route add 10.231.0.0/24 dev ctun1

sysctl -qw net.ipv4.ip_forward=1
iptables -C FORWARD -s 10.231.20.0/24 -d 10.231.21.0/24 -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s 10.231.20.0/24 -d 10.231.21.0/24 -j ACCEPT
iptables -C FORWARD -s 10.231.21.0/24 -d 10.231.20.0/24 -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s 10.231.21.0/24 -d 10.231.20.0/24 -j ACCEPT

cd /root/calltun
rm -f nostr-a.key nostr-b.key
NPUB_A=$("$CALLTUN" nostr-keygen nostr-a.key | awk '/^pub:/ {print $2}')
NPUB_B=$("$CALLTUN" nostr-keygen nostr-b.key | awk '/^pub:/ {print $2}')
echo "npub A (accept, ct-a): $NPUB_A"
echo "npub B (up,     ct-b): $NPUB_B"

# The relay lives in the main ns; each netns reaches it through its own
# veth gateway address (the same trick the ssh bench plays with ctlo).
nohup "$NAK" serve --hostname 0.0.0.0 --port $NAKPORT > /root/calltun/nak.log 2>&1 &
sleep 1
RELAY_A=ws://10.231.20.1:$NAKPORT
RELAY_B=ws://10.231.21.1:$NAKPORT

accept_daemon() { # $1 = log suffix
    ip netns exec ct-a sh -c "nohup $CALLTUN accept --link $LINK --dev ctun0 \
        --mode tun --stun none --nostr $NPUB_B \
        --nostr-key /root/calltun/nostr-a.key --relays $RELAY_A -v \
        > /root/calltun/accept$1.log 2>&1 &"
}
up_daemon() { # $1 = log suffix
    ip netns exec ct-b sh -c "nohup $CALLTUN up --link $LINK --dev ctun1 \
        --mode tun --stun none --nostr $NPUB_A \
        --nostr-key /root/calltun/nostr-b.key --relays $RELAY_B -v \
        > /root/calltun/up$1.log 2>&1 &"
}

echo "=== phase 1: normal bring-up"
accept_daemon ""
sleep 1
up_daemon ""
sleep 8

echo "=== ping ct-a -> ct-b (through the tunnel, both directions traversed):"
ip netns exec ct-a ping -c 3 -W 2 10.231.1.1 || true
echo "=== ping ct-b -> ct-a:"
ip netns exec ct-b ping -c 3 -W 2 10.231.0.1 || true

echo "=== phase 2: store-and-forward — offer first, responder 3s later"
pkill -x "$(basename "$CALLTUN")" 2>/dev/null || true
sleep 1
up_daemon "2"          # the offer waits on the relay, nobody answers yet
sleep 3
accept_daemon "2"      # late responder: backfills, answers, ICE connects
sleep 8
ip netns exec ct-a ping -c 3 -W 2 10.231.1.1 || true

echo "bench done (logs: /root/calltun/*.log)"
trap - EXIT
