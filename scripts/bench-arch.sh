#!/bin/bash
# bench-arch.sh — same-host e2e bench for calltun: two netns with the tun
# devices moved in, a veth pair to the main ns as the media path, and the
# signaling unix socket shared through the filesystem. Run as root on the
# bench host (developed on arch; veth + netns required).
#
# Why netns: on a single kernel any local address is in the local routing
# table, so ICMP replies to the "peer" ride lo and never traverse the
# reverse tunnel. Separate netns have separate local tables — the only way
# to test the full round trip of both directions on one host.
#
# After bring-up:
#   ip netns exec ct-a ping 10.231.1.1   # through the tunnel both ways
#   ip netns exec ct-b ping 10.231.0.1
set -euo pipefail

CALLTUN=${CALLTUN:-/root/calltun/calltun}
SOCKDIR=/run/calltun
LINK=ct0

command -v ip >/dev/null || { echo "iproute2 required"; exit 1; }
[ -x "$CALLTUN" ] || { echo "$CALLTUN not found (build and deploy first)"; exit 1; }

cleanup() {
    pkill -x calltun 2>/dev/null || true
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
ip netns exec ct-a ip addr add 10.231.0.1/24 dev ctun0
ip netns exec ct-a ip link set ctun0 up
ip netns exec ct-a ip route add 10.231.1.0/24 dev ctun0

ip netns exec ct-b ip link set lo up
ip netns exec ct-b ip addr add 10.231.21.2/24 dev veth-b
ip netns exec ct-b ip link set veth-b up
ip netns exec ct-b ip route add default via 10.231.21.1
ip netns exec ct-b ip addr add 10.231.1.1/24 dev ctun1
ip netns exec ct-b ip link set ctun1 up
ip netns exec ct-b ip route add 10.231.0.0/24 dev ctun1

sysctl -qw net.ipv4.ip_forward=1
# Docker's FORWARD chain is often policy DROP; allow the bench subnets.
iptables -C FORWARD -s 10.231.20.0/24 -d 10.231.21.0/24 -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s 10.231.20.0/24 -d 10.231.21.0/24 -j ACCEPT
iptables -C FORWARD -s 10.231.21.0/24 -d 10.231.20.0/24 -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s 10.231.21.0/24 -d 10.231.20.0/24 -j ACCEPT

mkdir -p "$SOCKDIR"

# The up side reaches the main-ns sshd through its veth; the forced
# command (`offer`) runs in the main ns and dials the shared unix socket.
# Requires an ssh alias for the bench, e.g. in ~/.ssh/config:
#   Host ctlo
#       HostName 10.231.21.1
#       User root
#       IdentityFile ~/.ssh/ct_id
# and a matching restrict,command="... offer --link ct0" authorized_key.
ip netns exec ct-a sh -c "nohup $CALLTUN accept --link $LINK --dev ctun0 \
    --mode tun --stun none -v > /root/calltun/accept.log 2>&1 &"
sleep 1
ip netns exec ct-b sh -c "nohup $CALLTUN up --link $LINK --dev ctun1 \
    --mode tun --ssh ctlo --offer-cmd $CALLTUN --stun none -v \
    > /root/calltun/up.log 2>&1 &"
sleep 6

echo "=== ping ct-a -> ct-b (through the tunnel, both directions traversed):"
ip netns exec ct-a ping -c 3 -W 2 10.231.1.1
echo "=== ping ct-b -> ct-a:"
ip netns exec ct-b ping -c 3 -W 2 10.231.0.1

echo "bench is up; daemons keep running (logs: /root/calltun/*.log)"
trap - EXIT
