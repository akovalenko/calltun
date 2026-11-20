#!/bin/bash
# bench-arch-tunfd.sh — ns-split e2e for the fd-passing path (run as root
# on the bench host). Complements bench-arch.sh, which runs the daemons
# INSIDE the namespaces; here the daemons stay in the main ns (the
# "underlay"), the persistent tun devices live inside ct-a/ct-b ("target"
# namespaces), and the descriptors reach the daemons via `nsm tunfd`
# exec-inheritance. No veths: media rides main's lo between the daemons.
#
#   ct-a: ctun0 10.231.0.1/24, default dev ctun0   — initiator's ns,
#         the ct44 recipe shape: nothing but the tunnel
#   ct-b: ctun1 10.231.1.1/24, route 10.231.0.0/24 — responder's ns
#
# Checks:
#   1. link up through tunfd on both sides; accept drops to `nobody`
#   2. pings both ways THROUGH the tunnel (separate netns = separate
#      local tables — replies cannot shortcut over lo)
#   3. daemon restart (kill -9 + rerun, as a supervisor would) re-attaches
#      and never touches the ns ip state: convergence, not teardown
#   4. the MTU gate fires on the helper-delivered CALLTUN_MTU (sysfs is
#      invisible from the daemon's namespace)
#
# KEEP=1 leaves the link up for poking (logs: /root/calltun/{up,acc}.log).
set -euo pipefail

CALLTUN=${CALLTUN:-/usr/local/bin/calltun}
NSM=${NSM:-/usr/local/bin/nsm}
D=/root/calltun
LINK=ct0
SOCKDIR=/run/calltun

fail() { echo "FAIL: $*" >&2; exit 1; }

cleanup() {
    pkill -x calltun 2>/dev/null || true
    ip netns del ct-a 2>/dev/null || true
    ip netns del ct-b 2>/dev/null || true
    rm -rf "$SOCKDIR"
}
trap cleanup EXIT
cleanup
sleep 0.3

up_start() {
    nohup "$NSM" tunfd --netns ct-a --dev ctun0 --mode tun \
        --fd-env CALLTUN_FD --mtu-env CALLTUN_MTU -- \
        "$CALLTUN" up --link "$LINK" --dev ctun0 --mode tun --stun none -v \
        --ssh root@localhost -- -i /root/.ssh/ct_id -o StrictHostKeyChecking=accept-new \
        >"$D/up.log" 2>&1 &
    echo $! >"$D/up.pid"
}
acc_start() {
    nohup "$NSM" tunfd --netns ct-b --dev ctun1 --mode tun --uid nobody \
        --fd-env CALLTUN_FD --mtu-env CALLTUN_MTU -- \
        "$CALLTUN" accept --link "$LINK" --dev ctun1 --mode tun --stun none -v \
        >"$D/acc.log" 2>&1 &
    echo $! >"$D/acc.pid"
}

# --- ip-level state, as the ct44 run script would converge it
ip netns add ct-a
ip netns add ct-b
ip -n ct-a link set lo up
ip -n ct-b link set lo up
ip -n ct-a tuntap add dev ctun0 mode tun
ip -n ct-b tuntap add dev ctun1 mode tun
ip -n ct-a addr add 10.231.0.1/24 dev ctun0
ip -n ct-a link set ctun0 mtu 1370 up
ip -n ct-a route replace default dev ctun0
ip -n ct-b addr add 10.231.1.1/24 dev ctun1
ip -n ct-b link set ctun1 mtu 1370 up
ip -n ct-b route replace 10.231.0.0/24 dev ctun1
install -d -o nobody -g nobody -m 755 "$SOCKDIR"

# --- 1. bring the link up through tunfd on both sides
acc_start
sleep 1
up_start
for _ in $(seq 20); do
    grep -q 'device attached' "$D/up.log" 2>/dev/null && break
    sleep 1
done
sleep 5 # ICE + ready handshake
kill -0 "$(cat "$D/acc.pid")" 2>/dev/null || fail "accept died: $(tail -5 "$D/acc.log")"
kill -0 "$(cat "$D/up.pid")" 2>/dev/null || fail "up died: $(tail -5 "$D/up.log")"
grep -q 'remote track bound' "$D/acc.log" || fail "no remote track (acc): $(tail -5 "$D/acc.log")"
grep -q 'remote track bound' "$D/up.log" || fail "no remote track (up): $(tail -5 "$D/up.log")"
ps -o user= -p "$(cat "$D/acc.pid")" | grep -qx nobody \
    || fail "accept is not running as nobody (uid drop broken)"
echo "PASS 1: link up via tunfd (accept dropped to nobody, up as root)"

# --- 2. both directions through the tunnel
ip netns exec ct-a ping -c 3 -W 2 10.231.1.1 >/dev/null \
    || fail "ping ct-a -> ct-b: $(tail -3 "$D/up.log")"
ip netns exec ct-b ping -c 3 -W 2 10.231.0.1 >/dev/null \
    || fail "ping ct-b -> ct-a: $(tail -3 "$D/acc.log")"
echo "PASS 2: pings both ways through the tunnel"

# --- 3. restart convergence: kill the initiator, re-run as systemd would.
# Compare addresses and routes, normalized: both `ip addr show` and
# `ip route show` reflect the link's carrier state (NO-CARRIER on the
# link, `linkdown` on its routes), which legitimately drops with the
# daemon — carrier == "daemon attached" is the design's liveness marker,
# not teardown.
snap() { ip -n ct-a -4 addr show dev ctun0 | grep inet; ip -n ct-a route show | sed 's/ linkdown//'; }
before=$(snap)
kill -9 "$(cat "$D/up.pid")"
sleep 1
after=$(snap)
[ "$before" = "$after" ] || fail "ns ip state torn down on daemon death"
ip -n ct-a link show ctun0 | grep -q NO-CARRIER \
    || echo "note: carrier did not drop with the daemon"
# Crash-only on both sides: the media dying takes the acceptor down too
# (ice state dead -> exit, socket removed); each side's supervisor would
# restart it. Same invariance for the acceptor's ns, then restart BOTH,
# as the two systemd units would independently.
snapb() { ip -n ct-b -4 addr show dev ctun1 | grep inet; ip -n ct-b route show | sed 's/ linkdown//'; }
bbefore=$(snapb)
kill -9 "$(cat "$D/acc.pid")" 2>/dev/null || true
sleep 1
[ "$bbefore" = "$(snapb)" ] || fail "acceptor ns ip state torn down on death"
grep -o 'msg=exiting err="[^"]*"' "$D/acc.log" | tail -1 || true
acc_start
sleep 1
up_start
for _ in $(seq 20); do
    ip netns exec ct-a ping -c 1 -W 1 10.231.1.1 >/dev/null 2>&1 && break
    sleep 1
done
ip netns exec ct-a ping -c 3 -W 2 10.231.1.1 >/dev/null \
    || fail "no re-convergence after restart: $(tail -5 "$D/up.log")"
echo "PASS 3: daemon restart re-attaches, ns ip state untouched on both sides"

# --- 4. the MTU gate fires on the helper-delivered CALLTUN_MTU
kill -9 "$(cat "$D/acc.pid")"
ip -n ct-b link set ctun1 mtu 1500
if "$NSM" tunfd --netns ct-b --dev ctun1 --mode tun --uid nobody \
      --fd-env CALLTUN_FD --mtu-env CALLTUN_MTU -- \
      "$CALLTUN" accept --link "$LINK" --dev ctun1 --mode tun --stun none -v \
      >"$D/acc-gate.log" 2>&1; then
    fail "MTU gate did not fire: $(cat "$D/acc-gate.log")"
fi
grep -q 'MTU 1500 exceeds' "$D/acc-gate.log" \
    || fail "gate fired without the message: $(tail -3 "$D/acc-gate.log")"
echo "PASS 4: MTU gate refuses via CALLTUN_MTU"

# --- optionally leave a live link for poking
ip -n ct-b link set ctun1 mtu 1370
pkill -x calltun 2>/dev/null || true
sleep 0.5
acc_start
sleep 1
up_start
sleep 8
if ip netns exec ct-a ping -c 3 -W 2 10.231.1.1 >/dev/null 2>&1; then
    echo "link re-established (third convergence cycle)"
else
    echo "(final link not re-established; logs: $D/{up,acc}.log)"
fi
if [ "${KEEP:-0}" = 1 ]; then
    trap - EXIT
    echo "KEEP=1: bench left running (logs: $D/{up,acc}.log; cleanup: pkill -x calltun; ip netns del ct-a ct-b; rm -rf $SOCKDIR)"
else
    echo "ALL PASS"
fi
