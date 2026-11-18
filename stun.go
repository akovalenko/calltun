package main

import (
	"os"
	"strings"
)

// Built-in STUN collection. Curated empirically (2026-11-18) from three
// different ISPs (home RU broadband, murphy, texas NAT): every server in
// the list answered from all three; google STUN is NOT in the list —
// selectively blocked from two of them while all other UDP flowed.
// Ordered by measured latency from the most constrained site; pion
// gathers srflx from each until one succeeds, so the list doubles as
// redundancy against per-provider blocking.
var defaultSTUNServers = []string{
	"stun.cloudflare.com:3478",
	"stun.nextcloud.com:3478",
	"global.stun.twilio.com:3478",
	"stun.internetcalls.com:3478",
	"stun.voipbuster.com:3478",
	"stun.sipgate.net:3478",
	"stun.schlund.de:3478",
	"stun.freeswitch.org:3478",
}

// stunServers resolves the effective server list: the --stun flag wins
// (comma list, "none" for host candidates only), then CALLTUN_STUN, then
// the built-in collection.
func stunServers(flagVal string) []string {
	if s := splitList(flagVal); len(s) > 0 {
		return stunURLs(flagVal)
	}
	if env := os.Getenv("CALLTUN_STUN"); env != "" {
		return stunURLs(env)
	}
	return stunURLs(joinList(defaultSTUNServers))
}

// normalizeStun expands bare host entries to host:3478 for probing.
func normalizeStun(s string) string {
	out := ""
	for i, p := range splitList(s) {
		if i > 0 {
			out += ","
		}
		if !strings.Contains(p, ":") {
			p += ":3478"
		}
		out += p
	}
	return out
}

func joinList(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
