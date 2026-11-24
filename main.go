// calltun — a point-to-point link between two hosts over WebRTC, with IP
// packets (or Ethernet frames, in tap mode) carried inside the payload of
// real RTP packets, so the flow looks like a video call on the wire.
//
// Signaling is peer-to-peer over an SSH session (possibly routed via tor —
// that is just an ssh_config alias, calltun does not know about tor). There
// is no signaling server and no TURN: if UDP hole punching does not work,
// the link dies and systemd restarts it (crash-only).
//
// The tunnel device itself is created and configured externally (ifupdown,
// iproute2); calltun only attaches to an existing persistent device and
// never touches addresses, routes or MTU.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// defaultSTUN kept for compatibility; the real default list lives in
	// stun.go (defaultSTUNServers). This value is used only when the
	// collection is somehow empty.
	defaultSTUN = "stun.cloudflare.com:3478"
	sockDirEnv  = "CALLTUN_RUN_DIR"
	sockDirDef  = "/run/calltun"
)

var lg *slog.Logger

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(ctx, os.Args[2:])
	case "accept":
		err = cmdAccept(ctx, os.Args[2:])
	case "offer":
		err = cmdOffer(ctx, os.Args[2:])
	case "exit":
		err = cmdExit(ctx, os.Args[2:])
	case "stun-probe":
		err = cmdStunProbe(ctx, os.Args[2:])
	case "nostr-keygen":
		err = cmdNostrKeygen(ctx, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "calltun: unknown subcommand %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		lg.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  calltun up     --link NAME --ssh ALIAS [--offer-cmd calltun] [flags]  initiator side
  calltun up     --link NAME --nostr PEER --nostr-key FILE [flags]      initiator side, nostr signaling
  calltun accept --link NAME [--nostr PEER --nostr-key FILE] [flags]    responder daemon
  calltun offer  --link NAME                                           sshd-forced bridge
  calltun nostr-keygen FILE                                            mint a nostr identity, print keys

common flags: --link NAME --dev NAME --mode tun|tap --stun LIST --ice-timeout 30s -v
              --forever (rerun the session in place on failure; systemd-free experiments)
nostr signaling: --nostr (peer npub/hex; replaces --ssh), --nostr-key (our secret),
--relays (comma list; default: curated public relays). Signaling rides in NIP-17
gift wraps, so on the wire it is ordinary nostr DM traffic.
STUN list: comma-separated host[:port] entries, or "none" for host candidates only.
`)
}

// commonFlags holds the flags shared by up and accept. offer takes none of them.
type commonFlags struct {
	link    string
	dev     string
	mode    string
	stun    string
	iceWait string
	verbose bool
	forever bool
}

func registerCommon(fs *flag.FlagSet, c *commonFlags) {
	fs.StringVar(&c.link, "link", "", "link name: signaling socket identity and default device name (required)")
	fs.StringVar(&c.dev, "dev", "", "tun/tap device to attach to (default: --link)")
	fs.StringVar(&c.mode, "mode", "", "tun | tap (default: inferred from device name prefix)")
	fs.StringVar(&c.stun, "stun", defaultSTUN, `comma list of STUN servers, "none" for host candidates only`)
	fs.StringVar(&c.iceWait, "ice-timeout", "30s", "how long to wait for ICE to connect after the exchange")
	fs.BoolVar(&c.verbose, "v", false, "debug logging")
	fs.BoolVar(&c.forever, "forever", false, "rerun the session in place on any failure (systemd Restart=always without systemd; for experiments)")
}

func initLog(verbose bool) {
	lvl := slog.LevelInfo
	if verbose || os.Getenv("CALLTUN_VERBOSE") != "" {
		lvl = slog.LevelDebug
	}
	lg = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}

// resolveDevice maps --dev/--mode into a device name and TAP-or-not. The
// kernel does not care about name prefixes; the prefix is only a default
// for --mode, matching the persistent devices ifupdown creates.
func resolveDevice(c *commonFlags) (name string, tap bool, err error) {
	name = c.dev
	if name == "" {
		name = c.link
	}
	if name == "" {
		return "", false, fmt.Errorf("--link is required")
	}
	m := strings.ToLower(c.mode)
	if m == "" {
		switch {
		case strings.HasPrefix(name, "tun"):
			m = "tun"
		case strings.HasPrefix(name, "tap"):
			m = "tap"
		default:
			return "", false, fmt.Errorf("cannot infer --mode from device %q; pass --mode explicitly", name)
		}
	}
	if m != "tun" && m != "tap" {
		return "", false, fmt.Errorf("--mode must be tun or tap, got %q", c.mode)
	}
	return name, m == "tap", nil
}

// stunURLs normalizes the --stun flag into ICE server URLs.
func stunURLs(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "none") || s == "-" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, ":") {
			p += ":3478"
		}
		if !strings.HasPrefix(p, "stun:") {
			p = "stun:" + p
		}
		out = append(out, p)
	}
	return out
}

func sockPath(link string) string {
	d := os.Getenv(sockDirEnv)
	if d == "" {
		d = sockDirDef
	}
	return filepath.Join(d, link+".sock")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
