// Command calltun is a point-to-point link between two hosts over WebRTC,
// with IP packets (or Ethernet frames, in tap mode) carried inside the
// payload of real RTP packets, so the flow looks like a video call on the
// wire. Signaling is peer-to-peer over ssh or nostr; there is no signaling
// server and no TURN.
//
// The command line is package cli: its Main is the process entry point and
// is exported so that a multi-call binary can embed calltun as an applet.
package main

import (
	"os"

	"github.com/akovalenko/calltun/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
