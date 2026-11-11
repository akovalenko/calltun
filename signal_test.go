package main

import (
	"bytes"
	"net"
	"testing"
)

func TestSignalCodec(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a, b := newSigConn(c1), newSigConn(c2)

	go func() {
		if err := a.send(sigMsg{Type: "offer", SDP: "v=0..."}); err != nil {
			t.Error(err)
		}
		if err := a.send(sigMsg{Type: "ready"}); err != nil {
			t.Error(err)
		}
	}()
	m, err := b.recv()
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "offer" || m.SDP != "v=0..." {
		t.Fatalf("offer mismatch: %+v", m)
	}
	m, err = b.recv()
	if err != nil {
		t.Fatal(err)
	}
	if m.Type != "ready" {
		t.Fatalf("ready mismatch: %+v", m)
	}
}

func TestSignalBadJSON(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	go w.Write([]byte("this is not json\n"))
	w.Close()
	c := newSigConn(r)
	if _, err := c.recv(); err == nil {
		t.Fatal("bad json accepted")
	}
}

func TestSignalLargeSDP(t *testing.T) {
	// A full SDP with candidates is a few KB; make sure the bufio sizes cope.
	sdp := bytes.Repeat([]byte("x"), 64*1024)
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	a, b := newSigConn(c1), newSigConn(c2)
	go func() {
		if err := a.send(sigMsg{Type: "answer", SDP: string(sdp)}); err != nil {
			t.Error(err)
		}
	}()
	m, err := b.recv()
	if err != nil {
		t.Fatal(err)
	}
	if len(m.SDP) != len(sdp) {
		t.Fatalf("large sdp truncated: %d", len(m.SDP))
	}
}
