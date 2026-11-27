package cli

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// A pipe stands in for the tun descriptor: takeFD must adopt any inherited
// fd into the netpoller, which the blocking-mode flag and a parked Read
// both witness. (Creating a real tun needs CAP_NET_ADMIN; the attach order
// itself is exercised on the bench.)
func TestTakeFDAdoptsDescriptor(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])

	t.Setenv("CALLTUN_FD", strconv.Itoa(fds[0]))
	t.Setenv("CALLTUN_MTU", "1370")
	f, err := attachTun("tun9", false)
	if err != nil {
		t.Fatalf("attachTun: %v", err)
	}
	defer f.Close()

	// The wrap must leave the descriptor non-blocking: os.NewFile only
	// registers an already-non-blocking fd with the netpoller.
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("descriptor left blocking (flags %#x)", flags)
	}

	if _, err := unix.Write(fds[1], []byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if err := f.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, err := f.Read(buf)
	if err != nil || string(buf[:n]) != "ping" {
		t.Fatalf("read: %d %q %v", n, buf[:n], err)
	}
}

func TestTakeFDMTUGate(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	t.Setenv("CALLTUN_FD", strconv.Itoa(fds[0]))
	t.Setenv("CALLTUN_MTU", strconv.Itoa(maxFrame+1))
	_, err := attachTun("tun9", false)
	if err == nil || !strings.Contains(err.Error(), "MTU") {
		t.Fatalf("want MTU gate refusal, got %v", err)
	}
}

func TestTakeFDGarbage(t *testing.T) {
	t.Setenv("CALLTUN_FD", "not-a-number")
	if _, err := attachTun("tun9", false); err == nil {
		t.Fatal("want an error for a non-numeric CALLTUN_FD")
	}
	t.Setenv("CALLTUN_FD", "99999")
	if _, err := attachTun("tun9", false); err == nil {
		t.Fatal("want an error for a closed descriptor")
	}
}
