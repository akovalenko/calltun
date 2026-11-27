package cli

// Attach to an existing persistent TUN/TAP device, the same way ssh does
// for `ssh -w` (see notes/ssh-w-tun.md): open /dev/net/tun, TUNSETIFF with
// the device name and mode, IFF_NO_PI for raw frames. Creating the device,
// addresses, routes and MTU belong to the host (ifupdown/iproute2); with a
// persistent device owned by this user no CAP_NET_ADMIN is needed here.
//
// I/O runs on the runtime netpoller: the descriptor is opened non-blocking
// up front and wrapped with os.NewFile only AFTER a successful TUNSETIFF —
// the tun driver only polls an attached fd, and os.NewFile registers a
// descriptor with the poller only when it is already non-blocking, so both
// must be true before the wrap (golang/go#30426; the songgao/water order,
// water/syscalls_linux_go1.11.go). Reads then park the goroutine instead of
// pinning an OS thread, Close wakes a blocked reader, and deadlines work.

import (
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

// attachTun returns the tunnel device handle. CALLTUN_FD (set by an
// fd-passing helper — `nsm tunfd`, see plans/calltun.md) means the
// descriptor was already attached to the persistent device inside its own
// network namespace and inherited here on exec; take it as is. Otherwise
// attach locally.
func attachTun(name string, tap bool) (*os.File, error) {
	if spec := os.Getenv("CALLTUN_FD"); spec != "" {
		return takeFD(spec, name)
	}
	return attachDevice(name, tap)
}

func attachDevice(name string, tap bool) (*os.File, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (exists? permissions?): %w", err)
	}
	if err := tunSetIFF(fd, name, tap); err != nil {
		unix.Close(fd)
		return nil, err
	}
	// MTU gate: with fire-and-forget framing a frame larger than the
	// budget would be silently lost — and TCP inside sizes its segments
	// from the interface MTU, so a whole segment class would die quietly.
	// Refuse instead: crash-only, the misconfiguration is visible in the
	// unit log.
	if b, err := os.ReadFile("/sys/class/net/" + name + "/mtu"); err == nil {
		var mtu int
		if _, err := fmt.Sscanf(string(b), "%d", &mtu); err == nil && mtu > maxFrame {
			unix.Close(fd)
			return nil, mtuGateError(name, mtu)
		}
	}
	return os.NewFile(uintptr(fd), name), nil
}

// takeFD adopts a descriptor delivered by a helper. TUNSETIFF already
// happened on the helper's side (in the device's namespace), so there is
// nothing to attach here — only the netpoller wrap, in non-blocking mode
// (see the file comment). The MTU gate reads CALLTUN_MTU: /sys/class/net
// is namespace-tagged, and this process sits in the underlay namespace,
// which does not see the device.
func takeFD(spec, name string) (*os.File, error) {
	fd, err := strconv.Atoi(spec)
	if err != nil || fd < 0 {
		return nil, fmt.Errorf("CALLTUN_FD=%q: want a file descriptor number", spec)
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0); err != nil {
		return nil, fmt.Errorf("CALLTUN_FD=%d: not an open descriptor: %w", fd, err)
	}
	if spec := os.Getenv("CALLTUN_MTU"); spec != "" {
		if mtu, err := strconv.Atoi(spec); err == nil && mtu > maxFrame {
			return nil, mtuGateError(name, mtu)
		}
	} else {
		lg.Debug("CALLTUN_MTU not set: MTU gate skipped (helper should deliver it)")
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("CALLTUN_FD=%d: O_NONBLOCK: %w", fd, err)
	}
	return os.NewFile(uintptr(fd), name), nil
}

// tunSetIFF attaches fd to the named persistent device, tun or tap.
func tunSetIFF(fd int, name string, tap bool) error {
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if tap {
		flags = uint16(unix.IFF_TAP | unix.IFF_NO_PI)
	}
	var ifr [unix.IFNAMSIZ + 2]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		switch errno {
		case unix.EPERM:
			return fmt.Errorf("attach %s: EPERM (device exists and owned by this user?)", name)
		case unix.ENODEV:
			return fmt.Errorf("attach %s: no such device (create it first: ip tuntap add)", name)
		default:
			return fmt.Errorf("attach %s: %w", name, errno)
		}
	}
	return nil
}

func mtuGateError(name string, mtu int) error {
	return fmt.Errorf("%s: MTU %d exceeds the fire-and-forget budget %d — set the device MTU to %d or lower",
		name, mtu, maxFrame, maxFrame)
}
