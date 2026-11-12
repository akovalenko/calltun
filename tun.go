package main

// Attach to an existing persistent TUN/TAP device, the same way ssh does
// for `ssh -w` (see notes/ssh-w-tun.md): open /dev/net/tun, TUNSETIFF with
// the device name and mode, IFF_NO_PI for raw frames. Creating the device,
// addresses, routes and MTU belong to the host (ifupdown/iproute2); with a
// persistent device owned by this user no CAP_NET_ADMIN is needed here.
//
// The fd is deliberately kept OUT of the os.File/netpoll machinery: on
// go1.26 the eager epoll registration of /dev/net/tun fds collides with
// the runtime's terminal probe (observed: another thread TCGETS2+close on
// the fd, reads then fail with "not pollable"). Raw blocking I/O only.

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

type tunFD struct {
	fd   int
	name string
}

func attachDevice(name string, tap bool) (*tunFD, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (exists? permissions?): %w", err)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if tap {
		flags = unix.IFF_TAP | unix.IFF_NO_PI
	}
	var ifr [unix.IFNAMSIZ + 2]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	*(*uint16)(unsafe.Pointer(&ifr[unix.IFNAMSIZ])) = flags
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		unix.Close(fd)
		switch errno {
		case unix.EPERM:
			return nil, fmt.Errorf("attach %s: EPERM (device exists and owned by this user?)", name)
		case unix.ENODEV:
			return nil, fmt.Errorf("attach %s: no such device (create it first: ip tuntap add)", name)
		default:
			return nil, fmt.Errorf("attach %s: %w", name, errno)
		}
	}
	return &tunFD{fd: fd, name: name}, nil
}

// Read blocks until a frame arrives; raw blocking syscall, no netpoll.
func (t *tunFD) Read(p []byte) (int, error) {
	for {
		n, err := unix.Read(t.fd, p)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("read %s: %w", t.name, err)
		}
		return n, nil
	}
}

// Write sends one frame; TUN writes are all-or-nothing, but loop anyway.
func (t *tunFD) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := unix.Write(t.fd, p[written:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return written, fmt.Errorf("write %s: %w", t.name, err)
		}
		written += n
	}
	return written, nil
}

func (t *tunFD) Close() error {
	return unix.Close(t.fd)
}
