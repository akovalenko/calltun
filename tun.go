package main

// Attach to an existing persistent TUN/TAP device, the same way ssh does
// for `ssh -w` (see notes/ssh-w-tun.md): open /dev/net/tun, TUNSETIFF with
// the device name and mode, IFF_NO_PI for raw frames. Creating the device,
// addresses, routes and MTU belong to the host (ifupdown/iproute2); with a
// persistent device owned by this user no CAP_NET_ADMIN is needed here.

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func attachDevice(name string, tap bool) (*os.File, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun (exists? permissions?): %w", err)
	}
	flags := uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if tap {
		flags = unix.IFF_TAP | unix.IFF_NO_PI
	}
	var ifr [unix.IFNAMSIZ + 2]byte
	copy(ifr[:unix.IFNAMSIZ-1], name)
	ifr[unix.IFNAMSIZ] = byte(flags)
	ifr[unix.IFNAMSIZ+1] = byte(flags >> 8)
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		f.Close()
		if errno == unix.EPERM {
			return nil, fmt.Errorf("attach %s: EPERM (device exists and owned by this user?)", name)
		}
		if errno == unix.ENODEV {
			return nil, fmt.Errorf("attach %s: no such device (create it first: ip tuntap add)", name)
		}
		return nil, fmt.Errorf("attach %s: %w", name, errno)
	}
	return f, nil
}
