//go:build linux

package capture

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"
)

// readTimeout lets the read loop notice cancellation.
const readTimeout = time.Second

// afPacketSource reads every frame on one interface through an AF_PACKET
// socket. It needs CAP_NET_RAW, which Cerberus already holds for BPF.
type afPacketSource struct {
	iface   net.Interface
	snaplen int
}

// NewInterfaceSource returns a source for the named interface.
func NewInterfaceSource(name string, snaplen int) (Source, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("capture interface %q: %w", name, err)
	}
	return &afPacketSource{iface: *ifc, snaplen: snaplen}, nil
}

func (s *afPacketSource) Name() string { return s.iface.Name }

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (s *afPacketSource) Run(ctx context.Context, emit func([]byte, int)) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("open packet socket: %w", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: s.iface.Index}); err != nil {
		return fmt.Errorf("bind packet socket to %s: %w", s.iface.Name, err)
	}
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set read timeout: %w", err)
	}
	buf := make([]byte, s.snaplen)
	for ctx.Err() == nil {
		// MSG_TRUNC makes the return value the frame's full length.
		n, _, err := unix.Recvfrom(fd, buf, unix.MSG_TRUNC)
		switch {
		case err == unix.EAGAIN || err == unix.EINTR:
			continue
		case err != nil:
			return fmt.Errorf("read %s: %w", s.iface.Name, err)
		}
		kept := min(n, len(buf))
		emit(append([]byte(nil), buf[:kept]...), n)
	}
	return nil
}
