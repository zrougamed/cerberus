//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// The kernel ring per interface: 4 blocks of 1 MiB. The kernel fills a
	// block and hands it over whole, so the reader wakes once per block
	// (or per retire timeout) instead of once per frame.
	ringBlockSize = 1 << 20
	ringBlocks    = 4
	ringFrameSize = 2048 // required by the API; V3 packs frames tightly anyway
	// retireTimeoutMs hands over a partly filled block on quiet links.
	retireTimeoutMs = 100
	pollTimeoutMs   = 100
	statsInterval   = time.Second
)

// memFence orders reads of a block against the kernel's writes. Any
// sync/atomic operation is a full barrier for the Go compiler and an
// acquire-release on arm64, which is what the TPACKET protocol needs
// around block_status; this avoids an unsafe pointer into the mapping.
var memFence atomic.Uint32

// afPacketSource reads every frame on one interface through a
// memory-mapped TPACKET_V3 ring. It needs CAP_NET_RAW, which Cerberus
// already holds for BPF.
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

func (s *afPacketSource) Run(ctx context.Context, sink Sink) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("open packet socket: %w", err)
	}
	defer unix.Close(fd)
	ring, err := s.setup(fd)
	if err != nil {
		return err
	}
	defer unix.Munmap(ring)

	pfd := []unix.PollFd{{Fd: fdInt32(fd), Events: unix.POLLIN | unix.POLLERR}}
	nextStats := time.Now().Add(statsInterval)
	for i := 0; ctx.Err() == nil; {
		if now := time.Now(); now.After(nextStats) {
			nextStats = now.Add(statsInterval)
			if st, err := unix.GetsockoptTpacketStatsV3(fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil && st.Drops > 0 {
				sink.Drops(uint64(st.Drops))
			}
		}
		block := ring[i*ringBlockSize : (i+1)*ringBlockSize]
		if !blockReady(block) {
			if _, err := unix.Poll(pfd, pollTimeoutMs); err != nil && !errors.Is(err, unix.EINTR) {
				return fmt.Errorf("poll %s: %w", s.iface.Name, err)
			}
			continue
		}
		memFence.Add(1) // acquire: frame data after block_status
		sink.Frames(func(add func(int64, []byte, int)) { walkBlock(block, add) })
		memFence.Add(1) // release: our reads before handing the block back
		releaseBlock(block)
		i = (i + 1) % ringBlocks
	}
	return nil
}

// setup switches the socket to TPACKET_V3, truncates frames in the kernel
// to snaplen, maps the ring and binds to the interface.
func (s *afPacketSource) setup(fd int) ([]byte, error) {
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); err != nil {
		return nil, fmt.Errorf("select TPACKET_V3: %w", err)
	}
	// One classic BPF instruction, "accept snaplen bytes": the kernel then
	// copies only what is kept into the ring.
	filter := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: u32(s.snaplen)}}
	prog := unix.SockFprog{Len: 1, Filter: &filter[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return nil, fmt.Errorf("attach snaplen filter: %w", err)
	}
	req := unix.TpacketReq3{
		Block_size:     ringBlockSize,
		Block_nr:       ringBlocks,
		Frame_size:     ringFrameSize,
		Frame_nr:       ringBlockSize * ringBlocks / ringFrameSize,
		Retire_blk_tov: retireTimeoutMs,
	}
	if err := unix.SetsockoptTpacketReq3(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		return nil, fmt.Errorf("create packet ring: %w", err)
	}
	ring, err := unix.Mmap(fd, 0, ringBlockSize*ringBlocks, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map packet ring: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: s.iface.Index}); err != nil {
		_ = unix.Munmap(ring)
		return nil, fmt.Errorf("bind packet socket to %s: %w", s.iface.Name, err)
	}
	return ring, nil
}

func fdInt32(fd int) int32 {
	if fd < 0 || fd > math.MaxInt32 {
		return -1
	}
	return int32(fd)
}
