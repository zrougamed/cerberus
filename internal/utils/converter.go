package utils

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/zrougamed/cerberus/internal/models"
)

func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func Max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func ParseNetworkEvent(data []byte) *models.NetworkEvent {
	evt := &models.NetworkEvent{}
	offset := 0

	evt.EventType = data[offset]
	offset += 1 // 1

	copy(evt.SrcMac[:], data[offset:offset+6])
	offset += 6 // 7

	copy(evt.DstMac[:], data[offset:offset+6])
	offset += 6 // 13

	evt.SrcIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4 // 17

	evt.DstIP = binary.LittleEndian.Uint32(data[offset : offset+4])
	offset += 4 // 21

	evt.SrcPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2 // 23

	evt.DstPort = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2 // 25

	evt.Protocol = data[offset]
	offset += 1 // 26

	evt.TCPFlags = data[offset]
	offset += 1 // 27

	evt.ArpOp = binary.LittleEndian.Uint16(data[offset : offset+2])
	offset += 2 // 29

	copy(evt.ArpSha[:], data[offset:offset+6])
	offset += 6 // 35

	copy(evt.ArpTha[:], data[offset:offset+6])
	offset += 6 // 41

	return evt
}

func IntToIP(i uint32) net.IP {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return net.IP(b)
}

func MacToString(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}
