// embed
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/utils"

	bpf "github.com/aquasecurity/libbpfgo"
)

type HookInfo struct {
	hook   *bpf.TcHook
	tcOpts *bpf.TcOpts
}

func main() {
	utils.CleanCards()
	monitor, err := monitor.NewNetworkMonitor(1000, "./data/network.db")
	if err != nil {
		panic(err)
	}
	defer monitor.Close()

	module, err := bpf.NewModuleFromFile("monitor_xdp.o")
	if err != nil {
		panic(err)
	}
	defer module.Close()

	if err := module.BPFLoadObject(); err != nil {
		panic(err)
	}

	prog, err := module.GetProgram("xdp_arp_monitor")
	if err != nil {
		panic(err)
	}

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	fmt.Println("Scanning for network interfaces...")

	var hooks []HookInfo
	attachedCount := 0

	for _, iface := range ifaces {
		// TODO: listen to interface state changes (up/down) and handle accordingly
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		ifaceName := iface.Name

		fmt.Printf("Attaching to %s...\n", ifaceName)

		hook := module.TcHookInit()
		if err := hook.SetInterfaceByName(ifaceName); err != nil {
			fmt.Printf("Failed to set interface %s: %v\n", ifaceName, err)
			continue
		}

		hook.SetAttachPoint(bpf.BPFTcIngress)

		// Clean up any existing hooks first
		hook.Destroy()

		// Create new hook
		if err := hook.Create(); err != nil {
			fmt.Printf("Failed to create TC hook on %s: %v\n", ifaceName, err)
			continue
		}

		tcOpts := &bpf.TcOpts{
			ProgFd: int(prog.GetFd()),
		}

		if err := hook.Attach(tcOpts); err != nil {
			fmt.Printf("Failed to attach TC hook to %s: %v\n", ifaceName, err)
			hook.Destroy()
			continue
		}

		hooks = append(hooks, HookInfo{hook: hook, tcOpts: tcOpts})
		attachedCount++
		fmt.Printf("Successfully attached to %s\n", ifaceName)
	}

	if attachedCount == 0 {
		panic("Failed to attach to any interface!")
	}

	fmt.Printf("\nMonitoring %d interface(s)\n\n", attachedCount)

	// Cleanup hooks on exit
	defer func() {
		fmt.Println("\nCleaning up hooks...")
		for _, h := range hooks {
			h.hook.Detach(h.tcOpts)
			h.hook.Destroy()
		}
	}()

	eventsChan := make(chan []byte)
	rb, err := module.InitRingBuf("events", eventsChan)
	if err != nil {
		panic(err)
	}
	defer rb.Close()

	rb.Start()
	defer rb.Stop()

	fmt.Println("Monitoring network traffic... Press Ctrl+C to exit")
	fmt.Println("Stats will be printed every 60 seconds")

	// Add debug ticker to show we're alive
	debugTicker := time.NewTicker(10 * time.Second)
	defer debugTicker.Stop()

	go func() {
		for range debugTicker.C {
			fmt.Printf("Alive - Packets: Total=%d ARP=%d TCP=%d UDP=%d ICMP=%d DNS=%d HTTP=%d TLS=%d | Devices=%d\n",
				monitor.Stats.TotalPackets,
				monitor.Stats.ArpPackets,
				monitor.Stats.TcpPackets,
				monitor.Stats.UdpPackets,
				monitor.Stats.IcmpPackets,
				monitor.Stats.DnsPackets,
				monitor.Stats.HttpPackets,
				monitor.Stats.TlsPackets,
				monitor.Cache.Len())
		}
	}()

	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range statsTicker.C {
			monitor.PrintStats()
		}
	}()

	go func() {
		eventCount := 0
		// Expected packet size: 1 + 6 + 6 + 4 + 4 + 2 + 2 + 1 + 1 + 2 + 6 + 6 + 1 + 1 + 32 = 75 bytes
		expectedSize := 75

		for data := range eventsChan {
			eventCount++

			if len(data) < expectedSize {
				fmt.Printf("Short packet: %d bytes (expected %d)\n", len(data), expectedSize)
				continue
			}

			evt := utils.ParseNetworkEvent(data)

			// Debug: Print first 10 events to verify parsing
			if eventCount <= 10 {
				eventTypeStr := "UNKNOWN"
				switch evt.EventType {
				case 1:
					eventTypeStr = "ARP"
				case 2:
					eventTypeStr = "TCP"
				case 3:
					eventTypeStr = "UDP"
				case 4:
					eventTypeStr = "ICMP"
				case 5:
					eventTypeStr = "DNS"
				case 6:
					eventTypeStr = "HTTP"
				case 7:
					eventTypeStr = "TLS"
				}

				fmt.Printf("Event #%d: Type=%s(%d) SrcIP=%s DstIP=%s SrcPort=%d DstPort=%d\n",
					eventCount, eventTypeStr, evt.EventType,
					utils.IntToIP(evt.SrcIP), utils.IntToIP(evt.DstIP),
					evt.SrcPort, evt.DstPort)
			}

			monitor.TrackEvent(evt)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\n\nFinal Statistics:")
	monitor.PrintStats()
	fmt.Println("Shutting down...")
}
