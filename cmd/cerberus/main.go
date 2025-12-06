// embed
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
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
	monitor, err := monitor.NewNetworkMonitor(1000, "network.db")
	if err != nil {
		panic(err)
	}
	defer monitor.Close()

	module, err := bpf.NewModuleFromFile("arp_xdp.o")
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

	fmt.Println(" Scanning for network interfaces...")

	var hooks []HookInfo
	attachedCount := 0

	for _, iface := range ifaces {
		// TODO: listen to interface state changes (up/down) and handle accordingly
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// TODO: work on feeding this using yaml config
		// Skip virtual interfaces (optional - remove these conditions to monitor everything)
		ifaceName := iface.Name
		if strings.HasPrefix(ifaceName, "veth") ||
			strings.HasPrefix(ifaceName, "cali") ||
			strings.HasPrefix(ifaceName, "docker") ||
			strings.HasPrefix(ifaceName, "br-") ||
			strings.HasPrefix(ifaceName, "flannel") {
			fmt.Printf("Skipping virtual interface: %s\n", ifaceName)
			continue
		}

		fmt.Printf(" Attaching to %s...\n", ifaceName)

		hook := module.TcHookInit()
		if err := hook.SetInterfaceByName(ifaceName); err != nil {
			fmt.Printf("️Failed to set interface %s: %v\n", ifaceName, err)
			continue
		}

		hook.SetAttachPoint(bpf.BPFTcIngress)

		// Clean up any existing hooks first
		hook.Destroy()

		// Create new hook
		if err := hook.Create(); err != nil {
			fmt.Printf("️  Failed to create TC hook on %s: %v\n", ifaceName, err)
			continue
		}

		tcOpts := &bpf.TcOpts{
			ProgFd: int(prog.GetFd()),
		}

		if err := hook.Attach(tcOpts); err != nil {
			fmt.Printf("️  Failed to attach TC hook to %s: %v\n", ifaceName, err)
			hook.Destroy()
			continue
		}

		hooks = append(hooks, HookInfo{hook: hook, tcOpts: tcOpts})
		attachedCount++
		fmt.Printf(" Successfully attached to %s\n", ifaceName)
	}

	if attachedCount == 0 {
		panic(" Failed to attach to any interface!")
	}

	fmt.Printf("\n Monitoring %d interface(s)\n\n", attachedCount)

	// Cleanup hooks on exit
	defer func() {
		fmt.Println("\n Cleaning up hooks...")
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

	fmt.Println(" Monitoring network traffic... Press Ctrl+C to exit")
	fmt.Println(" Stats will be printed every 60 seconds\n")

	// Add debug ticker to show we're alive
	debugTicker := time.NewTicker(10 * time.Second)
	defer debugTicker.Stop()

	go func() {
		for range debugTicker.C {
			fmt.Printf(" Alive - Packets: Total=%d ARP=%d TCP=%d UDP=%d | Devices=%d\n",
				monitor.Stats.TotalPackets,
				monitor.Stats.ArpPackets,
				monitor.Stats.TcpPackets,
				monitor.Stats.UdpPackets,
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
		for data := range eventsChan {
			eventCount++

			if len(data) < 41 { // Changed from 44 to 41
				fmt.Printf("️  Short packet: %d bytes (expected 41)\n", len(data))
				continue
			}

			evt := utils.ParseNetworkEvent(data)

			// Debug: Print first 5 events
			if eventCount <= 5 {
				fmt.Printf(" Event #%d: Type=%d SrcIP=%s DstIP=%s SrcPort=%d DstPort=%d\n",
					eventCount, evt.EventType,
					utils.IntToIP(evt.SrcIP), utils.IntToIP(evt.DstIP),
					evt.SrcPort, evt.DstPort)
			}

			monitor.TrackEvent(evt)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\n\n Final Statistics:")
	monitor.PrintStats()
	fmt.Println(" Shutting down...")
}
