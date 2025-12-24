package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/utils"
)

func main() {
	// Clean up any existing TC hooks
	utils.CleanCards()

	// Ensure the data directory exists
	err := os.MkdirAll("./data", 0755)
	if err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	// Initialize monitor
	mon, err := monitor.NewNetworkMonitor(1000, "./data/network.db")
	if err != nil {
		panic(err)
	}
	defer mon.Close()

	// Load BPF collection from compiled object file
	spec, err := ebpf.LoadCollectionSpec("cerberus_tc.o")
	if err != nil {
		panic(fmt.Errorf("failed to load BPF spec: %w", err))
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(fmt.Errorf("failed to create BPF collection: %w", err))
	}
	defer coll.Close()

	// Get the classifier program
	prog := coll.Programs["xdp_arp_monitor"]
	if prog == nil {
		panic("BPF program 'xdp_arp_monitor' not found in object file")
	}

	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	fmt.Println("Scanning for network interfaces...")

	var links []link.Link
	attachedCount := 0

	for _, iface := range ifaces {
		// Skip loopback and down interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		fmt.Printf("Attaching to %s...\n", iface.Name)

		// Attach using TCX (modern TC hook mechanism)
		// TCX is the new way to attach TC programs, replacing the old clsact qdisc approach
		l, err := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   prog,
			Attach:    ebpf.AttachTCXIngress,
		})
		if err != nil {
			fmt.Printf("Failed to attach to %s: %v\n", iface.Name, err)
			continue
		}

		links = append(links, l)
		attachedCount++
		fmt.Printf("Successfully attached to %s\n", iface.Name)
	}

	if attachedCount == 0 {
		panic("Failed to attach to any interface!")
	}

	fmt.Printf("\nMonitoring %d interface(s)\n\n", attachedCount)

	// Cleanup hooks on exit
	defer func() {
		fmt.Println("\nCleaning up hooks...")
		for _, l := range links {
			if err := l.Close(); err != nil {
				fmt.Printf("Error cleaning up link: %v\n", err)
			}
		}
	}()

	// Open ring buffer for event communication
	eventsMap := coll.Maps["events"]
	if eventsMap == nil {
		panic("Ring buffer map 'events' not found")
	}

	reader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		panic(fmt.Errorf("failed to open ring buffer: %w", err))
	}
	defer reader.Close()

	fmt.Println("Monitoring network traffic... Press Ctrl+C to exit")
	fmt.Println("Stats will be printed every 60 seconds")

	// Debug ticker to show we're alive
	debugTicker := time.NewTicker(10 * time.Second)
	defer debugTicker.Stop()

	go func() {
		for range debugTicker.C {
			fmt.Printf("Alive - Packets: Total=%d ARP=%d TCP=%d UDP=%d ICMP=%d DNS=%d HTTP=%d TLS=%d | Devices=%d\n",
				mon.Stats.TotalPackets,
				mon.Stats.ArpPackets,
				mon.Stats.TcpPackets,
				mon.Stats.UdpPackets,
				mon.Stats.IcmpPackets,
				mon.Stats.DnsPackets,
				mon.Stats.HttpPackets,
				mon.Stats.TlsPackets,
				mon.Cache.Len())
		}
	}()

	// Statistics ticker
	statsTicker := time.NewTicker(60 * time.Second)
	defer statsTicker.Stop()

	go func() {
		for range statsTicker.C {
			mon.PrintStats()
		}
	}()

	// Event processor goroutine
	go func() {
		eventCount := 0
		// Expected packet size: 79 bytes as defined in cerberus_tc.c
		expectedSize := 79

		for {
			// Read event from ring buffer
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					fmt.Println("Ring buffer closed, stopping event processor")
					return
				}
				fmt.Printf("Error reading from ring buffer: %v\n", err)
				continue
			}

			eventCount++

			// Validate packet size
			if len(record.RawSample) < expectedSize {
				fmt.Printf("Short packet: %d bytes (expected %d)\n",
					len(record.RawSample), expectedSize)
				continue
			}

			// Parse network event
			evt := utils.ParseNetworkEvent(record.RawSample)

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

			// Track event in monitor
			mon.TrackEvent(evt)
		}
	}()

	// Wait for interrupt signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	fmt.Println("\n\nFinal Statistics:")
	mon.PrintStats()
	fmt.Println("Shutting down...")
}
