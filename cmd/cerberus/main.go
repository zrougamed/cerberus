package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/zrougamed/cerberus/internal/alerts"
	"github.com/zrougamed/cerberus/internal/api"
	"github.com/zrougamed/cerberus/internal/databases"
	"github.com/zrougamed/cerberus/internal/kstats"
	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"
	"github.com/zrougamed/cerberus/internal/network"
	"github.com/zrougamed/cerberus/internal/policy"
	"github.com/zrougamed/cerberus/internal/utils"
	"github.com/zrougamed/cerberus/internal/version"
)

func main() {
	fmt.Printf("Cerberus %s\n", version.String())

	// No startup TC/XDP cleanup: TCX links are owned by this process and the
	// kernel detaches them when it exits, so nothing is left behind. The old
	// cleanup deleted every interface's clsact/ingress qdisc and XDP program,
	// breaking other TC users (Cilium, tc-based shapers, other BPF tools).

	// Ensure the data directory exists
	err := os.MkdirAll("./data", 0o750)
	if err != nil {
		log.Fatalf("failed to create data directory: %v", err)
	}

	// Initialize monitor (optional CERBERUS_ALERTS_CONFIG for declarative rules)
	alertCfg := alerts.DefaultConfig()
	if alertsPath := os.Getenv("CERBERUS_ALERTS_CONFIG"); alertsPath != "" {
		loaded, err := alerts.LoadFile(alertsPath)
		if err != nil {
			log.Fatalf("alerts config: %v", err)
		}
		alertCfg = loaded
		fmt.Printf("Loaded alerts config from %s\n", alertsPath)
	}
	mon, err := monitor.NewNetworkMonitorWithAlerts(1000, "./data/network.db", alertCfg)
	if err != nil {
		panic(err)
	}
	defer mon.Close()
	if geoipDBPath := os.Getenv("CERBERUS_GEOIP_DB"); geoipDBPath != "" {
		if err := mon.EnableGeoIP(geoipDBPath); err != nil {
			fmt.Printf("GeoIP disabled: failed to load DB %q: %v\n", geoipDBPath, err)
		} else {
			fmt.Printf("GeoIP enabled with DB: %s\n", geoipDBPath)
		}
	}

	// Start REST API + dashboard server
	apiAddr := os.Getenv("CERBERUS_HTTP_ADDR")
	if apiAddr == "" {
		apiAddr = "127.0.0.1:8080"
	}
	apiServer := api.NewServer(mon)

	// Active response: the policy is loaded now (so the API can serve it)
	// and pushed to the kernel once the BPF collection exists.
	policyEngine, err := openPolicy()
	if err != nil {
		log.Fatalf("%v", err)
	}
	apiServer.SetPolicy(policyEngine)
	if err := apiServer.SetAPIToken(os.Getenv("CERBERUS_API_TOKEN")); err != nil {
		log.Fatalf("CERBERUS_API_TOKEN: %v", err)
	}
	if os.Getenv("CERBERUS_API_TOKEN") == "" {
		fmt.Println("Policy changes disabled: set CERBERUS_API_TOKEN to manage rules from the console/API")
	}

	apiHandler, err := apiServer.Handler()
	if err != nil {
		panic(fmt.Errorf("failed to create API handler: %w", err))
	}
	httpServer := &http.Server{
		Addr:              apiAddr,
		Handler:           apiHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		fmt.Printf("Dashboard available at http://%s\n", apiAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("API server error: %v\n", err)
		}
	}()
	defer func() {
		_ = httpServer.Close()
	}()

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

	policyMaps, err := policy.NewBPFMaps(coll.Maps)
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	if err := policyEngine.Bind(policyMaps); err != nil {
		log.Fatalf("%v", err)
	}
	st := policyEngine.Status()
	fmt.Printf("Policy loaded: %d rule(s), mode=%s\n", len(st.Rules), st.Mode)
	stopPolicy := make(chan struct{})
	defer close(stopPolicy)
	go policyLoop(policyEngine, mon, stopPolicy)
	if logMap := coll.Maps["filter_log"]; logMap != nil {
		logReader, err := ringbuf.NewReader(logMap)
		if err != nil {
			log.Fatalf("filter log ring buffer: %v", err)
		}
		defer logReader.Close()
		go readFilterLog(logReader, policyEngine)
	}

	if countersMap := coll.Maps["counters"]; countersMap != nil {
		apiServer.SetKernelStats(kstats.NewReader(countersMap).Read)
	} else {
		fmt.Println("BPF object has no 'counters' map; kernel counters disabled")
	}

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

	// CERBERUS_INTERFACES narrows the attach set (names/globs, "!" excludes).
	ifaceFilter, err := network.ParseInterfaceFilter(os.Getenv("CERBERUS_INTERFACES"))
	if err != nil {
		log.Fatalf("CERBERUS_INTERFACES: %v", err)
	}

	var links []link.Link
	attachedCount := 0

	for _, iface := range ifaceFilter.Select(ifaces) {
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
		// Expected packet size as defined in cerberus_tc.c
		expectedSize := models.EventSize

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
					utils.EventSrcIPString(evt), utils.EventDstIPString(evt),
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

// openPolicy loads the persisted policy from CERBERUS_POLICY_FILE (default
// <data dir>/policy.json) and protects this host's and the gateway's
// addresses from accidental blocking.
func openPolicy() (*policy.Engine, error) {
	path := os.Getenv("CERBERUS_POLICY_FILE")
	if path == "" {
		path = filepath.Join(databases.DataDir(), "policy.json")
	}
	topology, _ := network.DetectNetworkTopology()
	addrs, macs := network.ProtectedTargets(topology)
	return policy.Open(policy.Options{StatePath: path, Protected: addrs, ProtectedMAC: macs})
}

// policyLoop expires temporary rules and turns rule counter growth into
// alerts (at most one per rule per 10 minutes).
func policyLoop(e *policy.Engine, mon *monitor.NetworkMonitor, stop <-chan struct{}) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		for _, r := range e.Expire() {
			fmt.Printf("Policy rule %s expired\n", r.ID)
		}
		for _, h := range e.PollHits() {
			mon.RecordAlert(policyHitAlert(h))
		}
	}
}

// readFilterLog feeds filter "log" events to the engine until the reader is
// closed at shutdown.
func readFilterLog(r *ringbuf.Reader, e *policy.Engine) {
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		if err := e.RecordLog(rec.RawSample); err != nil {
			fmt.Printf("filter log: %v\n", err)
		}
	}
}

func policyHitAlert(h policy.Hit) models.AlertEvent {
	if h.Filter != nil {
		return filterHitAlert(h)
	}
	target := h.Rule.CIDR
	if h.Rule.MAC != "" {
		target = "MAC " + h.Rule.MAC
	}
	verb, severity := "matched", "low"
	switch {
	case h.Enforced:
		verb, severity = "dropped", "high"
	case h.Rule.Action == policy.ActionDrop:
		verb, severity = "would have dropped (monitor mode)", "medium"
	}
	return models.AlertEvent{
		DeviceMAC: h.Rule.MAC,
		Rule:      "policy:" + h.Rule.ID,
		Severity:  severity,
		Message: fmt.Sprintf("Policy rule %s %s %d packet(s) for %s (total %d)",
			h.Rule.ID, verb, h.Delta.Packets, target, h.Total.Packets),
	}
}

func filterHitAlert(h policy.Hit) models.AlertEvent {
	f := h.Filter
	verb, severity := "matched", "low"
	switch {
	case h.Enforced:
		verb, severity = "dropped", "high"
	case f.Verdict == policy.VerdictDrop:
		verb, severity = "would have dropped (monitor mode)", "medium"
	case f.Verdict == policy.VerdictAccept:
		verb = "allowed"
	}
	return models.AlertEvent{
		DeviceMAC: f.Match.SrcMAC,
		Rule:      "filter:" + f.ID,
		Severity:  severity,
		Message: fmt.Sprintf("Filter %s %s %d packet(s) matching %s (total %d)",
			f.ID, verb, h.Delta.Packets, f.Match.Summary(), h.Total.Packets),
	}
}
