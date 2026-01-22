package api

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/swagger"

	"github.com/zrougamed/cerberus/internal/models"
	"github.com/zrougamed/cerberus/internal/monitor"

	_ "github.com/zrougamed/cerberus/docs" // swagger docs
)

// Server represents the API server
type Server struct {
	app        *fiber.App
	monitor    *monitor.NetworkMonitor
	startTime  time.Time
	interfaces []InterfaceInfo
	mu         sync.RWMutex

	// SSE clients for pattern streaming
	patternClients   map[string]chan *models.CommunicationPattern
	patternClientsMu sync.RWMutex
}

// InterfaceInfo holds information about a monitored interface
type InterfaceInfo struct {
	Name            string   `json:"name" example:"eth0"`
	Index           int      `json:"index" example:"2"`
	MAC             string   `json:"mac" example:"00:11:22:33:44:55"`
	Addresses       []string `json:"addresses"`
	IsUp            bool     `json:"is_up" example:"true"`
	IsLoopback      bool     `json:"is_loopback" example:"false"`
	MTU             int      `json:"mtu" example:"1500"`
	PacketsCaptured int64    `json:"packets_captured" example:"12345"`
	Attached        bool     `json:"attached" example:"true"`
}

// NewServer creates a new API server instance
// @title Cerberus Network Monitor API
// @version 1.0
// @description REST API for Cerberus - a high-performance network monitoring tool built with eBPF.
// @termsOfService http://swagger.io/terms/
// @contact.name Cerberus Project
// @contact.url https://github.com/zrougamed/cerberus
// @license.name MIT
// @license.url https://opensource.org/licenses/MIT
// @host localhost:8080
// @BasePath /api/v1
// @schemes http
func NewServer(mon *monitor.NetworkMonitor) *Server {
	app := fiber.New(fiber.Config{
		AppName:      "Cerberus API",
		ServerHeader: "Cerberus",
		ErrorHandler: customErrorHandler,
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New(logger.Config{
		Format: "[${time}] ${status} - ${latency} ${method} ${path}\n",
	}))
	app.Use(cors.New(cors.Config{
		AllowOrigins: "*",
		AllowMethods: "GET,POST,PUT,DELETE,OPTIONS",
		AllowHeaders: "Origin,Content-Type,Accept,Authorization",
	}))

	server := &Server{
		app:            app,
		monitor:        mon,
		startTime:      time.Now(),
		patternClients: make(map[string]chan *models.CommunicationPattern),
	}

	// Setup routes
	server.setupRoutes()

	return server
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(ErrorResponse{
		Error: err.Error(),
		Code:  strconv.Itoa(code),
	})
}

func (s *Server) setupRoutes() {
	// Swagger documentation
	s.app.Get("/swagger/*", swagger.HandlerDefault)

	// API v1 routes
	api := s.app.Group("/api/v1")

	// Health & Stats
	api.Get("/health", s.healthCheck)
	api.Get("/stats", s.getStats)
	api.Get("/stats/history", s.getStatsHistory)

	// Devices
	api.Get("/devices", s.listDevices)
	api.Get("/devices/:mac", s.getDevice)
	api.Get("/devices/:mac/patterns", s.getDevicePatterns)
	api.Get("/devices/:mac/dns", s.getDeviceDNS)
	api.Get("/devices/:mac/services", s.getDeviceServices)

	// Patterns
	api.Get("/patterns", s.listPatterns)
	api.Get("/patterns/stream", s.streamPatterns)

	// Interfaces
	api.Get("/interfaces", s.listInterfaces)
	api.Get("/interfaces/:name", s.getInterface)

	// Lookup
	api.Get("/lookup/vendor/:mac", s.lookupVendor)
	api.Get("/lookup/service/:port", s.lookupService)
}

// SetInterfaces sets the list of monitored interfaces
func (s *Server) SetInterfaces(ifaces []InterfaceInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.interfaces = ifaces
}

// Start starts the API server
func (s *Server) Start(addr string) error {
	log.Printf("Starting API server on %s", addr)
	log.Printf("Swagger UI available at http://%s/swagger/index.html", addr)
	return s.app.Listen(addr)
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown() error {
	return s.app.Shutdown()
}

// BroadcastPattern sends a pattern to all SSE clients
func (s *Server) BroadcastPattern(pattern *models.CommunicationPattern) {
	s.patternClientsMu.RLock()
	defer s.patternClientsMu.RUnlock()

	for _, ch := range s.patternClients {
		select {
		case ch <- pattern:
		default:
			// Client buffer full, skip
		}
	}
}

// =============================================================================
// Response Types
// =============================================================================

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Device not found"`
	Code  string `json:"code" example:"404"`
}

// HealthResponse represents health check response
type HealthResponse struct {
	Status              string `json:"status" example:"healthy"`
	Uptime              int64  `json:"uptime" example:"86400"`
	Version             string `json:"version" example:"1.0.0"`
	InterfacesMonitored int    `json:"interfaces_monitored" example:"2"`
}

// NetworkStatsResponse represents network statistics
type NetworkStatsResponse struct {
	TotalPackets        uint64 `json:"total_packets" example:"1542890"`
	ArpPackets          uint64 `json:"arp_packets" example:"12543"`
	TcpPackets          uint64 `json:"tcp_packets" example:"987234"`
	UdpPackets          uint64 `json:"udp_packets" example:"432567"`
	IcmpPackets         uint64 `json:"icmp_packets" example:"1234"`
	DnsPackets          uint64 `json:"dns_packets" example:"45678"`
	HttpPackets         uint64 `json:"http_packets" example:"23456"`
	TlsPackets          uint64 `json:"tls_packets" example:"89012"`
	TotalDevices        int    `json:"total_devices" example:"47"`
	ActiveDevices       int    `json:"active_devices" example:"23"`
	UniquePatterns      int    `json:"unique_patterns" example:"1892"`
	InterfacesMonitored int    `json:"interfaces_monitored" example:"2"`
	UptimeSeconds       int64  `json:"uptime_seconds" example:"86400"`
}

// StatsHistoryResponse represents historical statistics
type StatsHistoryResponse struct {
	Interval   string           `json:"interval" example:"5m"`
	DataPoints []StatsDataPoint `json:"data_points"`
}

// StatsDataPoint represents a single data point in history
type StatsDataPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	TotalPackets  uint64    `json:"total_packets"`
	TcpPackets    uint64    `json:"tcp_packets"`
	UdpPackets    uint64    `json:"udp_packets"`
	DevicesActive int       `json:"devices_active"`
}

// DeviceListResponse represents a list of devices
type DeviceListResponse struct {
	Total   int                  `json:"total" example:"47"`
	Limit   int                  `json:"limit" example:"100"`
	Offset  int                  `json:"offset" example:"0"`
	Devices []*models.DeviceInfo `json:"devices"`
}

// PatternListResponse represents a list of patterns
type PatternListResponse struct {
	Total    int                            `json:"total" example:"1892"`
	Patterns []*models.CommunicationPattern `json:"patterns"`
}

// DNSDomainListResponse represents DNS domains for a device
type DNSDomainListResponse struct {
	MAC          string      `json:"mac" example:"00:11:22:33:44:55"`
	TotalQueries int         `json:"total_queries" example:"156"`
	Domains      []DNSDomain `json:"domains"`
}

// DNSDomain represents a DNS domain entry
type DNSDomain struct {
	Domain string `json:"domain" example:"google.com"`
	Count  int    `json:"count" example:"42"`
}

// ServiceAccessListResponse represents services accessed by a device
type ServiceAccessListResponse struct {
	MAC      string          `json:"mac" example:"00:11:22:33:44:55"`
	Services []ServiceAccess `json:"services"`
}

// ServiceAccess represents a service access entry
type ServiceAccess struct {
	Service  string `json:"service" example:"HTTPS"`
	Port     uint16 `json:"port" example:"443"`
	Protocol string `json:"protocol" example:"TCP"`
	Count    int    `json:"count" example:"89"`
}

// InterfaceListResponse represents a list of interfaces
type InterfaceListResponse struct {
	Interfaces []InterfaceInfo `json:"interfaces"`
}

// VendorInfoResponse represents vendor lookup response
type VendorInfoResponse struct {
	OUI     string `json:"oui" example:"00:11:22"`
	Vendor  string `json:"vendor" example:"Apple, Inc."`
	Address string `json:"address,omitempty"`
}

// ServiceInfoResponse represents service lookup response
type ServiceInfoResponse struct {
	Port        uint16 `json:"port" example:"443"`
	Protocol    string `json:"protocol" example:"TCP"`
	Service     string `json:"service" example:"https"`
	Description string `json:"description" example:"HTTP over TLS/SSL"`
}

// =============================================================================
// Handlers
// =============================================================================

// healthCheck godoc
// @Summary Health check
// @Description Returns service health status
// @Tags Statistics
// @Accept json
// @Produce json
// @Success 200 {object} HealthResponse
// @Router /health [get]
func (s *Server) healthCheck(c *fiber.Ctx) error {
	s.mu.RLock()
	interfaceCount := len(s.interfaces)
	s.mu.RUnlock()

	return c.JSON(HealthResponse{
		Status:              "healthy",
		Uptime:              int64(time.Since(s.startTime).Seconds()),
		Version:             "1.0.0",
		InterfacesMonitored: interfaceCount,
	})
}

// getStats godoc
// @Summary Get overall network statistics
// @Description Returns aggregate packet counts and network statistics
// @Tags Statistics
// @Accept json
// @Produce json
// @Success 200 {object} NetworkStatsResponse
// @Router /stats [get]
func (s *Server) getStats(c *fiber.Ctx) error {
	stats := s.monitor.GetStats()

	s.mu.RLock()
	interfaceCount := len(s.interfaces)
	s.mu.RUnlock()

	// Count active devices (seen in last 5 minutes)
	activeCount := 0
	uniquePatterns := 0
	fiveMinAgo := time.Now().Add(-5 * time.Minute)

	for _, device := range stats {
		if device.LastSeen.After(fiveMinAgo) {
			activeCount++
		}
		if device.SeenPatterns != nil {
			uniquePatterns += len(device.SeenPatterns)
		}
	}

	return c.JSON(NetworkStatsResponse{
		TotalPackets:        s.monitor.Stats.TotalPackets,
		ArpPackets:          s.monitor.Stats.ArpPackets,
		TcpPackets:          s.monitor.Stats.TcpPackets,
		UdpPackets:          s.monitor.Stats.UdpPackets,
		IcmpPackets:         s.monitor.Stats.IcmpPackets,
		DnsPackets:          s.monitor.Stats.DnsPackets,
		HttpPackets:         s.monitor.Stats.HttpPackets,
		TlsPackets:          s.monitor.Stats.TlsPackets,
		TotalDevices:        len(stats),
		ActiveDevices:       activeCount,
		UniquePatterns:      uniquePatterns,
		InterfacesMonitored: interfaceCount,
		UptimeSeconds:       int64(time.Since(s.startTime).Seconds()),
	})
}

// getStatsHistory godoc
// @Summary Get historical statistics
// @Description Returns time-series statistics data for charts
// @Tags Statistics
// @Accept json
// @Produce json
// @Param from query string false "Start timestamp (RFC3339)"
// @Param to query string false "End timestamp (RFC3339)"
// @Param interval query string false "Aggregation interval" Enums(1m, 5m, 15m, 1h, 1d) default(5m)
// @Success 200 {object} StatsHistoryResponse
// @Router /stats/history [get]
func (s *Server) getStatsHistory(c *fiber.Ctx) error {
	interval := c.Query("interval", "5m")

	// For now, return current stats as a single data point
	// TODO: Implement proper time-series storage
	return c.JSON(StatsHistoryResponse{
		Interval: interval,
		DataPoints: []StatsDataPoint{
			{
				Timestamp:     time.Now(),
				TotalPackets:  s.monitor.Stats.TotalPackets,
				TcpPackets:    s.monitor.Stats.TcpPackets,
				UdpPackets:    s.monitor.Stats.UdpPackets,
				DevicesActive: s.monitor.Cache.Len(),
			},
		},
	})
}

// listDevices godoc
// @Summary List all discovered devices
// @Description Returns all devices discovered on the network
// @Tags Devices
// @Accept json
// @Produce json
// @Param vendor query string false "Filter by vendor name (partial match)"
// @Param ip query string false "Filter by IP address"
// @Param active query int false "Filter by activity (seen within last N minutes)" default(5)
// @Param sort query string false "Sort field" Enums(mac, ip, vendor, last_seen, first_seen, tcp_connections) default(last_seen)
// @Param order query string false "Sort order" Enums(asc, desc) default(desc)
// @Param limit query int false "Maximum number of devices" default(100)
// @Param offset query int false "Offset for pagination" default(0)
// @Success 200 {object} DeviceListResponse
// @Router /devices [get]
func (s *Server) listDevices(c *fiber.Ctx) error {
	vendorFilter := c.Query("vendor", "")
	ipFilter := c.Query("ip", "")
	activeMinutes := c.QueryInt("active", 0)
	sortField := c.Query("sort", "last_seen")
	sortOrder := c.Query("order", "desc")
	limit := c.QueryInt("limit", 100)
	offset := c.QueryInt("offset", 0)

	stats := s.monitor.GetStats()
	devices := make([]*models.DeviceInfo, 0, len(stats))

	activeThreshold := time.Now().Add(-time.Duration(activeMinutes) * time.Minute)

	for _, device := range stats {
		// Apply filters
		if vendorFilter != "" && !strings.Contains(strings.ToLower(device.Vendor), strings.ToLower(vendorFilter)) {
			continue
		}
		if ipFilter != "" && !strings.Contains(device.IP, ipFilter) {
			continue
		}
		if activeMinutes > 0 && device.LastSeen.Before(activeThreshold) {
			continue
		}

		devices = append(devices, device)
	}

	// Sort
	sort.Slice(devices, func(i, j int) bool {
		var less bool
		switch sortField {
		case "mac":
			less = devices[i].MAC < devices[j].MAC
		case "ip":
			less = devices[i].IP < devices[j].IP
		case "vendor":
			less = devices[i].Vendor < devices[j].Vendor
		case "first_seen":
			less = devices[i].FirstSeen.Before(devices[j].FirstSeen)
		case "tcp_connections":
			less = devices[i].TCPConnections < devices[j].TCPConnections
		default: // last_seen
			less = devices[i].LastSeen.Before(devices[j].LastSeen)
		}
		if sortOrder == "desc" {
			return !less
		}
		return less
	})

	total := len(devices)

	// Pagination
	if offset >= len(devices) {
		devices = []*models.DeviceInfo{}
	} else {
		end := offset + limit
		if end > len(devices) {
			end = len(devices)
		}
		devices = devices[offset:end]
	}

	return c.JSON(DeviceListResponse{
		Total:   total,
		Limit:   limit,
		Offset:  offset,
		Devices: devices,
	})
}

// getDevice godoc
// @Summary Get device details
// @Description Returns detailed information about a specific device
// @Tags Devices
// @Accept json
// @Produce json
// @Param mac path string true "MAC address (format XX:XX:XX:XX:XX:XX)"
// @Success 200 {object} models.DeviceInfo
// @Failure 404 {object} ErrorResponse
// @Router /devices/{mac} [get]
func (s *Server) getDevice(c *fiber.Ctx) error {
	mac := c.Params("mac")
	mac = strings.ToUpper(mac)

	device, found := s.monitor.Cache.Get(mac)
	if !found {
		return c.Status(404).JSON(ErrorResponse{
			Error: "Device not found",
			Code:  "404",
		})
	}

	return c.JSON(device)
}

// getDevicePatterns godoc
// @Summary Get device communication patterns
// @Description Returns all communication patterns for a specific device
// @Tags Devices, Patterns
// @Accept json
// @Produce json
// @Param mac path string true "MAC address"
// @Param protocol query string false "Filter by protocol" Enums(ARP, TCP, UDP, ICMP, DNS, HTTP, TLS)
// @Param from query string false "Start timestamp"
// @Param limit query int false "Maximum patterns" default(100)
// @Success 200 {object} PatternListResponse
// @Failure 404 {object} ErrorResponse
// @Router /devices/{mac}/patterns [get]
func (s *Server) getDevicePatterns(c *fiber.Ctx) error {
	mac := strings.ToUpper(c.Params("mac"))
	protocolFilter := strings.ToUpper(c.Query("protocol", ""))
	limit := c.QueryInt("limit", 100)

	device, found := s.monitor.Cache.Get(mac)
	if !found {
		return c.Status(404).JSON(ErrorResponse{
			Error: "Device not found",
			Code:  "404",
		})
	}

	patterns := make([]*models.CommunicationPattern, 0)

	if device.SeenPatterns != nil {
		for patternKey := range device.SeenPatterns {
			// Parse pattern key: "PROTOCOL:srcIP->dstIP:dstPort:trafficType"
			parts := strings.SplitN(patternKey, ":", 2)
			if len(parts) < 2 {
				continue
			}

			protocol := parts[0]
			if protocolFilter != "" && protocol != protocolFilter {
				continue
			}

			pattern := &models.CommunicationPattern{
				SrcMAC:   mac,
				Protocol: protocol,
			}
			patterns = append(patterns, pattern)

			if len(patterns) >= limit {
				break
			}
		}
	}

	return c.JSON(PatternListResponse{
		Total:    len(patterns),
		Patterns: patterns,
	})
}

// getDeviceDNS godoc
// @Summary Get DNS domains queried by device
// @Description Returns DNS domains queried by a specific device with counts
// @Tags Devices
// @Accept json
// @Produce json
// @Param mac path string true "MAC address"
// @Param limit query int false "Maximum domains" default(50)
// @Success 200 {object} DNSDomainListResponse
// @Failure 404 {object} ErrorResponse
// @Router /devices/{mac}/dns [get]
func (s *Server) getDeviceDNS(c *fiber.Ctx) error {
	mac := strings.ToUpper(c.Params("mac"))
	limit := c.QueryInt("limit", 50)

	device, found := s.monitor.Cache.Get(mac)
	if !found {
		return c.Status(404).JSON(ErrorResponse{
			Error: "Device not found",
			Code:  "404",
		})
	}

	domains := make([]DNSDomain, 0)
	totalQueries := 0

	if device.DNSDomains != nil {
		for domain, count := range device.DNSDomains {
			totalQueries += count
			domains = append(domains, DNSDomain{
				Domain: domain,
				Count:  count,
			})
			if len(domains) >= limit {
				break
			}
		}
	}

	// Sort by count descending
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].Count > domains[j].Count
	})

	return c.JSON(DNSDomainListResponse{
		MAC:          mac,
		TotalQueries: totalQueries,
		Domains:      domains,
	})
}

// getDeviceServices godoc
// @Summary Get services accessed by device
// @Description Returns services/ports accessed by a specific device
// @Tags Devices
// @Accept json
// @Produce json
// @Param mac path string true "MAC address"
// @Success 200 {object} ServiceAccessListResponse
// @Failure 404 {object} ErrorResponse
// @Router /devices/{mac}/services [get]
func (s *Server) getDeviceServices(c *fiber.Ctx) error {
	mac := strings.ToUpper(c.Params("mac"))

	device, found := s.monitor.Cache.Get(mac)
	if !found {
		return c.Status(404).JSON(ErrorResponse{
			Error: "Device not found",
			Code:  "404",
		})
	}

	services := make([]ServiceAccess, 0)

	if device.Services != nil {
		for service, count := range device.Services {
			services = append(services, ServiceAccess{
				Service: service,
				Count:   count,
			})
		}
	}

	// Sort by count descending
	sort.Slice(services, func(i, j int) bool {
		return services[i].Count > services[j].Count
	})

	return c.JSON(ServiceAccessListResponse{
		MAC:      mac,
		Services: services,
	})
}

// listPatterns godoc
// @Summary List all communication patterns
// @Description Returns recent unique communication patterns across all devices
// @Tags Patterns
// @Accept json
// @Produce json
// @Param protocol query string false "Filter by protocol" Enums(ARP, TCP, UDP, ICMP, DNS, HTTP, TLS)
// @Param traffic_type query string false "Filter by traffic type"
// @Param src_ip query string false "Filter by source IP"
// @Param dst_ip query string false "Filter by destination IP"
// @Param dst_port query int false "Filter by destination port"
// @Param interface query string false "Filter by network interface"
// @Param from query string false "Start timestamp"
// @Param limit query int false "Maximum patterns" default(100)
// @Success 200 {object} PatternListResponse
// @Router /patterns [get]
func (s *Server) listPatterns(c *fiber.Ctx) error {
	protocolFilter := strings.ToUpper(c.Query("protocol", ""))
	limit := c.QueryInt("limit", 100)

	stats := s.monitor.GetStats()
	patterns := make([]*models.CommunicationPattern, 0)

	for mac, device := range stats {
		if device.SeenPatterns == nil {
			continue
		}

		for patternKey := range device.SeenPatterns {
			parts := strings.SplitN(patternKey, ":", 2)
			if len(parts) < 2 {
				continue
			}

			protocol := parts[0]
			if protocolFilter != "" && protocol != protocolFilter {
				continue
			}

			pattern := &models.CommunicationPattern{
				SrcMAC:   mac,
				Protocol: protocol,
			}
			patterns = append(patterns, pattern)

			if len(patterns) >= limit {
				break
			}
		}

		if len(patterns) >= limit {
			break
		}
	}

	return c.JSON(PatternListResponse{
		Total:    len(patterns),
		Patterns: patterns,
	})
}

// streamPatterns godoc
// @Summary Stream new patterns (SSE)
// @Description Server-Sent Events stream of new communication patterns
// @Tags Patterns, Events
// @Accept json
// @Produce text/event-stream
// @Param protocol query string false "Filter by protocol" Enums(ARP, TCP, UDP, ICMP, DNS, HTTP, TLS)
// @Success 200 {string} string "SSE stream"
// @Router /patterns/stream [get]
func (s *Server) streamPatterns(c *fiber.Ctx) error {
	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("Transfer-Encoding", "chunked")

	clientID := fmt.Sprintf("%d", time.Now().UnixNano())
	patternChan := make(chan *models.CommunicationPattern, 100)

	s.patternClientsMu.Lock()
	s.patternClients[clientID] = patternChan
	s.patternClientsMu.Unlock()

	defer func() {
		s.patternClientsMu.Lock()
		delete(s.patternClients, clientID)
		close(patternChan)
		s.patternClientsMu.Unlock()
	}()

	protocolFilter := strings.ToUpper(c.Query("protocol", ""))
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		for pattern := range patternChan {
			if protocolFilter != "" && pattern.Protocol != protocolFilter {
				continue
			}

			data := fmt.Sprintf("event: pattern\ndata: {\"src_mac\":\"%s\",\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"dst_port\":%d,\"protocol\":\"%s\",\"traffic_type\":\"%s\"}\n\n",
				pattern.SrcMAC, pattern.SrcIP, pattern.DstIP, pattern.DstPort, pattern.Protocol, pattern.TrafficType)

			if _, err := w.WriteString(data); err != nil {
				return
			}
			if err := w.Flush(); err != nil {
				return
			}
		}
	})

	return nil
}

// listInterfaces godoc
// @Summary List monitored network interfaces
// @Description Returns all network interfaces being monitored
// @Tags Interfaces
// @Accept json
// @Produce json
// @Success 200 {object} InterfaceListResponse
// @Router /interfaces [get]
func (s *Server) listInterfaces(c *fiber.Ctx) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return c.JSON(InterfaceListResponse{
		Interfaces: s.interfaces,
	})
}

// getInterface godoc
// @Summary Get interface details
// @Description Returns details and statistics for a specific interface
// @Tags Interfaces
// @Accept json
// @Produce json
// @Param name path string true "Interface name (e.g., eth0, wlan0)"
// @Success 200 {object} InterfaceInfo
// @Failure 404 {object} ErrorResponse
// @Router /interfaces/{name} [get]
func (s *Server) getInterface(c *fiber.Ctx) error {
	name := c.Params("name")

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, iface := range s.interfaces {
		if iface.Name == name {
			return c.JSON(iface)
		}
	}

	return c.Status(404).JSON(ErrorResponse{
		Error: "Interface not found",
		Code:  "404",
	})
}

// lookupVendor godoc
// @Summary Lookup MAC vendor
// @Description Returns vendor information for a MAC address using IEEE OUI database
// @Tags Lookup
// @Accept json
// @Produce json
// @Param mac path string true "MAC address or OUI prefix (XX:XX:XX)"
// @Success 200 {object} VendorInfoResponse
// @Failure 404 {object} ErrorResponse
// @Router /lookup/vendor/{mac} [get]
func (s *Server) lookupVendor(c *fiber.Ctx) error {
	mac := strings.ToUpper(c.Params("mac"))

	// Extract OUI (first 3 octets)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		return c.Status(400).JSON(ErrorResponse{
			Error: "Invalid MAC address format",
			Code:  "400",
		})
	}

	oui := strings.Join(parts[:3], ":")

	// Try to find device in cache to get vendor
	vendor := "Unknown"
	stats := s.monitor.GetStats()

	for deviceMAC, device := range stats {
		if strings.HasPrefix(strings.ToUpper(deviceMAC), oui) {
			vendor = device.Vendor
			break
		}
	}

	if vendor == "Unknown" {
		return c.Status(404).JSON(ErrorResponse{
			Error: "Vendor not found",
			Code:  "404",
		})
	}

	return c.JSON(VendorInfoResponse{
		OUI:    oui,
		Vendor: vendor,
	})
}

// lookupService godoc
// @Summary Lookup service by port
// @Description Returns service information for a port number
// @Tags Lookup
// @Accept json
// @Produce json
// @Param port path int true "Port number" minimum(1) maximum(65535)
// @Param protocol query string false "Protocol (TCP or UDP)" Enums(TCP, UDP) default(TCP)
// @Success 200 {object} ServiceInfoResponse
// @Failure 404 {object} ErrorResponse
// @Router /lookup/service/{port} [get]
func (s *Server) lookupService(c *fiber.Ctx) error {
	portStr := c.Params("port")
	protocol := strings.ToUpper(c.Query("protocol", "TCP"))

	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return c.Status(400).JSON(ErrorResponse{
			Error: "Invalid port number",
			Code:  "400",
		})
	}

	// Well-known ports lookup
	services := map[int]ServiceInfoResponse{
		20:   {Port: 20, Protocol: "TCP", Service: "ftp-data", Description: "FTP Data Transfer"},
		21:   {Port: 21, Protocol: "TCP", Service: "ftp", Description: "FTP Control"},
		22:   {Port: 22, Protocol: "TCP", Service: "ssh", Description: "Secure Shell"},
		23:   {Port: 23, Protocol: "TCP", Service: "telnet", Description: "Telnet"},
		25:   {Port: 25, Protocol: "TCP", Service: "smtp", Description: "Simple Mail Transfer Protocol"},
		53:   {Port: 53, Protocol: "BOTH", Service: "dns", Description: "Domain Name System"},
		67:   {Port: 67, Protocol: "UDP", Service: "dhcp-server", Description: "DHCP Server"},
		68:   {Port: 68, Protocol: "UDP", Service: "dhcp-client", Description: "DHCP Client"},
		80:   {Port: 80, Protocol: "TCP", Service: "http", Description: "Hypertext Transfer Protocol"},
		110:  {Port: 110, Protocol: "TCP", Service: "pop3", Description: "Post Office Protocol v3"},
		123:  {Port: 123, Protocol: "UDP", Service: "ntp", Description: "Network Time Protocol"},
		143:  {Port: 143, Protocol: "TCP", Service: "imap", Description: "Internet Message Access Protocol"},
		161:  {Port: 161, Protocol: "UDP", Service: "snmp", Description: "Simple Network Management Protocol"},
		443:  {Port: 443, Protocol: "TCP", Service: "https", Description: "HTTP over TLS/SSL"},
		445:  {Port: 445, Protocol: "TCP", Service: "smb", Description: "Server Message Block"},
		993:  {Port: 993, Protocol: "TCP", Service: "imaps", Description: "IMAP over TLS/SSL"},
		995:  {Port: 995, Protocol: "TCP", Service: "pop3s", Description: "POP3 over TLS/SSL"},
		3306: {Port: 3306, Protocol: "TCP", Service: "mysql", Description: "MySQL Database"},
		3389: {Port: 3389, Protocol: "TCP", Service: "rdp", Description: "Remote Desktop Protocol"},
		5432: {Port: 5432, Protocol: "TCP", Service: "postgresql", Description: "PostgreSQL Database"},
		6379: {Port: 6379, Protocol: "TCP", Service: "redis", Description: "Redis Database"},
		8080: {Port: 8080, Protocol: "TCP", Service: "http-alt", Description: "HTTP Alternate"},
		8443: {Port: 8443, Protocol: "TCP", Service: "https-alt", Description: "HTTPS Alternate"},
	}

	if svc, ok := services[port]; ok {
		svc.Protocol = protocol
		return c.JSON(svc)
	}

	return c.Status(404).JSON(ErrorResponse{
		Error: "Service not found",
		Code:  "404",
	})
}

// GetInterfaceInfo retrieves interface information for the server
func GetInterfaceInfo() []InterfaceInfo {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}

	result := make([]InterfaceInfo, 0)

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, _ := iface.Addrs()
		addrStrings := make([]string, 0)
		for _, addr := range addrs {
			addrStrings = append(addrStrings, addr.String())
		}

		result = append(result, InterfaceInfo{
			Name:       iface.Name,
			Index:      iface.Index,
			MAC:        iface.HardwareAddr.String(),
			Addresses:  addrStrings,
			IsUp:       iface.Flags&net.FlagUp != 0,
			IsLoopback: iface.Flags&net.FlagLoopback != 0,
			MTU:        iface.MTU,
			Attached:   false,
		})
	}

	return result
}
