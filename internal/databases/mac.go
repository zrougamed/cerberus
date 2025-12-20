package databases

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OUIDatabase represents the MAC vendor lookup database
type OUIDatabase struct {
	vendors  map[string]string // OUI prefix -> vendor name
	cache    map[string]ouiCacheEntry
	mu       sync.RWMutex
	online   bool
	dbPath   string
	lastSync time.Time
}

type ouiCacheEntry struct {
	vendor    string
	timestamp time.Time
}

const (
	// IEEE OUI database URLs
	IEEE_OUI_URL     = "http://standards-oui.ieee.org/oui/oui.txt"
	IEEE_OUI_CSV_URL = "http://standards-oui.ieee.org/oui/oui.csv"

	// Alternative API endpoints
	MACVENDORS_API = "https://api.macvendors.com/%s"

	// Local cache settings
	CACHE_DIR          = "./data"
	OUI_CACHE_FILE     = "oui_database.txt"
	CACHE_VALID_DAYS   = 30 // Refresh IEEE database every 30 days
	ONLINE_CACHE_HOURS = 24 // Cache online API lookups for 24 hours
)

// NewOUIDatabase creates a new OUI database instance
func NewOUIDatabase(enableOnline bool) (*OUIDatabase, error) {
	db := &OUIDatabase{
		vendors: make(map[string]string),
		cache:   make(map[string]ouiCacheEntry),
		online:  enableOnline,
		dbPath:  filepath.Join(CACHE_DIR, OUI_CACHE_FILE),
	}

	// Try to load from local cache first
	if err := db.loadFromCache(); err != nil {
		// If cache doesn't exist or is old, download from IEEE
		if enableOnline {
			if err := db.downloadIEEEDatabase(); err != nil {
				// If download fails, use minimal fallback database
				db.loadFallbackDatabase()
			}
		} else {
			// Offline mode - use minimal fallback
			db.loadFallbackDatabase()
		}
	}

	return db, nil
}

// LoadOUIDatabase returns a basic map for backward compatibility
func LoadOUIDatabase() map[string]string {
	db, _ := NewOUIDatabase(false)
	return db.vendors
}

// downloadIEEEDatabase downloads the official IEEE OUI database
func (db *OUIDatabase) downloadIEEEDatabase() error {
	fmt.Println("Downloading IEEE OUI database...")

	// Ensure cache directory exists
	if err := os.MkdirAll(CACHE_DIR, 0755); err != nil {
		return fmt.Errorf("failed to create cache directory: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(IEEE_OUI_URL)
	if err != nil {
		return fmt.Errorf("failed to download OUI database: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download OUI database: status %d", resp.StatusCode)
	}

	// Save to cache file
	cacheFile, err := os.Create(db.dbPath)
	if err != nil {
		return fmt.Errorf("failed to create cache file: %w", err)
	}
	defer cacheFile.Close()

	// Copy and parse simultaneously
	scanner := bufio.NewScanner(resp.Body)
	writer := bufio.NewWriter(cacheFile)

	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		writer.WriteString(line + "\n")

		// Parse OUI entries in format:
		// XX-XX-XX   (hex)		Organization Name
		if strings.Contains(line, "(hex)") {
			parts := strings.Split(line, "(hex)")
			if len(parts) == 2 {
				oui := strings.TrimSpace(parts[0])
				vendor := strings.TrimSpace(parts[1])

				// Convert XX-XX-XX to XX:XX:XX
				oui = strings.ReplaceAll(oui, "-", ":")

				db.mu.Lock()
				db.vendors[oui] = vendor
				db.mu.Unlock()
				count++
			}
		}
	}

	writer.Flush()
	db.lastSync = time.Now()

	fmt.Printf("Successfully loaded %d OUI entries from IEEE database\n", count)
	return nil
}

// loadFromCache loads the OUI database from local cache
func (db *OUIDatabase) loadFromCache() error {
	// Check if cache file exists and is recent
	fileInfo, err := os.Stat(db.dbPath)
	if err != nil {
		return fmt.Errorf("cache file not found: %w", err)
	}

	// Check if cache is too old
	if time.Since(fileInfo.ModTime()) > CACHE_VALID_DAYS*24*time.Hour {
		return fmt.Errorf("cache is outdated")
	}

	file, err := os.Open(db.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open cache file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0

	for scanner.Scan() {
		line := scanner.Text()

		// Parse OUI entries
		if strings.Contains(line, "(hex)") {
			parts := strings.Split(line, "(hex)")
			if len(parts) == 2 {
				oui := strings.TrimSpace(parts[0])
				vendor := strings.TrimSpace(parts[1])

				oui = strings.ReplaceAll(oui, "-", ":")

				db.vendors[oui] = vendor
				count++
			}
		}
	}

	db.lastSync = fileInfo.ModTime()
	fmt.Printf("Loaded %d OUI entries from cache (age: %s)\n",
		count, time.Since(fileInfo.ModTime()).Round(time.Hour))

	return nil
}

// loadFallbackDatabase loads a minimal hardcoded database for offline operation
func (db *OUIDatabase) loadFallbackDatabase() {
	// Keep only the most common vendors for minimal footprint
	fallback := map[string]string{
		// Standards
		"00:00:5E": "IANA",
		"01:00:5E": "IPv4 Multicast",
		"33:33:00": "IPv6 Multicast",

		// Major vendors (only their most common prefixes)
		"00:03:93": "Apple Inc.",
		"00:1C:B3": "Apple Inc.",
		"00:23:32": "Apple Inc.",
		"00:26:BB": "Apple Inc.",
		"3C:15:C2": "Apple Inc.",
		"A4:C3:61": "Apple Inc.",
		"BC:92:6B": "Apple Inc.",
		"F4:F9:51": "Apple Inc.",

		"00:01:42": "Cisco Systems",
		"00:1E:BD": "Cisco Systems",
		"00:26:0A": "Cisco Systems",

		"00:0D:3A": "Microsoft Corporation",
		"00:15:5D": "Microsoft Corporation",

		"00:1B:21": "Intel Corporation",
		"3C:A9:F4": "Intel Corporation",

		"00:12:FB": "Samsung Electronics",
		"34:AA:8B": "Samsung Electronics",

		"00:1A:11": "Google LLC",
		"3C:5A:B4": "Google LLC",

		"00:17:88": "Amazon Technologies",
		"68:37:E9": "Amazon Technologies",

		// Virtualization
		"00:0C:29": "VMware Inc.",
		"00:50:56": "VMware Inc.",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:16:3E": "Xen Source",
		"00:1C:42": "Parallels Inc.",

		// IoT & Embedded
		"B8:27:EB": "Raspberry Pi Foundation",
		"DC:A6:32": "Raspberry Pi Foundation",
		"E4:5F:01": "Raspberry Pi Foundation",
		"18:03:73": "Texas Instruments",

		// Network Equipment
		"28:6A:BA": "TP-Link Technologies",
		"00:1D:D3": "Netgear Inc.",
		"00:07:7D": "Ubiquiti Networks",
		"24:A4:3C": "Ubiquiti Networks",

		// Special
		"02:00:00": "Locally Administered",
		"02:42:00": "Docker Container",
	}

	db.vendors = fallback
	fmt.Printf("Using fallback database with %d entries\n", len(fallback))
}

// Lookup performs OUI lookup with offline-first approach and optional online fallback
func (db *OUIDatabase) Lookup(mac string) string {
	parts := strings.Split(strings.ToUpper(mac), ":")
	if len(parts) < 3 {
		return "Unknown"
	}
	oui := strings.Join(parts[:3], ":")

	// 1. Check local database (IEEE downloaded or fallback)
	db.mu.RLock()
	if vendor, ok := db.vendors[oui]; ok {
		db.mu.RUnlock()
		return vendor
	}
	db.mu.RUnlock()

	// 2. Check online lookup cache
	db.mu.RLock()
	if entry, ok := db.cache[oui]; ok {
		if time.Since(entry.timestamp) < ONLINE_CACHE_HOURS*time.Hour {
			db.mu.RUnlock()
			return entry.vendor
		}
	}
	db.mu.RUnlock()

	// 3. If online lookup is enabled, query API
	if db.online {
		if vendor := db.queryOnlineAPI(mac); vendor != "" {
			// Cache the result
			db.mu.Lock()
			db.cache[oui] = ouiCacheEntry{
				vendor:    vendor,
				timestamp: time.Now(),
			}
			db.mu.Unlock()

			// Also add to main database for persistence
			db.mu.Lock()
			db.vendors[oui] = vendor
			db.mu.Unlock()

			return vendor
		}
	}

	return "Unknown"
}

// queryOnlineAPI queries the macvendors.com API for vendor information
// Rate limited to 2 requests/second by the API
func (db *OUIDatabase) queryOnlineAPI(mac string) string {
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	url := fmt.Sprintf(MACVENDORS_API, mac)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}

	req.Header.Set("User-Agent", "Cerberus-Network-Monitor/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	vendor := strings.TrimSpace(string(body))

	// macvendors.com returns plain text
	if vendor != "" && vendor != "Vendor not found" && !strings.HasPrefix(vendor, "{") {
		return vendor
	}

	return ""
}

// UpdateDatabase forces a refresh of the IEEE OUI database
func (db *OUIDatabase) UpdateDatabase() error {
	if !db.online {
		return fmt.Errorf("online mode is disabled")
	}
	return db.downloadIEEEDatabase()
}

// SetOnlineMode enables or disables online lookups
func (db *OUIDatabase) SetOnlineMode(enabled bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.online = enabled
}

// GetStats returns statistics about the database
func (db *OUIDatabase) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return map[string]interface{}{
		"total_vendors":  len(db.vendors),
		"cached_lookups": len(db.cache),
		"last_sync":      db.lastSync,
		"online_enabled": db.online,
		"cache_age":      time.Since(db.lastSync).Round(time.Hour).String(),
	}
}

// ClearOnlineCache clears the online lookup cache
func (db *OUIDatabase) ClearOnlineCache() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.cache = make(map[string]ouiCacheEntry)
}

// SaveToCache persists any new vendors learned from online lookups
func (db *OUIDatabase) SaveToCache() error {
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Ensure cache directory exists
	if err := os.MkdirAll(CACHE_DIR, 0755); err != nil {
		return err
	}

	file, err := os.Create(db.dbPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for oui, vendor := range db.vendors {
		// Write in IEEE format
		ouiFormatted := strings.ReplaceAll(oui, ":", "-")
		fmt.Fprintf(writer, "%s   (hex)\t\t%s\n", ouiFormatted, vendor)
	}

	return writer.Flush()
}
