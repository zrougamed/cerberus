package databases

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// OUIDatabase is a thread-safe IEEE vendor registry (MA-L / MA-M / MA-S) with optional online lookups.
type OUIDatabase struct {
	vendors  map[string]string // normalized prefix keys -> vendor
	cache    map[string]ouiCacheEntry
	mu       sync.RWMutex
	online   bool
	dbPath   string // primary cache: combined IEEE CSV
	lastSync time.Time
	stale    bool
}

type ouiCacheEntry struct {
	vendor    string
	timestamp time.Time
}

const (
	IEEE_OUI_CSV_URL   = "https://standards-oui.ieee.org/oui/oui.csv"
	IEEE_MAM_CSV_URL   = "https://standards-oui.ieee.org/oui28/mam.csv"
	IEEE_OUI36_CSV_URL = "https://standards-oui.ieee.org/oui36/oui36.csv"
	IEEE_OUI_TXT_URL   = "https://standards-oui.ieee.org/oui/oui.txt"

	MACVENDORS_API = "https://api.macvendors.com/%s"

	ouiCacheCSV    = "oui_registry.csv"
	ouiCacheLegacy = "oui_database.txt"

	cacheValidDays   = 30
	onlineCacheHours = 24

	VendorMulticast  = "Multicast"
	VendorLocalAdmin = "Locally administered (privacy MAC)"
	VendorUnknown    = "Unknown"
)

// NewOUIDatabase loads cached IEEE data from DataDir(), or downloads when enableOnline is true.
// A stale cache is preferred over the tiny embedded fallback; online mode refreshes in the background.
func NewOUIDatabase(enableOnline bool) (*OUIDatabase, error) {
	db := &OUIDatabase{
		vendors: make(map[string]string),
		cache:   make(map[string]ouiCacheEntry),
		online:  enableOnline,
		dbPath:  filepath.Join(DataDir(), ouiCacheCSV),
	}

	if err := db.loadFromDisk(); err != nil {
		if enableOnline {
			if err := db.downloadIEEE(); err != nil {
				log.Printf("databases: IEEE OUI download failed: %v", err)
				db.loadFallbackDatabase()
			}
		} else {
			db.loadFallbackDatabase()
		}
	} else if enableOnline && db.stale {
		go func() {
			if err := db.downloadIEEE(); err != nil {
				log.Printf("databases: background IEEE OUI refresh failed: %v", err)
			}
		}()
	}

	return db, nil
}

// LoadOUIDatabase returns a snapshot map for callers that only need prefix → vendor (read-only use).
func LoadOUIDatabase() map[string]string {
	db, _ := NewOUIDatabase(false)
	out := make(map[string]string, len(db.vendors))
	db.mu.RLock()
	for k, v := range db.vendors {
		out[k] = v
	}
	db.mu.RUnlock()
	return out
}

func (db *OUIDatabase) loadFromDisk() error {
	if err := db.tryLoadCSV(db.dbPath); err == nil {
		return nil
	}
	db.mu.Lock()
	db.vendors = make(map[string]string)
	db.mu.Unlock()

	legacy := filepath.Join(DataDir(), ouiCacheLegacy)
	if err := db.tryLoadTXT(legacy); err == nil {
		return nil
	}
	db.mu.Lock()
	db.vendors = make(map[string]string)
	db.mu.Unlock()
	return fmt.Errorf("no valid OUI cache in %s", DataDir())
}

func (db *OUIDatabase) tryLoadCSV(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	stale := time.Since(fi.ModTime()) > cacheValidDays*24*time.Hour
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM
	n, err := db.ingestIEEEcsv(bytes.NewReader(data))
	if err != nil || n == 0 {
		return fmt.Errorf("parse OUI CSV: %w entries=%d", err, n)
	}
	db.lastSync = fi.ModTime()
	db.stale = stale
	if stale {
		log.Printf("databases: loaded %d OUI vendors from stale cache %s (age %s); prefer refresh with CERBERUS_DB_ONLINE=1",
			n, path, time.Since(fi.ModTime()).Round(time.Hour))
	} else {
		log.Printf("databases: loaded %d OUI vendors from %s", n, path)
	}
	return nil
}

func (db *OUIDatabase) tryLoadTXT(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	stale := time.Since(fi.ModTime()) > cacheValidDays*24*time.Hour
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n := db.ingestIEEEtxt(f)
	if n == 0 {
		return fmt.Errorf("no OUI entries in %s", path)
	}
	db.lastSync = fi.ModTime()
	db.stale = stale
	if stale {
		log.Printf("databases: loaded %d OUI vendors from stale legacy %s", n, path)
	} else {
		log.Printf("databases: loaded %d OUI vendors from legacy %s", n, path)
	}
	return nil
}

func (db *OUIDatabase) ingestIEEEcsv(r io.Reader) (int, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.ReuseRecord = true
	cr.LazyQuotes = true
	n := 0
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		if len(rec) < 3 {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(rec[0]), "Registry") {
			continue
		}
		registry := strings.ToUpper(strings.TrimSpace(rec[0]))
		assign := strings.TrimSpace(strings.ReplaceAll(rec[1], "-", ""))
		assign = strings.ReplaceAll(assign, ":", "")
		vendor := strings.TrimSpace(rec[2])
		if vendor == "" {
			continue
		}
		key, ok := registryKey(registry, assign)
		if !ok {
			continue
		}
		db.mu.Lock()
		db.vendors[key] = vendor
		db.mu.Unlock()
		n++
	}
	return n, nil
}

// registryKey maps an IEEE assignment hex string to a colon-separated lookup key.
// MA-L: 6 hex → AA:BB:CC
// MA-M: 7 hex → AA:BB:CC:D0 (28-bit; low nibble of 4th octet wild)
// MA-S: 9 hex → AA:BB:CC:DD:E0 (36-bit; low nibble of 5th octet wild)
func registryKey(registry, assign string) (string, bool) {
	assign = strings.ToUpper(assign)
	if assign == "" || !isHexString(assign) {
		return "", false
	}
	switch registry {
	case "MA-L", "":
		if len(assign) != 6 {
			return "", false
		}
		return formatOUIHex(assign), true
	case "MA-M":
		if len(assign) != 7 {
			return "", false
		}
		return formatOUIHex(assign + "0"), true
	case "MA-S", "MA-S/OUI36", "OUI36":
		if len(assign) != 9 {
			return "", false
		}
		return formatOUIHex(assign + "0"), true
	default:
		// Accept length-based inference for combined/custom caches.
		switch len(assign) {
		case 6:
			return formatOUIHex(assign), true
		case 7:
			return formatOUIHex(assign + "0"), true
		case 8:
			return formatOUIHex(assign), true
		case 9:
			return formatOUIHex(assign + "0"), true
		case 10:
			return formatOUIHex(assign), true
		default:
			return "", false
		}
	}
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'A' && c <= 'F', c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}

func formatOUIHex(assign string) string {
	a := strings.ToUpper(assign)
	var b strings.Builder
	for i := 0; i+1 < len(a); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(a[i : i+2])
	}
	return b.String()
}

func (db *OUIDatabase) ingestIEEEtxt(r io.Reader) int {
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if !strings.Contains(line, "(hex)") {
			continue
		}
		parts := strings.SplitN(line, "(hex)", 2)
		if len(parts) != 2 {
			continue
		}
		left := strings.TrimSpace(parts[0])
		fields := strings.Fields(left)
		if len(fields) == 0 {
			continue
		}
		hexTok := fields[len(fields)-1]
		hexTok = strings.ReplaceAll(hexTok, "-", "")
		hexTok = strings.ReplaceAll(hexTok, ":", "")
		if len(hexTok) != 6 {
			continue
		}
		if _, err := hex.DecodeString(hexTok); err != nil {
			continue
		}
		vendor := strings.TrimSpace(parts[1])
		if vendor == "" {
			continue
		}
		key := formatOUIHex(hexTok)
		db.mu.Lock()
		db.vendors[key] = vendor
		db.mu.Unlock()
		n++
	}
	return n
}

func (db *OUIDatabase) downloadIEEE() error {
	if err := os.MkdirAll(DataDir(), 0755); err != nil {
		return err
	}
	client := &http.Client{Timeout: 45 * time.Second}

	combined := &bytes.Buffer{}
	w := csv.NewWriter(combined)
	_ = w.Write([]string{"Registry", "Assignment", "Organization Name", "Organization Address"})

	sources := []string{
		IEEE_OUI_CSV_URL,
		IEEE_MAM_CSV_URL,
		IEEE_OUI36_CSV_URL,
	}

	tmp := &OUIDatabase{vendors: make(map[string]string)}
	total := 0
	for _, url := range sources {
		body, err := db.httpGetBody(client, url)
		if err != nil {
			log.Printf("databases: skip %s: %v", url, err)
			continue
		}
		body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
		n, err := tmp.ingestIEEEcsv(bytes.NewReader(body))
		if err != nil {
			log.Printf("databases: parse %s: %v", url, err)
			continue
		}
		total += n
	}

	if total == 0 {
		// Fall back to legacy TXT (MA-L only).
		body, err := db.httpGetBody(client, IEEE_OUI_TXT_URL)
		if err != nil {
			return err
		}
		tmp.mu.Lock()
		tmp.vendors = make(map[string]string)
		tmp.mu.Unlock()
		n := tmp.ingestIEEEtxt(bytes.NewReader(body))
		if n == 0 {
			return fmt.Errorf("IEEE download produced zero entries")
		}
		legacy := filepath.Join(DataDir(), ouiCacheLegacy)
		if err := os.WriteFile(legacy, body, 0644); err != nil {
			return err
		}
		db.mu.Lock()
		db.vendors = tmp.vendors
		db.lastSync = time.Now()
		db.stale = false
		db.mu.Unlock()
		log.Printf("databases: downloaded %d OUI entries from IEEE TXT (legacy cache)", n)
		return nil
	}

	tmp.mu.RLock()
	for key, name := range tmp.vendors {
		assign := strings.ReplaceAll(key, ":", "")
		reg := "MA-L"
		switch len(assign) {
		case 8:
			reg = "MA-M"
			assign = assign[:7] // drop padded nibble for IEEE-shaped cache
		case 10:
			reg = "MA-S"
			assign = assign[:9]
		}
		_ = w.Write([]string{reg, assign, name, ""})
	}
	tmp.mu.RUnlock()
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}

	if err := os.WriteFile(db.dbPath, combined.Bytes(), 0644); err != nil {
		return err
	}

	db.mu.Lock()
	db.vendors = tmp.vendors
	db.lastSync = time.Now()
	db.stale = false
	db.mu.Unlock()
	log.Printf("databases: downloaded %d OUI entries from IEEE (MA-L/MA-M/MA-S)", len(tmp.vendors))
	return nil
}

func (db *OUIDatabase) httpGetBody(client *http.Client, url string) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ParseMAC48 parses common MAC forms into six octets. Accepts ":", "-", ".", and 12 hex digits.
func ParseMAC48(s string) ([6]byte, bool) {
	var z [6]byte
	s = strings.TrimSpace(strings.ToUpper(s))
	s = strings.ReplaceAll(s, "-", ":")
	s = strings.ReplaceAll(s, ".", ":")

	if strings.Count(s, ":") == 0 && len(s) == 12 {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 6 {
			return z, false
		}
		copy(z[:], b)
		return z, true
	}

	parts := strings.Split(s, ":")
	for len(parts) > 6 && parts[0] == "" {
		parts = parts[1:]
	}
	if len(parts) != 6 {
		return z, false
	}
	for i := 0; i < 6; i++ {
		if len(parts[i]) == 0 || len(parts[i]) > 2 {
			return z, false
		}
		v, err := hex.DecodeString(parts[i])
		if err != nil || len(v) != 1 {
			return z, false
		}
		z[i] = v[0]
	}
	return z, true
}

// OUIKeyCandidates returns colon-uppercase prefix keys longest-first for IEEE registry lookup.
// Includes MA-S (36-bit) and MA-M (28-bit) masked keys plus full-octet prefixes.
func OUIKeyCandidates(mac [6]byte) []string {
	out := make([]string, 0, 5)
	// MA-S: first 36 bits, low nibble of 5th octet zeroed → AA:BB:CC:DD:E0
	out = append(out, fmt.Sprintf("%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4]&0xF0))
	// 4 full octets (overrides / future)
	out = append(out, fmt.Sprintf("%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3]))
	// MA-M: first 28 bits, low nibble of 4th octet zeroed → AA:BB:CC:D0
	out = append(out, fmt.Sprintf("%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3]&0xF0))
	// MA-L: 24-bit
	out = append(out, fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2]))
	return out
}

// Lookup returns a vendor name for a 48-bit station address.
// Order: multicast → registry (including locally-administered virtualization OUIs) →
// online cache → privacy-MAC label → optional online API → Unknown.
func (db *OUIDatabase) Lookup(mac string) string {
	b, ok := ParseMAC48(mac)
	if !ok {
		return VendorUnknown
	}
	// I/G (multicast) bit — least significant bit of first octet.
	if b[0]&0x01 != 0 {
		return VendorMulticast
	}

	for _, key := range OUIKeyCandidates(b) {
		db.mu.RLock()
		v, hit := db.vendors[key]
		db.mu.RUnlock()
		if hit {
			return v
		}
	}

	db.mu.RLock()
	if entry, ok := db.cache[keyFrom3(b)]; ok && time.Since(entry.timestamp) < onlineCacheHours*time.Hour {
		v := entry.vendor
		db.mu.RUnlock()
		return v
	}
	db.mu.RUnlock()

	// U/L (local) bit — second least significant bit of first octet.
	// Checked after registry so known locally-administered prefixes (QEMU, Docker, …) still resolve.
	locallyAdmin := b[0]&0x02 != 0
	if locallyAdmin {
		return VendorLocalAdmin
	}

	if db.online {
		if vendor := db.queryOnlineAPI(mac); vendor != "" {
			k := keyFrom3(b)
			db.mu.Lock()
			db.cache[k] = ouiCacheEntry{vendor: vendor, timestamp: time.Now()}
			db.vendors[k] = vendor
			db.mu.Unlock()
			return vendor
		}
	}

	return VendorUnknown
}

func keyFrom3(b [6]byte) string {
	return fmt.Sprintf("%02X:%02X:%02X", b[0], b[1], b[2])
}

func (db *OUIDatabase) queryOnlineAPI(mac string) string {
	client := &http.Client{Timeout: 3 * time.Second}
	url := fmt.Sprintf(MACVENDORS_API, strings.TrimSpace(mac))
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
	if vendor != "" && vendor != "Vendor not found" && !strings.HasPrefix(vendor, "{") {
		return vendor
	}
	return ""
}

// UpdateDatabase refreshes the IEEE cache when online mode is enabled.
func (db *OUIDatabase) UpdateDatabase() error {
	if !db.online {
		return fmt.Errorf("online mode is disabled")
	}
	return db.downloadIEEE()
}

func (db *OUIDatabase) SetOnlineMode(enabled bool) {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.online = enabled
}

func (db *OUIDatabase) GetStats() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return map[string]interface{}{
		"total_vendors":  len(db.vendors),
		"cached_lookups": len(db.cache),
		"last_sync":      db.lastSync,
		"online_enabled": db.online,
		"cache_stale":    db.stale,
		"cache_file":     db.dbPath,
		"data_dir":       DataDir(),
		"cache_age":      time.Since(db.lastSync).Round(time.Hour).String(),
	}
}

func (db *OUIDatabase) ClearOnlineCache() {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.cache = make(map[string]ouiCacheEntry)
}

// SaveToCache writes the in-memory map as IEEE-style CSV (Registry,Assignment,...).
func (db *OUIDatabase) SaveToCache() error {
	if err := os.MkdirAll(DataDir(), 0755); err != nil {
		return err
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	_ = w.Write([]string{"Registry", "Assignment", "Organization Name", "Organization Address"})
	for oui, name := range db.vendors {
		assign := strings.ReplaceAll(oui, ":", "")
		reg := "MA-L"
		switch len(assign) {
		case 6:
			reg = "MA-L"
		case 8:
			reg = "MA-M"
			assign = assign[:7]
		case 10:
			reg = "MA-S"
			assign = assign[:9]
		default:
			continue
		}
		_ = w.Write([]string{reg, assign, name, ""})
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	return os.WriteFile(db.dbPath, buf.Bytes(), 0644)
}

func (db *OUIDatabase) loadFallbackDatabase() {
	fallback := map[string]string{
		"00:00:5E": "IANA",

		"00:03:93": "Apple Inc.",
		"00:1C:B3": "Apple Inc.",
		"00:23:32": "Apple Inc.",
		"00:26:BB": "Apple Inc.",
		"3C:15:C2": "Apple Inc.",
		"A4:C3:61": "Apple Inc.",
		"BC:92:6B": "Apple Inc.",
		"F4:F9:51": "Apple Inc.",
		"AC:DE:48": "Apple Inc.",
		"F0:18:98": "Apple Inc.",
		"DC:A9:04": "Apple Inc.",

		"00:01:42": "Cisco Systems",
		"00:1E:BD": "Cisco Systems",
		"00:26:0A": "Cisco Systems",
		"00:0A:F3": "Cisco Systems",

		"00:0D:3A": "Microsoft Corporation",
		"00:15:5D": "Microsoft Corporation",
		"00:50:F2": "Microsoft Corporation",

		"00:1B:21": "Intel Corporation",
		"3C:A9:F4": "Intel Corporation",
		"00:1F:3B": "Intel Corporate",

		"00:12:FB": "Samsung Electronics",
		"34:AA:8B": "Samsung Electronics",
		"8C:77:12": "Samsung Electronics",

		"00:1A:11": "Google LLC",
		"3C:5A:B4": "Google LLC",
		"F4:F5:E8": "Google LLC",

		"00:17:88": "Amazon Technologies",
		"68:37:E9": "Amazon Technologies",
		"FC:A1:83": "Amazon Technologies",

		"00:0C:29": "VMware Inc.",
		"00:50:56": "VMware Inc.",
		"00:05:69": "VMware Inc.",
		"08:00:27": "Oracle VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:16:3E": "Xen Source",
		"00:1C:42": "Parallels Inc.",
		"02:42:00": "Docker Container",
		"02:42:AC": "Docker Container",

		"B8:27:EB": "Raspberry Pi Foundation",
		"DC:A6:32": "Raspberry Pi Foundation",
		"E4:5F:01": "Raspberry Pi Foundation",
		"28:CD:C1": "Raspberry Pi Trading",
		"2C:CF:67": "Raspberry Pi Trading",
		"D8:3A:DD": "Raspberry Pi Trading",
		"18:03:73": "Texas Instruments",

		"28:6A:BA": "TP-Link Technologies",
		"50:C7:BF": "TP-Link Technologies",
		"00:1D:D3": "Netgear Inc.",
		"00:07:7D": "Ubiquiti Networks",
		"24:A4:3C": "Ubiquiti Networks",
		"FC:EC:DA": "Ubiquiti Networks",
		"B4:FB:E4": "Ubiquiti Networks",

		"00:1E:06": "Espressif Inc.",
		"24:0A:C4": "Espressif Inc.",
		"30:AE:A4": "Espressif Inc.",
		"A4:CF:12": "Espressif Inc.",
		"84:CC:A8": "Espressif Inc.",
		"8C:AA:B5": "Espressif Inc.",

		"00:E0:4C": "Realtek Semiconductor",
	}

	db.mu.Lock()
	db.vendors = fallback
	db.stale = true
	db.mu.Unlock()
	log.Printf("databases: using embedded OUI fallback (%d prefixes)", len(fallback))
}
