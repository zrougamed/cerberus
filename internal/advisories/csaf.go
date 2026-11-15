package advisories

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// The subset of CSAF 2.0 (OASIS) the bundle needs.
type csafDoc struct {
	Document struct {
		Category string `json:"category"`
		Title    string `json:"title"`
		Tracking struct {
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			CurrentReleaseDate string `json:"current_release_date"`
		} `json:"tracking"`
		References []struct {
			Category string `json:"category"`
			URL      string `json:"url"`
		} `json:"references"`
	} `json:"document"`
	ProductTree     csafBranch `json:"product_tree"`
	Vulnerabilities []struct {
		CVE    string `json:"cve"`
		Scores []struct {
			CVSSv3 *struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvss_v3"`
			CVSSv4 *struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvss_v4"`
		} `json:"scores"`
		ProductStatus struct {
			KnownAffected []string `json:"known_affected"`
			FirstAffected []string `json:"first_affected"`
			LastAffected  []string `json:"last_affected"`
		} `json:"product_status"`
	} `json:"vulnerabilities"`
}

type csafBranch struct {
	Category string       `json:"category"`
	Name     string       `json:"name"`
	Branches []csafBranch `json:"branches"`
	Product  *struct {
		ProductID string `json:"product_id"`
	} `json:"product"`
}

// ParseCSAF converts one CSAF security advisory into an Advisory. ok is
// false for documents that are not advisories or affect no product.
func ParseCSAF(data []byte) (Advisory, bool, error) {
	var d csafDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return Advisory{}, false, fmt.Errorf("parse CSAF: %w", err)
	}
	if d.Document.Category != "csaf_security_advisory" || d.Document.Tracking.ID == "" {
		return Advisory{}, false, nil
	}
	products := map[string]Product{}
	walkBranches(d.ProductTree.Branches, Product{}, products)

	a := Advisory{ID: d.Document.Tracking.ID, Title: d.Document.Title}
	for _, s := range []string{d.Document.Tracking.InitialReleaseDate, d.Document.Tracking.CurrentReleaseDate} {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			a.Published = t.UTC()
			break
		}
	}
	a.URL = advisoryURL(d.Document.References)
	affected := map[string]bool{}
	for _, v := range d.Vulnerabilities {
		if v.CVE != "" {
			a.CVEs = append(a.CVEs, v.CVE)
		}
		for _, s := range v.Scores {
			if s.CVSSv3 != nil {
				a.Score = max(a.Score, s.CVSSv3.BaseScore)
			}
			if s.CVSSv4 != nil {
				a.Score = max(a.Score, s.CVSSv4.BaseScore)
			}
		}
		for _, list := range [][]string{v.ProductStatus.KnownAffected, v.ProductStatus.FirstAffected, v.ProductStatus.LastAffected} {
			for _, id := range list {
				affected[id] = true
			}
		}
	}
	seen := map[Product]bool{}
	for id := range affected {
		if p, ok := products[id]; ok && p.Vendor != "" && p.Name != "" && !seen[p] {
			seen[p] = true
			a.Products = append(a.Products, p)
		}
	}
	if len(a.Products) == 0 {
		return Advisory{}, false, nil
	}
	sort.Slice(a.Products, func(i, j int) bool {
		x, y := a.Products[i], a.Products[j]
		return x.Vendor+x.Name+x.Version < y.Vendor+y.Name+y.Version
	})
	sort.Strings(a.CVEs)
	a.Severity = severityFor(a.Score)
	return a, true, nil
}

// advisoryURL prefers the publisher's human-readable advisory page (CISA's
// ics-advisories page in its feed) over vendor PDFs and the JSON itself.
func advisoryURL(refs []struct {
	Category string `json:"category"`
	URL      string `json:"url"`
}) string {
	var self string
	for _, r := range refs {
		if !strings.HasPrefix(r.URL, "https://") || strings.HasSuffix(r.URL, ".json") {
			continue
		}
		if strings.Contains(r.URL, "/ics-advisories/") {
			return r.URL
		}
		if self == "" && r.Category == "self" {
			self = r.URL
		}
	}
	return self
}

// walkBranches collects vendor, product name and version along each path
// down to a product id.
func walkBranches(bs []csafBranch, cur Product, out map[string]Product) {
	for _, b := range bs {
		p := cur
		name := strings.TrimSpace(b.Name)
		switch b.Category {
		case "vendor":
			p.Vendor = name
		case "product_name", "product_family":
			if p.Name == "" || b.Category == "product_name" {
				p.Name = name
			}
		case "product_version", "product_version_range":
			p.Version = name
		}
		if b.Product != nil && b.Product.ProductID != "" {
			out[b.Product.ProductID] = p
		}
		walkBranches(b.Branches, p, out)
	}
}

// severityFor uses the CVSS v3/v4 qualitative bands.
func severityFor(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score > 0:
		return "low"
	}
	return "unknown"
}
