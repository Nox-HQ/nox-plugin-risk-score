// Package main implements the nox-plugin-risk-score plugin.
//
// This plugin enriches VULN-001 findings with real-world exploitability data:
//   - EPSS (Exploit Prediction Scoring System) probability scores from FIRST.org
//   - CISA KEV (Known Exploited Vulnerabilities) catalog status
//
// In production, this plugin communicates with nox core via gRPC and fetches
// live data from the EPSS API and KEV catalog. This scaffold demonstrates
// the data structures and processing logic.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// EPSSResponse represents the response from the FIRST.org EPSS API.
// Production endpoint: https://api.first.org/data/v1/epss?cve=CVE-YYYY-NNNNN
type EPSSResponse struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Data       []EPSSData `json:"data"`
}

// EPSSData holds a single EPSS score entry for a CVE.
type EPSSData struct {
	CVE        string  `json:"cve"`
	EPSS       float64 `json:"epss,string"`
	Percentile float64 `json:"percentile,string"`
	ModelDate  string  `json:"model-version"`
	Date       string  `json:"date"`
}

// KEVEntry represents a single entry in the CISA KEV catalog.
// Production source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
type KEVEntry struct {
	CVEID                 string `json:"cveID"`
	VendorProject         string `json:"vendorProject"`
	Product               string `json:"product"`
	VulnerabilityName     string `json:"vulnerabilityName"`
	DateAdded             string `json:"dateAdded"`
	ShortDescription      string `json:"shortDescription"`
	RequiredAction        string `json:"requiredAction"`
	DueDate               string `json:"dueDate"`
	KnownRansomwareCampaign string `json:"knownRansomwareCampaignUse"`
	Notes                 string `json:"notes"`
}

// KEVCatalog represents the full CISA KEV catalog response.
type KEVCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []KEVEntry `json:"vulnerabilities"`
}

// EnrichedFinding represents a vulnerability finding enriched with risk data.
type EnrichedFinding struct {
	RuleID       string       `json:"rule_id"`
	CVE          string       `json:"cve"`
	EPSSScore    float64      `json:"epss_score"`
	EPSSPctile   float64      `json:"epss_percentile"`
	InKEV        bool         `json:"in_kev"`
	KEVDetail    *KEVEntry    `json:"kev_detail,omitempty"`
	RiskPriority RiskPriority `json:"risk_priority"`
	EnrichedAt   time.Time    `json:"enriched_at"`
}

// RiskPriority categorizes the urgency of remediation.
type RiskPriority string

const (
	RiskCritical RiskPriority = "critical" // In KEV or EPSS >= 0.7
	RiskHigh     RiskPriority = "high"     // EPSS >= 0.4
	RiskMedium   RiskPriority = "medium"   // EPSS >= 0.1
	RiskLow      RiskPriority = "low"      // EPSS < 0.1
)

// ParseEPSSResponse parses a JSON EPSS API response into structured data.
func ParseEPSSResponse(data []byte) (*EPSSResponse, error) {
	var resp EPSSResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("parse EPSS response: %w", err)
	}
	return &resp, nil
}

// ParseKEVCatalog parses the CISA KEV catalog JSON into structured data.
func ParseKEVCatalog(data []byte) (*KEVCatalog, error) {
	var catalog KEVCatalog
	if err := json.Unmarshal(data, &catalog); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	return &catalog, nil
}

// LookupKEV searches the KEV catalog for a specific CVE.
// Returns the entry and true if found, nil and false otherwise.
func LookupKEV(catalog *KEVCatalog, cveID string) (*KEVEntry, bool) {
	normalized := strings.ToUpper(strings.TrimSpace(cveID))
	for i := range catalog.Vulnerabilities {
		if catalog.Vulnerabilities[i].CVEID == normalized {
			return &catalog.Vulnerabilities[i], true
		}
	}
	return nil, false
}

// ClassifyRisk determines the risk priority based on EPSS score and KEV status.
func ClassifyRisk(epssScore float64, inKEV bool) RiskPriority {
	if inKEV || epssScore >= 0.7 {
		return RiskCritical
	}
	if epssScore >= 0.4 {
		return RiskHigh
	}
	if epssScore >= 0.1 {
		return RiskMedium
	}
	return RiskLow
}

// EnrichFinding creates an enriched finding by combining a CVE with EPSS and KEV data.
//
// In production, this function would:
//  1. Receive a VULN-001 finding from the nox scan pipeline via gRPC
//  2. Extract the CVE identifier from the finding metadata
//  3. Query the EPSS API for the exploit probability score
//  4. Check the local KEV catalog cache for active exploitation status
//  5. Compute a composite risk priority
//  6. Return the enriched finding back to nox core
func EnrichFinding(ruleID, cve string, epssData *EPSSData, kevEntry *KEVEntry) *EnrichedFinding {
	enriched := &EnrichedFinding{
		RuleID:     ruleID,
		CVE:        cve,
		EnrichedAt: time.Now(),
	}

	if epssData != nil {
		enriched.EPSSScore = epssData.EPSS
		enriched.EPSSPctile = epssData.Percentile
	}

	if kevEntry != nil {
		enriched.InKEV = true
		enriched.KEVDetail = kevEntry
	}

	enriched.RiskPriority = ClassifyRisk(enriched.EPSSScore, enriched.InKEV)
	return enriched
}

// getEPSS is a tool stub for retrieving EPSS scores.
//
// In production, this tool would:
//   - Accept a CVE ID as input
//   - Query https://api.first.org/data/v1/epss?cve={cve_id}
//   - Cache responses with a 24-hour TTL (EPSS updates daily)
//   - Return the EPSS probability and percentile
func getEPSS(cveID string) (*EPSSData, error) {
	// Stub: in production, this performs an HTTP GET to the EPSS API.
	// The EPSS API is free, unauthenticated, and rate-limited to 100 req/min.
	return nil, fmt.Errorf("getEPSS: not implemented in scaffold (would query FIRST.org API for %s)", cveID)
}

// getKEVStatus is a tool stub for checking KEV catalog membership.
//
// In production, this tool would:
//   - Maintain a local cache of the KEV catalog (updated every 24 hours)
//   - Download from https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   - Index by CVE ID for O(1) lookup
//   - Return the KEV entry if the CVE is actively exploited
func getKEVStatus(cveID string) (*KEVEntry, error) {
	// Stub: in production, this checks the locally cached KEV catalog.
	// The catalog is ~1MB and updated infrequently — local caching is efficient.
	return nil, fmt.Errorf("getKEVStatus: not implemented in scaffold (would check KEV catalog for %s)", cveID)
}

// enrichFindings is the primary tool that orchestrates EPSS and KEV enrichment.
//
// In production, this tool would:
//   - Accept a batch of VULN-001 findings
//   - Extract CVE identifiers from each finding
//   - Fan-out EPSS and KEV lookups concurrently
//   - Attach risk priority scores to each finding
//   - Return enriched findings to the scan pipeline
func enrichFindings(findings []map[string]string) ([]*EnrichedFinding, error) {
	// Stub: in production, this processes each finding through getEPSS and getKEVStatus.
	return nil, fmt.Errorf("enrichFindings: not implemented in scaffold (would enrich %d findings)", len(findings))
}

func main() {
	fmt.Println("nox-plugin-risk-score v0.1.0")
	fmt.Println("Track: intelligence")
	fmt.Println()
	fmt.Println("Tools:")
	fmt.Println("  enrich_findings - Enriches VULN-001 findings with EPSS scores and KEV status")
	fmt.Println("  get_epss        - Get EPSS score for a specific CVE")
	fmt.Println("  get_kev_status  - Check if CVE is in CISA Known Exploited Vulnerabilities")
	fmt.Println()
	fmt.Println("Data sources:")
	fmt.Println("  EPSS API: https://api.first.org/data/v1/epss")
	fmt.Println("  KEV Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	fmt.Println()
	fmt.Println("This plugin enriches vulnerability findings with real-world exploitability")
	fmt.Println("data to help prioritize remediation. Findings in the CISA KEV catalog or")
	fmt.Println("with high EPSS scores are flagged as critical priority.")

	// Demonstrate the risk classification logic.
	fmt.Println()
	fmt.Println("Risk classification thresholds:")
	fmt.Printf("  critical: in KEV or EPSS >= 0.7 → %s\n", ClassifyRisk(0.8, false))
	fmt.Printf("  high:     EPSS >= 0.4           → %s\n", ClassifyRisk(0.5, false))
	fmt.Printf("  medium:   EPSS >= 0.1           → %s\n", ClassifyRisk(0.2, false))
	fmt.Printf("  low:      EPSS < 0.1            → %s\n", ClassifyRisk(0.05, false))
	fmt.Printf("  KEV override:                   → %s\n", ClassifyRisk(0.01, true))
}
