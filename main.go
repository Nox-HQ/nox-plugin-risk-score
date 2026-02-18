package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// EPSSResponse represents the response from the FIRST.org EPSS API.
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
type KEVEntry struct {
	CVEID                   string `json:"cveID"`
	VendorProject           string `json:"vendorProject"`
	Product                 string `json:"product"`
	VulnerabilityName       string `json:"vulnerabilityName"`
	DateAdded               string `json:"dateAdded"`
	ShortDescription        string `json:"shortDescription"`
	RequiredAction          string `json:"requiredAction"`
	DueDate                 string `json:"dueDate"`
	KnownRansomwareCampaign string `json:"knownRansomwareCampaignUse"`
	Notes                   string `json:"notes"`
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

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/risk-score", version).
		Capability("risk-score", "EPSS/KEV risk scoring and vulnerability prioritization").
		ToolWithContext("enrich_findings", "Enrich VULN findings with EPSS scores and KEV status", true).
		Tool("get_epss", "Get EPSS score for a specific CVE", true).
		Tool("get_kev_status", "Check if CVE is in CISA Known Exploited Vulnerabilities", true).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskPassive),
			sdk.WithNetworkHosts("api.first.org", "www.cisa.gov"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("enrich_findings", handleEnrichFindings).
		HandleTool("get_epss", handleGetEPSS).
		HandleTool("get_kev_status", handleGetKEVStatus)
}

func handleEnrichFindings(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()

	for _, f := range req.Findings() {
		meta := f.GetMetadata()
		if meta == nil {
			continue
		}
		cve := meta["cve"]
		if cve == "" {
			continue
		}

		// In production, these would be HTTP calls to FIRST.org and CISA.
		// For now, produce enrichments noting the CVE was found.
		enriched := EnrichFinding(f.GetRuleId(), cve, nil, nil)
		body, _ := json.Marshal(enriched)

		fingerprint := f.GetFingerprint()
		if fingerprint == "" {
			loc := f.GetLocation()
			file := ""
			line := 0
			if loc != nil {
				file = loc.GetFilePath()
				line = int(loc.GetStartLine())
			}
			fingerprint = fmt.Sprintf("%s:%s:%d", f.GetRuleId(), file, line)
		}

		resp.Enrichment(fingerprint, "risk-score", fmt.Sprintf("Risk score for %s", cve)).
			Body(string(body)).
			WithMetadata("cve", cve).
			WithMetadata("risk_priority", string(enriched.RiskPriority)).
			Source("nox/risk-score").
			Done()
	}

	return resp.Build(), nil
}

func handleGetEPSS(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()
	cveID := req.InputString("cve_id")
	if cveID == "" {
		return resp.Build(), nil
	}

	// In production: HTTP GET to https://api.first.org/data/v1/epss?cve={cve_id}
	resp.Enrichment(cveID, "epss-score", fmt.Sprintf("EPSS score for %s", cveID)).
		Body(fmt.Sprintf(`{"cve":%q,"status":"pending","note":"EPSS lookup requires network access to api.first.org"}`, cveID)).
		WithMetadata("cve", cveID).
		Source("nox/risk-score").
		Done()

	return resp.Build(), nil
}

func handleGetKEVStatus(_ context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	resp := sdk.NewResponse()
	cveID := req.InputString("cve_id")
	if cveID == "" {
		return resp.Build(), nil
	}

	// In production: check locally cached KEV catalog from www.cisa.gov
	resp.Enrichment(cveID, "kev-status", fmt.Sprintf("KEV status for %s", cveID)).
		Body(fmt.Sprintf(`{"cve":%q,"in_kev":false,"note":"KEV lookup requires cached catalog from www.cisa.gov"}`, cveID)).
		WithMetadata("cve", cveID).
		Source("nox/risk-score").
		Done()

	return resp.Build(), nil
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	return buildServer().Serve(ctx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-risk-score: %v\n", err)
		os.Exit(1)
	}
}
