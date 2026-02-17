package main

import (
	"context"
	"encoding/json"
	"net"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunConformance(t, srv)
}

func TestTrackConformance(t *testing.T) {
	srv := buildServer()
	sdk.RunForTrack(t, srv, registry.TrackIntelligence)
}

func TestEnrichFindingsWithScanContext(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "enrich_findings",
		Input:    input,
		ScanContext: &pluginv1.ScanContext{
			Findings: []*pluginv1.Finding{
				{
					RuleId:      "VULN-001",
					Severity:    sdk.SeverityCritical,
					Confidence:  sdk.ConfidenceHigh,
					Message:     "CVE-2021-44228 in Log4j",
					Fingerprint: "fp-vuln-001",
					Metadata:    map[string]string{"cve": "CVE-2021-44228"},
				},
				{
					RuleId:     "SEC-001",
					Severity:   sdk.SeverityHigh,
					Confidence: sdk.ConfidenceHigh,
					Message:    "Hardcoded secret (no CVE)",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	// Only VULN-001 has a CVE, so only 1 enrichment.
	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetKind() != "risk-score" {
		t.Errorf("kind = %q, want risk-score", e.GetKind())
	}
	if e.GetMetadata()["cve"] != "CVE-2021-44228" {
		t.Errorf("cve metadata = %q, want CVE-2021-44228", e.GetMetadata()["cve"])
	}
	if e.GetSource() != "nox/risk-score" {
		t.Errorf("source = %q, want nox/risk-score", e.GetSource())
	}
}

func TestGetEPSS(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{
		"cve_id": "CVE-2021-44228",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "get_epss",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetKind() != "epss-score" {
		t.Errorf("kind = %q, want epss-score", e.GetKind())
	}
	if e.GetMetadata()["cve"] != "CVE-2021-44228" {
		t.Errorf("cve = %q, want CVE-2021-44228", e.GetMetadata()["cve"])
	}
}

func TestGetEPSSEmpty(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "get_epss",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("expected 0 enrichments for empty cve_id, got %d", len(resp.GetEnrichments()))
	}
}

func TestGetKEVStatus(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{
		"cve_id": "CVE-2023-44487",
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "get_kev_status",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}

	if len(resp.GetEnrichments()) != 1 {
		t.Fatalf("expected 1 enrichment, got %d", len(resp.GetEnrichments()))
	}

	e := resp.GetEnrichments()[0]
	if e.GetKind() != "kev-status" {
		t.Errorf("kind = %q, want kev-status", e.GetKind())
	}
}

// --- Domain logic unit tests (preserved from Gen 1) ---

func TestParseEPSSResponse(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantCVE    string
		wantEPSS   float64
		wantPctile float64
		wantErr    bool
	}{
		{
			name: "valid single CVE response",
			input: `{
				"status": "OK",
				"status-code": 200,
				"version": "1.0",
				"total": 1,
				"data": [
					{
						"cve": "CVE-2023-44487",
						"epss": "0.93846",
						"percentile": "0.99917",
						"model-version": "v2023.03.01",
						"date": "2024-01-15"
					}
				]
			}`,
			wantCVE:    "CVE-2023-44487",
			wantEPSS:   0.93846,
			wantPctile: 0.99917,
		},
		{
			name: "valid low-risk CVE",
			input: `{
				"status": "OK",
				"status-code": 200,
				"version": "1.0",
				"total": 1,
				"data": [
					{
						"cve": "CVE-2024-0001",
						"epss": "0.00043",
						"percentile": "0.12500",
						"model-version": "v2023.03.01",
						"date": "2024-01-15"
					}
				]
			}`,
			wantCVE:    "CVE-2024-0001",
			wantEPSS:   0.00043,
			wantPctile: 0.125,
		},
		{
			name:    "invalid JSON",
			input:   `{invalid`,
			wantErr: true,
		},
		{
			name: "empty data array",
			input: `{
				"status": "OK",
				"status-code": 200,
				"version": "1.0",
				"total": 0,
				"data": []
			}`,
			wantCVE: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseEPSSResponse([]byte(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantCVE == "" {
				if len(resp.Data) != 0 {
					t.Fatalf("expected empty data, got %d entries", len(resp.Data))
				}
				return
			}

			if len(resp.Data) == 0 {
				t.Fatal("expected data entries, got none")
			}

			got := resp.Data[0]
			if got.CVE != tt.wantCVE {
				t.Errorf("CVE = %q, want %q", got.CVE, tt.wantCVE)
			}
			if got.EPSS != tt.wantEPSS {
				t.Errorf("EPSS = %f, want %f", got.EPSS, tt.wantEPSS)
			}
			if got.Percentile != tt.wantPctile {
				t.Errorf("Percentile = %f, want %f", got.Percentile, tt.wantPctile)
			}
		})
	}
}

func TestParseKEVCatalog(t *testing.T) {
	catalogJSON := `{
		"title": "CISA Known Exploited Vulnerabilities Catalog",
		"catalogVersion": "2024.01.15",
		"dateReleased": "2024-01-15T00:00:00.000Z",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2023-44487",
				"vendorProject": "IETF",
				"product": "HTTP/2",
				"vulnerabilityName": "HTTP/2 Rapid Reset Attack",
				"dateAdded": "2023-10-10",
				"shortDescription": "HTTP/2 protocol allows rapid reset of streams.",
				"requiredAction": "Apply mitigations per vendor instructions.",
				"dueDate": "2023-10-31",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": ""
			},
			{
				"cveID": "CVE-2021-44228",
				"vendorProject": "Apache",
				"product": "Log4j",
				"vulnerabilityName": "Apache Log4j Remote Code Execution",
				"dateAdded": "2021-12-10",
				"shortDescription": "Log4j JNDI injection vulnerability.",
				"requiredAction": "Upgrade to Log4j 2.17.0 or later.",
				"dueDate": "2021-12-24",
				"knownRansomwareCampaignUse": "Known",
				"notes": "Critical RCE"
			}
		]
	}`

	catalog, err := ParseKEVCatalog([]byte(catalogJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if catalog.Count != 2 {
		t.Errorf("Count = %d, want 2", catalog.Count)
	}
	if len(catalog.Vulnerabilities) != 2 {
		t.Fatalf("got %d vulnerabilities, want 2", len(catalog.Vulnerabilities))
	}
	if catalog.Vulnerabilities[0].CVEID != "CVE-2023-44487" {
		t.Errorf("first CVE = %q, want CVE-2023-44487", catalog.Vulnerabilities[0].CVEID)
	}
}

func TestLookupKEV(t *testing.T) {
	catalog := &KEVCatalog{
		Vulnerabilities: []KEVEntry{
			{CVEID: "CVE-2023-44487", VendorProject: "IETF", Product: "HTTP/2"},
			{CVEID: "CVE-2021-44228", VendorProject: "Apache", Product: "Log4j"},
			{CVEID: "CVE-2024-3094", VendorProject: "Tukaani", Product: "XZ Utils"},
		},
	}

	tests := []struct {
		name    string
		cveID   string
		want    bool
		product string
	}{
		{"found exact match", "CVE-2021-44228", true, "Log4j"},
		{"found with whitespace", "  CVE-2024-3094  ", true, "XZ Utils"},
		{"found case insensitive", "cve-2023-44487", true, "HTTP/2"},
		{"not found", "CVE-2099-99999", false, ""},
		{"empty input", "", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, found := LookupKEV(catalog, tt.cveID)
			if found != tt.want {
				t.Errorf("found = %v, want %v", found, tt.want)
			}
			if found && entry.Product != tt.product {
				t.Errorf("product = %q, want %q", entry.Product, tt.product)
			}
		})
	}
}

func TestClassifyRisk(t *testing.T) {
	tests := []struct {
		name  string
		epss  float64
		inKEV bool
		want  RiskPriority
	}{
		{"critical via KEV", 0.01, true, RiskCritical},
		{"critical via high EPSS", 0.85, false, RiskCritical},
		{"critical via both", 0.95, true, RiskCritical},
		{"critical at threshold", 0.7, false, RiskCritical},
		{"high", 0.5, false, RiskHigh},
		{"high at threshold", 0.4, false, RiskHigh},
		{"medium", 0.25, false, RiskMedium},
		{"medium at threshold", 0.1, false, RiskMedium},
		{"low", 0.05, false, RiskLow},
		{"low zero", 0.0, false, RiskLow},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyRisk(tt.epss, tt.inKEV)
			if got != tt.want {
				t.Errorf("ClassifyRisk(%f, %v) = %q, want %q", tt.epss, tt.inKEV, got, tt.want)
			}
		})
	}
}

func TestEnrichFinding(t *testing.T) {
	t.Run("with EPSS and KEV data", func(t *testing.T) {
		epss := &EPSSData{
			CVE:        "CVE-2021-44228",
			EPSS:       0.97565,
			Percentile: 0.99998,
		}
		kev := &KEVEntry{
			CVEID:             "CVE-2021-44228",
			VendorProject:     "Apache",
			Product:           "Log4j",
			VulnerabilityName: "Apache Log4j Remote Code Execution",
		}

		enriched := EnrichFinding("VULN-001", "CVE-2021-44228", epss, kev)

		if enriched.RuleID != "VULN-001" {
			t.Errorf("RuleID = %q, want VULN-001", enriched.RuleID)
		}
		if enriched.EPSSScore != 0.97565 {
			t.Errorf("EPSSScore = %f, want 0.97565", enriched.EPSSScore)
		}
		if !enriched.InKEV {
			t.Error("expected InKEV = true")
		}
		if enriched.RiskPriority != RiskCritical {
			t.Errorf("RiskPriority = %q, want critical", enriched.RiskPriority)
		}
		if enriched.KEVDetail == nil {
			t.Error("expected KEVDetail to be non-nil")
		}
		if enriched.EnrichedAt.IsZero() {
			t.Error("expected EnrichedAt to be set")
		}
	})

	t.Run("with EPSS only", func(t *testing.T) {
		epss := &EPSSData{
			CVE:        "CVE-2024-0001",
			EPSS:       0.15,
			Percentile: 0.55,
		}

		enriched := EnrichFinding("VULN-001", "CVE-2024-0001", epss, nil)

		if enriched.InKEV {
			t.Error("expected InKEV = false")
		}
		if enriched.KEVDetail != nil {
			t.Error("expected KEVDetail to be nil")
		}
		if enriched.RiskPriority != RiskMedium {
			t.Errorf("RiskPriority = %q, want medium", enriched.RiskPriority)
		}
	})

	t.Run("with no data", func(t *testing.T) {
		enriched := EnrichFinding("VULN-001", "CVE-2024-9999", nil, nil)

		if enriched.EPSSScore != 0 {
			t.Errorf("EPSSScore = %f, want 0", enriched.EPSSScore)
		}
		if enriched.InKEV {
			t.Error("expected InKEV = false")
		}
		if enriched.RiskPriority != RiskLow {
			t.Errorf("RiskPriority = %q, want low", enriched.RiskPriority)
		}
	})

	t.Run("JSON serialization", func(t *testing.T) {
		enriched := EnrichFinding("VULN-001", "CVE-2021-44228", &EPSSData{
			EPSS:       0.97,
			Percentile: 0.99,
		}, nil)

		data, err := json.Marshal(enriched)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}

		var decoded EnrichedFinding
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		if decoded.CVE != "CVE-2021-44228" {
			t.Errorf("decoded CVE = %q, want CVE-2021-44228", decoded.CVE)
		}
		if decoded.RiskPriority != RiskCritical {
			t.Errorf("decoded RiskPriority = %q, want critical", decoded.RiskPriority)
		}
	})
}

// --- helpers ---

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}
