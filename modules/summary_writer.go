package modules

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RunSummaryWriter(domain, outputDir string) {
	fmt.Println("📊 Generating recon_summary.json...")

	summary := ReconSummary{
		Domain:             domain,
		RiskScoreBreakdown: make(map[string]float64),
	}

	readLines := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			return []string{}
		}
		lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		clean := []string{}
		for _, line := range lines {
			if line != "" {
				clean = append(clean, line)
			}
		}
		return clean
	}

	summary.Subdomains = readLines(filepath.Join(outputDir, "subdomains.txt"))
	summary.LiveHosts = readLines(filepath.Join(outputDir, "live_hosts.txt"))
	summary.JSEndpoints = readLines(filepath.Join(outputDir, "js_endpoints.txt"))
	summary.Params = readLines(filepath.Join(outputDir, "params.txt"))
	summary.Technologies = readLines(filepath.Join(outputDir, "whatweb.txt"))
	summary.DirsDiscovered = len(readLines(filepath.Join(outputDir, "ffuf.json")))
	summary.APICandidates = readLines(filepath.Join(outputDir, "api_endpoints.txt"))
	summary.PotentiallySensitive = readLines(filepath.Join(outputDir, "sensitive_files.txt"))
	summary.InsecureHeaders = readLines(filepath.Join(outputDir, "insecure_headers.txt"))
	summary.CORSMisconfigs = readLines(filepath.Join(outputDir, "corsy.json"))
	summary.XSSCandidates = readLines(filepath.Join(outputDir, "gf_xss.txt"))
	summary.SSRFCandidates = readLines(filepath.Join(outputDir, "gf_ssrf.txt"))
	summary.IDORCandidates = readLines(filepath.Join(outputDir, "gf_idor.txt"))
	summary.OpenRedirectCandidates = readLines(filepath.Join(outputDir, "gf_redirect.txt"))
	summary.HighRiskTags = readLines(filepath.Join(outputDir, "regex_flagged.txt"))

	// JS secrets found
	if fileExists(filepath.Join(outputDir, "js_secrets.txt")) {
		summary.JSSecretsFound = readLines(filepath.Join(outputDir, "js_secrets.txt"))
		summary.LeaksDetected = true
		summary.RiskScoreBreakdown["js_secrets"] = 2.5
	}

	// Gitleaks
	if fileExists(filepath.Join(outputDir, "gitleaks.json")) {
		summary.LeaksDetected = true
		summary.RiskScoreBreakdown["gitleaks"] = 2.0
	}

	// Risk scoring
	if len(summary.Subdomains) > 0 {
		summary.RiskScoreBreakdown["subdomains"] = 1.0
	}
	if len(summary.LiveHosts) > 0 {
		summary.RiskScoreBreakdown["live_hosts"] = 1.0
	}
	if len(summary.JSEndpoints) > 0 {
		summary.RiskScoreBreakdown["js_endpoints"] = 1.0
	}
	if len(summary.APICandidates) > 0 {
		summary.RiskScoreBreakdown["api_endpoints"] = 1.0
	}
	if len(summary.XSSCandidates)+len(summary.SSRFCandidates)+len(summary.IDORCandidates) > 0 {
		summary.RiskScoreBreakdown["gf_findings"] = 2.0
	}

	score := 0.0
	for _, s := range summary.RiskScoreBreakdown {
		score += s
	}
	summary.RiskScore = score

	// Save
	outFile := filepath.Join(outputDir, "recon_summary.json")
	jsonBytes, _ := json.MarshalIndent(summary, "", "  ")
	err := os.WriteFile(outFile, jsonBytes, 0644)
	if err != nil {
		fmt.Printf("❌ Error writing summary: %v\n", err)
		return
	}

	fmt.Println("✅ Summary generated at:", outFile)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
