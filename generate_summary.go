package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"
)

type ReconSummary struct {
	Domain        string   `json:"domain"`
	Subdomains    []string `json:"subdomains"`
	LiveHosts     []string `json:"live_hosts"`
	JSEndpoints   []string `json:"js_endpoints"`
	Params        []string `json:"params"`
	GFPatterns    []string `json:"gf_patterns"`
	Secrets       []string `json:"secrets"`
	Suspicious    []string `json:"suspicious"`
	CORS          []string `json:"cors"`
	WhatWeb       []string `json:"whatweb"`
	RiskScore     float64  `json:"risk_score"`
	LeaksDetected bool     `json:"leaks_detected"`
}

func readLines(path string) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return []string{}
	}
	lines := strings.Split(string(data), "\n")
	var cleaned []string
	for _, line := range lines {
		if line = strings.TrimSpace(line); line != "" {
			cleaned = append(cleaned, line)
		}
	}
	return cleaned
}

func main() {
	outputDir := "output/myflixer.cx"
	summary := ReconSummary{
		Domain:        "myflixer.cx",
		Subdomains:    readLines(filepath.Join(outputDir, "subdomains.txt")),
		LiveHosts:     readLines(filepath.Join(outputDir, "live_subdomains.txt")),
		JSEndpoints:   readLines(filepath.Join(outputDir, "js_endpoints.txt")),
		Params:        readLines(filepath.Join(outputDir, "params.txt")),
		GFPatterns:    readLines(filepath.Join(outputDir, "gf_patterns.txt")),
		Secrets:       readLines(filepath.Join(outputDir, "js_secrets.txt")),
		Suspicious:    readLines(filepath.Join(outputDir, "regex_flagged.txt")),
		CORS:          readLines(filepath.Join(outputDir, "corsy.json")),
		WhatWeb:       readLines(filepath.Join(outputDir, "whatweb.txt")),
		RiskScore:     7.5,
		LeaksDetected: len(readLines(filepath.Join(outputDir, "js_secrets.txt"))) > 0,
	}

	jsonData, _ := json.MarshalIndent(summary, "", "  ")
	if err := ioutil.WriteFile(filepath.Join(outputDir, "recon_summary.json"), jsonData, 0644); err != nil {
		fmt.Println("❌ Failed to write recon_summary.json:", err)
		return
	}
	fmt.Println("✅ recon_summary.json created successfully.")
}
