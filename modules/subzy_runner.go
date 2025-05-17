package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"ReconEngine/utils"
)

func RunSubzy(domain, outputDir string) {
	liveFile := filepath.Join(outputDir, "live_hosts.txt")
	hostsFile := filepath.Join(outputDir, "all_subdomains.txt")
	resultFile := filepath.Join(outputDir, "subzy_results.txt")

	if _, err := os.Stat(liveFile); os.IsNotExist(err) {
		fmt.Printf("❌ live_hosts.txt not found for %s\n", domain)
		return
	}

	// Extract only hostnames from live_hosts.txt
	if err := utils.ExtractHostnamesFromURLs(liveFile, hostsFile); err != nil {
		fmt.Printf("❌ Failed to extract hostnames: %v\n", err)
		return
	}

	fmt.Printf("🔍 Running Subzy on %s...\n", domain)

	cmd := exec.Command("subzy", "run",
		"--targets", hostsFile,
		"--hide_fails",
		"--concurrency", "20",
		"--timeout", "15",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Subzy error on %s: %v\n", domain, err)
		return
	}

	if err := os.WriteFile(resultFile, output, 0644); err != nil {
		fmt.Printf("❌ Failed to write Subzy results for %s: %v\n", domain, err)
		return
	}

	fmt.Printf("✅ Subzy scan complete for %s. Results saved to %s\n", domain, resultFile)
}
