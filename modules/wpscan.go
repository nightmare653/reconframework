package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunWpscan scans WordPress sites if WP detected via whatweb or wappalyzer
func RunWpscan(domain, outputDir string) {
	techFiles := []string{
		filepath.Join(outputDir, "wappalyzer.json"),
		filepath.Join(outputDir, "whatweb.txt"),
	}

	isWordPress := false
	for _, file := range techFiles {
		data, err := os.ReadFile(file)
		if err == nil && strings.Contains(strings.ToLower(string(data)), "wordpress") {
			isWordPress = true
			break
		}
	}

	if !isWordPress {
		fmt.Println("❌ WordPress not detected. Skipping WPScan.")
		return
	}

	fmt.Println("🔍 WordPress detected. Running WPScan...")

	outFile := filepath.Join(outputDir, "wpscan_output.txt")
	cmd := exec.Command("wpscan", "--url", "https://"+domain, "--no-update")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ WPScan error: %v\n", err)
	}

	_ = os.WriteFile(outFile, output, 0644)
	fmt.Printf("✅ WPScan completed. Output saved to: %s\n", outFile)
}
