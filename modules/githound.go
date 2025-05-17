package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RunGitHound(domain, outputDir string) {
	fmt.Println("🔍 Running Git-Hound...")

	subdomainFile := filepath.Join(outputDir, "subdomains.txt")
	outputFile := filepath.Join(outputDir, "githound.json")

	if _, err := os.Stat(subdomainFile); os.IsNotExist(err) {
		fmt.Println("❌ subdomains.txt not found. Skipping Git-Hound.")
		return
	}

	cmd := exec.Command("git-hound", "--query-file", subdomainFile, "--json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Git-Hound error: %v\n", err)
		return
	}

	err = os.WriteFile(outputFile, output, 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write githound.json: %v\n", err)
		return
	}

	fmt.Println("✅ Git-Hound results saved to:", outputFile)
}
