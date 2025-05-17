package modules

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunSubdominator runs passive subdomain enumeration using Subdominator.
func RunSubdominator(domain, outputDir string) {
	subdomFile := filepath.Join(outputDir, "subdominator.txt")
	subfinderFile := filepath.Join(outputDir, "subfinder.txt")
	allFile := filepath.Join(outputDir, "all_subdomains.txt")

	fmt.Println("🔍 Running Subdominator...")
	cmd := exec.Command("subdominator", "-d", domain, "-o", subdomFile, "-s")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Subdominator error: %v\n", err)
		return
	}
	fmt.Println("✅ Subdominator done.")

	// Merge with subfinder.txt if it exists
	subdomains := make(map[string]bool)
	mergeFiles := []string{subfinderFile, subdomFile}
	for _, file := range mergeFiles {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				subdomains[line] = true
			}
		}
		f.Close()
	}

	// Write deduplicated results
	out, err := os.Create(allFile)
	if err != nil {
		fmt.Printf("❌ Failed to write all_subdomains.txt: %v\n", err)
		return
	}
	defer out.Close()
	for sub := range subdomains {
		_, _ = out.WriteString(sub + "\n")
	}
	fmt.Printf("✅ Merged subdomains saved to: %s\n", allFile)
}
