package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

var gfPatterns = []string{
	"xss",
	"ssrf",
	"idor",
	"sqli",
	"redirect",
	"rce",
	"lfi",
}

func RunGFScanner(domain, outputDir string) {
	fmt.Println("🧪 Running gf scanner on all_urls.txt...")

	input := filepath.Join(outputDir, "all_urls.txt")
	if _, err := os.Stat(input); os.IsNotExist(err) {
		fmt.Println("❌ all_urls.txt not found. Skipping gf scanner.")
		return
	}

	for _, pattern := range gfPatterns {
		output := filepath.Join(outputDir, fmt.Sprintf("gf_%s.txt", pattern))
		cmd := exec.Command("gf", pattern)
		inFile, err := os.Open(input)
		if err != nil {
			fmt.Printf("❌ Failed to open all_urls.txt for %s: %v\n", pattern, err)
			continue
		}
		defer inFile.Close()

		cmd.Stdin = inFile
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("❌ gf %s error: %v\n", pattern, err)
			continue
		}

		if err := os.WriteFile(output, out, 0644); err != nil {
			fmt.Printf("❌ Failed to write gf_%s.txt: %v\n", pattern, err)
			continue
		}
		fmt.Printf("✅ gf scan complete: %s\n", output)
	}
}
