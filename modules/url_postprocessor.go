package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RunURLPostProcessor(domain, outputDir string) {
	fmt.Println("🧹 Merging and deduplicating URL outputs...")

	files := []string{
		"golinkfinder.txt",
		"urlgrab.txt",
		"waybackurls.txt",
		"gau.txt",
		"waymore.txt",
	}

	urlSet := make(map[string]bool)

	for _, file := range files {
		path := filepath.Join(outputDir, file)
		f, err := os.Open(path)
		if err != nil {
			continue // Skip missing or unreadable files
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && strings.HasPrefix(line, "http") {
				urlSet[line] = true
			}
		}
	}

	// Write deduplicated URLs
	mergedPath := filepath.Join(outputDir, "all_urls.txt")
	out, err := os.Create(mergedPath)
	if err != nil {
		fmt.Printf("❌ Failed to create all_urls.txt: %v\n", err)
		return
	}
	defer out.Close()

	for url := range urlSet {
		out.WriteString(url + "\n")
	}

	fmt.Printf("✅ URL merging complete: %d unique URLs written to %s\n", len(urlSet), mergedPath)
}
