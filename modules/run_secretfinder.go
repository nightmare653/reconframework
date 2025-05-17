package modules

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func RunSecretFinder(domain, outputDir string) {
	fmt.Println("🔐 Running SecretFinder...")

	inputFile := filepath.Join(outputDir, "all_urls.txt")
	outputFile := filepath.Join(outputDir, "js_secrets.txt")

	urls := extractJSUrls(inputFile)
	if len(urls) == 0 {
		fmt.Println("❌ No JS URLs found to scan with SecretFinder.")
		return
	}

	output, err := os.Create(outputFile)
	if err != nil {
		fmt.Printf("❌ Failed to create output file: %v\n", err)
		return
	}
	defer output.Close()

	secretFinderPath := "SecretFinder.py"

	for _, jsURL := range urls {
		cmd := exec.Command("python3", secretFinderPath, "-i", jsURL, "-o", "cli")
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Fprintf(output, "[ERROR] %s: %v\n", jsURL, err)
		} else {
			fmt.Fprintf(output, "[URL] %s\n%s\n\n", jsURL, string(out))
		}
	}

	fmt.Printf("✅ SecretFinder results saved to: %s\n", outputFile)
}

func extractJSUrls(path string) []string {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	var jsUrls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ".js") && !strings.HasSuffix(line, ".json") {
			jsUrls = append(jsUrls, line)
		}
	}
	return jsUrls
}
