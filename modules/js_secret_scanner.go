package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"ReconEngine/utils"
)

func RunJSSecretScanner(domain, outputDir string) {
	fmt.Println("🔐 Scanning JS URLs for secrets...")

	inputFile := filepath.Join(outputDir, "all_urls.txt")
	outputFile := filepath.Join(outputDir, "js_secrets.txt")

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Println("❌ all_urls.txt not found. Skipping JS secret scan.")
		return
	}

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to open all_urls.txt: %v\n", err)
		return
	}
	defer file.Close()

	// Regex patterns to catch secrets
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)api[_-]?key[\s=:]+['"]?[A-Za-z0-9-_]{16,45}`),
		regexp.MustCompile(`(?i)secret[\s=:]+['"]?[A-Za-z0-9-_]{12,}`),
		regexp.MustCompile(`(?i)access[_-]?token[\s=:]+['"]?[A-Za-z0-9-_]{12,}`),
		regexp.MustCompile(`(?i)authorization[\s=:]+['"]?(Bearer )?[A-Za-z0-9\._\-]{20,}`),
		regexp.MustCompile(`(?i)firebaseConfig\s*=\s*{[^}]+}`),
		regexp.MustCompile(`(?i)client[_-]?secret[\s=:]+['"][A-Za-z0-9-_]{12,}`),
	}

	var matches []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !isJSFile(line) {
			continue
		}
		for _, re := range patterns {
			if re.MatchString(line) {
				matches = append(matches, line)
				break
			}
		}
	}

	if err := os.WriteFile(outputFile, []byte(utils.JoinLines(matches)), 0644); err != nil {
		fmt.Printf("❌ Failed to write js_secrets.txt: %v\n", err)
		return
	}

	fmt.Printf("✅ JS secret scanner found %d matching URLs → %s\n", len(matches), outputFile)
}

func isJSFile(url string) bool {
	return regexp.MustCompile(`(?i)\.js(\?|$)`).MatchString(url)
}
