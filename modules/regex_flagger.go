package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"ReconEngine/utils"
)

func RunRegexFlagger(domain, outputDir string) {
	fmt.Println("🧪 Running regex flagger on all_urls.txt...")

	inputFile := filepath.Join(outputDir, "all_urls.txt")
	outputFile := filepath.Join(outputDir, "regex_flagged.txt")

	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Println("❌ all_urls.txt not found. Skipping regex flagger.")
		return
	}

	file, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to open input: %v\n", err)
		return
	}
	defer file.Close()

	var matches []string

	patterns := []string{
		`(?i)redirect=`,
		`(?i)token=`,
		`(?i)email=`,
		`(?i)apikey=`,
		`(?i)key=`,
		`(?i)callback=`,
		`(?i)logout=`,
		`(?i)return=`,
		`(?i)auth=`,
		`(?i)access[_-]?token=`,
		`(?i)jwt=`,
		`(?i)secret`,
	}

	combinedRegex := regexp.MustCompile("(" + joinPatterns(patterns) + ")")

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if combinedRegex.MatchString(line) {
			matches = append(matches, line)
		}
	}

	if err := os.WriteFile(outputFile, []byte(utils.JoinLines(matches)), 0644); err != nil {
		fmt.Printf("❌ Failed to write regex_flagged.txt: %v\n", err)
		return
	}

	fmt.Printf("✅ Regex flagger found %d suspicious URLs → %s\n", len(matches), outputFile)
}

func joinPatterns(pats []string) string {
	return regexp.QuoteMeta(pats[0]) + "|" + utils.JoinLines(pats[1:])
}
