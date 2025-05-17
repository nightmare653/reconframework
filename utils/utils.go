package utils

import (
	"bufio"
	"os"
	"regexp"
	"strings"
)

// WriteToFile writes byte data to a given file path.
func WriteToFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// Extract200OKURLs parses colored nuclei output and extracts clean URLs with 200 OK status.
func Extract200OKURLs(inputPath string, outputPath string) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()

	scanner := bufio.NewScanner(file)
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`) // Remove ANSI color codes

	for scanner.Scan() {
		line := re.ReplaceAllString(scanner.Text(), "")
		if strings.Contains(line, "[200]") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				url := parts[0]
				_, _ = out.WriteString(url + "\n")
			}
		}
	}

	return scanner.Err()
}
