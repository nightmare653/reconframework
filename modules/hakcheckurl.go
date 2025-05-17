package modules

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

func RunHakCheckURL(domain, outputDir string) {
	fmt.Println("🌐 Running hakcheckurl on all_urls.txt...")

	inputFile := filepath.Join(outputDir, "all_urls.txt")
	liveOutputFile := filepath.Join(outputDir, "live_urls.txt")
	confirmedFile := filepath.Join(outputDir, "confirmed_alive.txt")

	// Check if input exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Println("❌ all_urls.txt not found. Skipping hakcheckurl.")
		return
	}

	// Prepare command
	cmd := exec.Command("hakcheckurl", "-t", "50", "-retry", "2", "-timeout", "5", "-retry-sleep", "1")

	stdin, err := os.Open(inputFile)
	if err != nil {
		fmt.Printf("❌ Failed to open all_urls.txt: %v\n", err)
		return
	}
	defer stdin.Close()
	cmd.Stdin = stdin

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Only print warning instead of failing
		fmt.Printf("⚠️ hakcheckurl finished with warnings (exit: %v). Continuing...\n", err)
	}

	// Write full output to live_urls.txt
	err = os.WriteFile(liveOutputFile, output, 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write live_urls.txt: %v\n", err)
		return
	}
	fmt.Println("✅ hakcheckurl done. Full results saved to:", liveOutputFile)

	// Filter for confirmed 2xx responses
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var confirmed []string

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		statusCode, err := strconv.Atoi(fields[0])
		if err == nil && statusCode >= 200 && statusCode < 300 {
			confirmed = append(confirmed, line)
		}
	}

	err = os.WriteFile(confirmedFile, []byte(strings.Join(confirmed, "\n")), 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write confirmed_alive.txt: %v\n", err)
		return
	}
	fmt.Printf("✅ Confirmed 2xx URLs saved to: %s (%d alive)\n", confirmedFile, len(confirmed))
}
