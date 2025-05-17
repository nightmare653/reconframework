package modules

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// RunSecretScanner scans both remote domain and local JS files for secrets.
func RunSecretScanner(domain, outputDir string) {
	scriptPath := "tools/secret_detector/secret_detector.py"
	outputFile := filepath.Join(outputDir, "secrets_detected.txt")
	mergedFile := filepath.Join(outputDir, "all_secrets.txt")
	jsSecretsFile := filepath.Join(outputDir, "js_secrets.txt")

	fmt.Println("🔐 Running Advanced Secret Scanner on domain...")
	cmd := exec.Command("python3", scriptPath,
		"--domain", domain,
		"--all",
		"--depth", "2",
		"--max-pages", "1000",
		"--verbose",
		"--rate-limit", "1",
	)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(outputFile, out, 0644)

	if err != nil {
		fmt.Printf("❌ Secret Scanner error: %v\n", err)
	} else {
		fmt.Println("✅ Secret Scanner completed successfully.")
	}

	// Merge with js_secrets.txt if it exists
	fmt.Println("🔄 Merging JS and Detector outputs...")
	combined := make(map[string]bool)
	files := []string{outputFile, jsSecretsFile}
	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				combined[line] = true
			}
		}
		f.Close()
	}
	outFile, err := os.Create(mergedFile)
	if err != nil {
		fmt.Printf("❌ Failed to write all_secrets.txt: %v\n", err)
		return
	}
	defer outFile.Close()
	for secret := range combined {
		_, _ = outFile.WriteString(secret + "\n")
	}
	fmt.Printf("🔐 Combined secrets saved to: %s\n", mergedFile)
}
