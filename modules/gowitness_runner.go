package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RunGowitness(domain, outputDir string) {
	fmt.Println("📸 Running Gowitness...")

	inputFile := filepath.Join(outputDir, "live_hosts.txt")
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Printf("❌ live_hosts.txt not found, skipping gowitness.\n")
		return
	}

	screenshotDir := filepath.Join(outputDir, "screenshots")
	if err := os.MkdirAll(screenshotDir, 0755); err != nil {
		fmt.Printf("❌ Failed to create screenshots dir: %v\n", err)
		return
	}

	cmd := exec.Command("gowitness", "scan", "file",
		"-f", inputFile,
		"-s", screenshotDir,
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ Gowitness error: %v\n", err)
		return
	}

	fmt.Printf("✅ Screenshots saved to: %s\n", screenshotDir)
}
