package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func RunHttprobe(domain, outputDir string) {
	fmt.Println("🌐 Running Httprobe...")
	input := filepath.Join(outputDir, "resolved.txt")
	output := filepath.Join(outputDir, "live_hosts.txt")
	data, _ := os.ReadFile(input)
	cmd := exec.Command("httprobe", "-c", "50")
	cmd.Stdin = strings.NewReader(string(data))
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Httprobe error: %v\n", err)
	}
	_ = os.WriteFile(output, out, 0644)
}
