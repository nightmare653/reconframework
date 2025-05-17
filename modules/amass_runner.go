package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func RunAmass(domain, outputDir string) {
	fmt.Println("🔍 Running Amass...")
	output := filepath.Join(outputDir, "amass.txt")
	cmd := exec.Command("amass", "enum", "-passive", "-d", domain, "-o", output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Amass error: %v\n", err)
	}
	fmt.Println(string(out))
}
