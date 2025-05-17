package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func RunDnsx(domain, outputDir string) {
	fmt.Println("🌐 Running DNSX...")
	input := filepath.Join(outputDir, "all_subdomains.txt")
	output := filepath.Join(outputDir, "resolved.txt")
	cmd := exec.Command("dnsx", "-l", input, "-o", output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ DNSX error: %v\n", err)
	}
	fmt.Println(string(out))
}
