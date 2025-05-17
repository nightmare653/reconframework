package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func RunWappalyzer(domain, outputDir string) {
	fmt.Println("🧠 Running Wappalyzer...")

	outputFile := filepath.Join(outputDir, "wappalyzer.json")

	cmd := exec.Command("wappalyzer",
		"--target", "https://"+domain,
		"--output", outputFile,
		"--json",
		"--disable-ssl",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Wappalyzer error: %v\n", err)
		fmt.Println("🔍 Output:", string(output))
		return
	}

	fmt.Println("✅ Wappalyzer results saved to:", outputFile)
}
