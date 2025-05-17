package modules

import (
	"fmt"
	"os/exec"
)

func RunGitleaks(domain, outputDir string) {
	fmt.Println("🔐 Running Gitleaks...")

	cmd := exec.Command("gitleaks", "detect", "--source=.", "--report-path="+outputDir+"/gitleaks.json", "--no-git")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Gitleaks error: %v\n", err)
		return
	}
	fmt.Println("✅ Gitleaks done.")
	fmt.Println(string(output))
}
