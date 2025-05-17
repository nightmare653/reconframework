package modules

import (
	"fmt"
	"os/exec"
)

func RunSubfinder(domain, outputDir string) {
	fmt.Println("🔍 Running subfinder...")

	cmd := exec.Command("subfinder", "-d", domain, "-silent", "-o", outputDir+"/subdomains.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Subfinder error: %v\n", err)
		return
	}

	fmt.Println("✅ Subfinder done.")
	fmt.Println(string(output))
}
