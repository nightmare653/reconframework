package modules

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunHakrawler(domain, outputDir string) {
	fmt.Println("🕷️ Running Hakrawler...")

	// Prepare input URL
	input := fmt.Sprintf("https://%s", domain)
	cmd := exec.Command("hakrawler", "-subs")
	cmd.Stdin = strings.NewReader(input)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Hakrawler error: %v\n", err)
		return
	}

	err = os.WriteFile(outputDir+"/hakrawler.txt", output, 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write Hakrawler output: %v\n", err)
		return
	}

	fmt.Println("✅ Hakrawler done.")
}
