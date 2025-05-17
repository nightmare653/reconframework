package modules

import (
	"fmt"
	"os/exec"
)

func RunFfuf(domain, outputDir string) {
	fmt.Println("📂 Running FFUF...")

	cmd := exec.Command("ffuf", "-u", "https://"+domain+"/FUZZ", "-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-o", outputDir+"/ffuf.json", "-of", "json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ FFUF error: %v\n", err)
		return
	}
	fmt.Println("✅ FFUF done.")
	fmt.Println(string(output))
}
