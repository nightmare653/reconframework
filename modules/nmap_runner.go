package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

func RunNmap(domain, outputDir string) {
	fmt.Println("🔍 Running Nmap TCP scan...")
	input := filepath.Join(outputDir, "resolved.txt")
	output := filepath.Join(outputDir, "nmap_tcp.txt")
	cmd := exec.Command("nmap", "-iL", input, "-p80,443", "-T4", "-oN", output)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Nmap error: %v\n", err)
	}
	fmt.Println(string(out))
}
