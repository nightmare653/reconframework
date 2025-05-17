package modules

import (
	"fmt"
	"os/exec"
	"path/filepath"
)

// RunHttpx probes live hosts using httpx and saves detailed output.
func RunHttpx(domain, outputDir string) {
	fmt.Println("🌐 Running httpx...")

	subdomainFile := filepath.Join(outputDir, "subdomains.txt")
	outputFile := filepath.Join(outputDir, "live_hosts.txt")

	// Use absolute path for httpx (no ./)
	cmd := exec.Command("/root/go/bin/httpx",
		"-l", subdomainFile,
		"-title",
		"-tech-detect",
		"-status-code",
		"-o", outputFile,
	)

	cmdOutput, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Httpx error: %v\n", err)
		fmt.Println(string(cmdOutput)) // Show httpx's internal output too
		return
	}

	fmt.Println("✅ Httpx done.")
	fmt.Println(string(cmdOutput))
}
