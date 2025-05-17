package modules

import (
	"ReconEngine/utils"
	"fmt"
	"os/exec"
	"path/filepath"
)

func RunWhatWeb(domain, outputDir string) {
	fmt.Println("🔍 Running WhatWeb...")
	outFile := filepath.Join(outputDir, "whatweb.txt")

	cmd := exec.Command("whatweb", domain, "-v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ WhatWeb error: %v\n", err)
		return
	}

	if err := utils.WriteToFile(outFile, output); err != nil {
		fmt.Printf("❌ Failed to write WhatWeb output: %v\n", err)
		return
	}

	fmt.Printf("✅ WhatWeb results saved to: %s\n", outFile)
}
