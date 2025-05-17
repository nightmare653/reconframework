package modules

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func RunDisclo(domain, outputDir string) {
	fmt.Println("🔍 Running Disclo PDF scanner...")

	inputFile := filepath.Join(outputDir, "all_urls.txt")
	outputFile := filepath.Join(outputDir, "pdf_keywords.txt")

	// Check input file
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		fmt.Println("❌ all_urls.txt not found, skipping Disclo.")
		return
	}

	// Prepare command
	cmd := exec.Command("./tools/disclo/disclo.sh", inputFile)
	cmd.Dir = "."

	// Open pipe to stdout
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("❌ Failed to capture stdout:", err)
		return
	}

	// Start command
	if err := cmd.Start(); err != nil {
		fmt.Println("❌ Disclo failed to start:", err)
		return
	}

	// Open file to write output
	outFile, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("❌ Failed to create output file:", err)
		return
	}
	defer outFile.Close()

	// Read and write line-by-line
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
		outFile.WriteString(line + "\n")
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		fmt.Println("❌ Error reading Disclo output:", err)
	}

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		fmt.Println("❌ Disclo execution failed:", err)
		return
	}

	fmt.Printf("✅ Disclo results saved to: %s\n", outputFile)
}
