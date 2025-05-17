package modules

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ExecutorStep defines a basic execution instruction extracted from AI plan
type ExecutorStep struct {
	VulnType  string
	TargetURL string
	Payload   string
}

func RunExecutorAgent(domain, outputDir string) {
	fmt.Println("🤖 Executor Agent: Parsing AI plan...")

	aiPlanPath := filepath.Join(outputDir, "ai_plan.txt")
	file, err := os.Open(aiPlanPath)
	if err != nil {
		fmt.Printf("❌ Could not read ai_plan.txt: %v\n", err)
		return
	}
	defer file.Close()

	steps := []ExecutorStep{}
	scanner := bufio.NewScanner(file)
	current := ExecutorStep{}

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "**") && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			vuln := strings.Trim(parts[0], "* ")
			url := strings.TrimSpace(parts[1])
			current = ExecutorStep{VulnType: vuln, TargetURL: url}
			steps = append(steps, current)
		}
	}

	if len(steps) == 0 {
		fmt.Println("⚠️ No exploit steps found.")
		return
	}

	logPath := filepath.Join(outputDir, "executor_log.txt")
	logFile, _ := os.Create(logPath)
	defer logFile.Close()

	for _, step := range steps {
		summary := fmt.Sprintf("[+] Plan: %s | URL: %s\n", step.VulnType, step.TargetURL)
		fmt.Print(summary)
		logFile.WriteString(summary)
	}

	fmt.Printf("✅ Executor Agent log saved to: %s\n", logPath)
}
