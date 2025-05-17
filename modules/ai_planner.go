package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func RunAIPlanner(domain, outputDir string) {
	fmt.Println("🧠 Running LLM Planner...")

	summaryPath := filepath.Join(outputDir, "recon_summary.json")
	summaryData, err := os.ReadFile(summaryPath)
	if err != nil {
		fmt.Printf("❌ Could not read recon_summary.json: %v\n", err)
		return
	}

	urlsPath := filepath.Join(outputDir, "all_urls.txt")
	regexPath := filepath.Join(outputDir, "regex_flagged.txt")

	allUrls := readFileAsString(urlsPath)
	regexHits := readFileAsString(regexPath)

	smartPrompt := fmt.Sprintf(`Here is the recon summary and extracted URLs for domain: %s.

Recon Summary:
%s

Top URLs:
%s

Regex Flagged URLs:
%s

Please:
1. Identify the top 3 likely vulnerabilities.
2. Map them to specific URLs.
3. Suggest payloads/tools for testing.
4. Output a step-by-step exploit plan.`, domain, string(summaryData), allUrls, regexHits)

	payload := map[string]interface{}{
		"model":  "llama3",
		"prompt": smartPrompt,
		"stream": false,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post("http://localhost:11434/api/generate", "application/json", bytes.NewBuffer(body))
	if err != nil {
		fmt.Printf("❌ Failed to call LLM: %v\n", err)
		return
	}
	defer resp.Body.Close()

	var result struct {
		Response string `json:"response"`
	}
	json.NewDecoder(resp.Body).Decode(&result)

	outputFile := filepath.Join(outputDir, "ai_plan.txt")
	err = os.WriteFile(outputFile, []byte(result.Response), 0644)
	if err != nil {
		fmt.Printf("❌ Failed to write ai_plan.txt: %v\n", err)
		return
	}

	fmt.Println("✅ AI Planner output saved to:", outputFile)
}

func readFileAsString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.Join(strings.Split(string(data), "\n"), "\n")
}

// 🔍 Extracts the most relevant AI prompt from the LLaMA-generated plan
func GetAIPromptFromPlan(outputDir string) string {
	planPath := filepath.Join(outputDir, "ai_plan.txt")
	data, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Println("⚠️ Could not read ai_plan.txt, using default prompt")
		return "Detect exposed secrets and credentials"
	}
	plan := string(data)

	// Heuristic examples – improve as needed
	switch {
	case strings.Contains(plan, "admin login"):
		return "Find admin login endpoints"
	case strings.Contains(plan, "api key") || strings.Contains(plan, "Authorization"):
		return "Detect API keys or bearer tokens in response"
	case strings.Contains(plan, "stack trace"):
		return "Detect exposed stack traces in error messages"
	case strings.Contains(plan, "sensitive file") || strings.Contains(plan, ".env"):
		return "Find exposed sensitive files like .env or config"
	default:
		return "Detect exposed secrets and credentials"
	}
}
