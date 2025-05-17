package modules

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

const ollamaHost = "http://localhost:11434"
const modelName = "llama3"

func RunAIAnalyzer(domain, outputDir string) {
	fmt.Println("🧠 Sending recon_summary.json to LLaMA for AI analysis...")

	summaryPath := filepath.Join(outputDir, "recon_summary.json")
	jsonBytes, err := os.ReadFile(summaryPath)
	if err != nil {
		fmt.Printf("❌ Failed to read summary: %v\n", err)
		return
	}

	prompt := fmt.Sprintf(`Here is a JSON summary of recon data for a domain. 
Analyze this and suggest:
- 3 vulnerable endpoints
- Potential PoC commands
- Attack chain if possible

Recon Summary:\n%s`, string(jsonBytes))

	reqBody, _ := json.Marshal(map[string]interface{}{
		"model":  modelName,
		"prompt": prompt,
		"stream": false,
	})

	resp, err := http.Post(ollamaHost+"/api/generate", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		fmt.Printf("❌ Error sending to LLaMA: %v\n", err)
		return
	}
	defer resp.Body.Close()

	respBody, _ := ioutil.ReadAll(resp.Body)

	var result map[string]interface{}
	err = json.Unmarshal(respBody, &result)
	if err != nil {
		fmt.Printf("❌ Failed to parse AI response: %v\n", err)
		return
	}

	fmt.Println("📬 AI Analysis Output:")
	fmt.Println("----------------------")
	fmt.Println(result["response"])

	_ = os.WriteFile(filepath.Join(outputDir, "ai_analysis.txt"), []byte(result["response"].(string)), 0644)
	fmt.Println("✅ AI suggestions saved to ai_analysis.txt")
}
