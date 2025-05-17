package modules

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
)

type OTXResponse struct {
	URLList    []map[string]interface{} `json:"url_list"`
	HasNext    bool                     `json:"has_next"`
	PageNum    int                      `json:"page_num"`
	ActualSize int                      `json:"actual_size"`
}

func RunOTXFetcher(domain, outputDir string) {
	fmt.Println("🌐 Fetching OTX URLs...")

	outFile := filepath.Join(outputDir, "otx_urls.txt")
	page := 1
	allUrls := []string{}

	for {
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/url_list?limit=500&page=%d", domain, page)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("❌ Error fetching page %d: %v\n", page, err)
			break
		}

		body, _ := ioutil.ReadAll(resp.Body)
		resp.Body.Close()

		var result OTXResponse
		if err := json.Unmarshal(body, &result); err != nil {
			fmt.Println("❌ JSON parsing failed:", err)
			break
		}

		for _, entry := range result.URLList {
			if urlStr, ok := entry["url"].(string); ok {
				allUrls = append(allUrls, urlStr)
			}
		}

		if !result.HasNext {
			break
		}
		page++
	}

	if len(allUrls) == 0 {
		fmt.Println("ℹ️ No URLs found from OTX.")
		return
	}

	err := os.WriteFile(outFile, []byte(joinLines(allUrls)), 0644)
	if err != nil {
		fmt.Println("❌ Failed to write otx_urls.txt:", err)
		return
	}

	fmt.Println("✅ OTX URLs saved to:", outFile)
}

func joinLines(lines []string) string {
	result := ""
	for _, line := range lines {
		result += line + "\n"
	}
	return result
}
