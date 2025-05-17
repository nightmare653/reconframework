// ✅ Go module: Inject auth headers into HTTP client
package utils

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
)

var AuthHeaders map[string]string

// LoadAuthHeaders reads headers from config/auth_headers.json
func LoadAuthHeaders() {
	file, err := os.Open("config/auth_headers.json")
	if err != nil {
		fmt.Println("⚠️  No auth_headers.json found, skipping auth injection.")
		return
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&AuthHeaders)
	if err != nil {
		fmt.Println("❌ Failed to parse auth_headers.json:", err)
		return
	}

	fmt.Println("🔑 Loaded authenticated headers.")
}

// InjectAuthHeaders adds auth headers to an HTTP request
func InjectAuthHeaders(req *http.Request) {
	if AuthHeaders == nil {
		return
	}
	for key, value := range AuthHeaders {
		req.Header.Set(key, value)
	}
}
