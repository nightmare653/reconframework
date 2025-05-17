package modules

type ReconSummary struct {
	Domain             string             `json:"domain"`
	Subdomains         []string           `json:"subdomains"`
	LiveHosts          []string           `json:"live_hosts"`
	JSEndpoints        []string           `json:"js_endpoints"`
	Params             []string           `json:"params"`
	LeaksDetected      bool               `json:"leaks_detected"`
	Technologies       []string           `json:"technologies"`
	DirsDiscovered     int                `json:"dirs_discovered"`
	RiskScore          float64            `json:"risk_score"`
	RiskScoreBreakdown map[string]float64 `json:"risk_score_breakdown,omitempty"`

	// 🧠 For AI Planner and Summary Modules
	APICandidates          []string `json:"api_candidates,omitempty"`
	PotentiallySensitive   []string `json:"potentially_sensitive,omitempty"`
	InsecureHeaders        []string `json:"insecure_headers,omitempty"`
	CORSMisconfigs         []string `json:"cors_misconfigs,omitempty"`
	XSSCandidates          []string `json:"xss_candidates,omitempty"`
	SSRFCandidates         []string `json:"ssrf_candidates,omitempty"`
	IDORCandidates         []string `json:"idor_candidates,omitempty"`
	OpenRedirectCandidates []string `json:"open_redirect_candidates,omitempty"`
	HighRiskTags           []string `json:"high_risk_tags,omitempty"`   // ✅ Add this
	JSSecretsFound         []string `json:"js_secrets_found,omitempty"` // ✅ And this
}
