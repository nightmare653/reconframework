// ✅ ReconEngine Main Controller (main.go)
package main

import (
	"ReconEngine/modules"
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var toolList = []string{
	"subfinder", "subdominator", "amass", "dnsx", "httprobe", "httpx", "subzy", "wappalyzer",
	"gowitness", "nmap", // 🔥 Add these here
	"gau", "otx",
	"hakrawler", "secret_scanner", "url_post", "gf", "regex_flagger",
	"disclo", "hakcheckurl", "js_secret", "secret_finder", "paramspider",
	"arjun", "gitleaks", "whatweb", "githound", "ffuf", "wpscan",
	"summary", "aiplanner",
}

func runRecon(domain string, selected map[string]bool) {
	outputDir := filepath.Join("output", domain)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		fmt.Printf("❌ Failed to create output directory: %v\n", err)
		return
	}

	fmt.Printf("🚀 Starting recon on: %s\n", domain)

	safeRun("subfinder", selected, func() { modules.RunSubfinder(domain, outputDir) })
	safeRun("subdominator", selected, func() { modules.RunSubdominator(domain, outputDir) })
	safeRun("httpx", selected, func() { modules.RunHttpx(domain, outputDir) })
	safeRun("subzy", selected, func() { modules.RunSubzy(domain, outputDir) })
	safeRun("amass", selected, func() { modules.RunAmass(domain, outputDir) })
	safeRun("dnsx", selected, func() { modules.RunDnsx(domain, outputDir) })
	safeRun("httprobe", selected, func() { modules.RunHttprobe(domain, outputDir) })
	safeRun("gowitness", selected, func() { modules.RunGowitness(domain, outputDir) })
	safeRun("nmap", selected, func() { modules.RunNmap(domain, outputDir) })

	safeRun("wappalyzer", selected, func() { modules.RunWappalyzer(domain, outputDir) })
	safeRun("golinkfinder", selected, func() { modules.RunGoLinkFinder(domain, outputDir) })
	safeRun("waybackurls", selected, func() { modules.RunWaybackUrls(domain, outputDir) })
	//safeRun("waymore", selected, func() { modules.RunWaymore(domain, outputDir) })
	safeRun("gau", selected, func() { modules.RunGau(domain, outputDir) })
	safeRun("otx", selected, func() { modules.RunOTXFetcher(domain, outputDir) })
	safeRun("hakrawler", selected, func() { modules.RunHakrawler(domain, outputDir) })
	safeRun("secret_scanner", selected, func() { modules.RunSecretScanner(domain, outputDir) })
	safeRun("url_post", selected, func() { modules.RunURLPostProcessor(domain, outputDir) })
	safeRun("gf", selected, func() { modules.RunGFScanner(domain, outputDir) })
	safeRun("regex_flagger", selected, func() { modules.RunRegexFlagger(domain, outputDir) })
	safeRun("disclo", selected, func() { modules.RunDisclo(domain, outputDir) })
	safeRun("hakcheckurl", selected, func() { modules.RunHakCheckURL(domain, outputDir) })
	safeRun("js_secret", selected, func() { modules.RunJSSecretScanner(domain, outputDir) })
	safeRun("secret_finder", selected, func() { modules.RunSecretFinder(domain, outputDir) })
	safeRun("paramspider", selected, func() { modules.RunParamSpider(domain, outputDir) })
	safeRun("arjun", selected, func() { modules.RunArjun(domain, outputDir) })
	safeRun("gitleaks", selected, func() { modules.RunGitleaks(domain, outputDir) })
	safeRun("whatweb", selected, func() { modules.RunWhatWeb(domain, outputDir) })
	//safeRun("githound", selected, func() { modules.RunGitHound(domain, outputDir) })
	safeRun("wpscan", selected, func() { modules.RunWpscan(domain, outputDir) })

	safeRun("ffuf", selected, func() { modules.RunFfuf(domain, outputDir) })
	safeRun("summary", selected, func() { modules.RunSummaryWriter(domain, outputDir) })
	safeRun("aiplanner", selected, func() { modules.RunAIPlanner(domain, outputDir) })

	fmt.Println("✅ Recon complete.")
}

func safeRun(name string, selected map[string]bool, fn func()) {
	if selected == nil || selected[name] {
		fmt.Printf("▶️ Running %s...\n", name)
		fn()
	}
}

func getSelectedTools(tools string) map[string]bool {
	if tools == "all" || tools == "" {
		sel := make(map[string]bool)
		for _, t := range toolList {
			sel[t] = true
		}
		return sel
	}
	parts := strings.Split(tools, ",")
	selected := make(map[string]bool)
	for _, p := range parts {
		selected[strings.TrimSpace(p)] = true
	}
	return selected
}

func main() {
	domain := flag.String("d", "", "Target domain (e.g., example.com)")
	list := flag.String("list", "", "Path to file with list of domains")
	tools := flag.String("tools", "all", "Comma-separated list of tools to run (or 'all')")
	flag.Parse()

	selected := getSelectedTools(*tools)

	if *domain == "" && *list == "" {
		fmt.Println("Usage:")
		fmt.Println("  ./reconengine -d example.com")
		fmt.Println("  ./reconengine --list domains.txt")
		fmt.Println("  Optional: --tools subfinder,httpx,gau")
		os.Exit(1)
	}

	if *list != "" {
		file, err := os.Open(*list)
		if err != nil {
			fmt.Printf("❌ Failed to open domain list file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				runRecon(line, selected)
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("❌ Error reading domain list: %v\n", err)
		}
	} else {
		runRecon(*domain, selected)
	}
}
