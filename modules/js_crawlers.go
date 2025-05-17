package modules

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath" // ✅ Add this
	

)



func RunGoLinkFinder(domain, outputDir string) {
	fmt.Println("🔗 Running GoLinkFinder...")

	cmd := exec.Command("GoLinkFinder", "-d", domain, "-o", outputDir+"/golinkfinder.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ GoLinkFinder error: %v\n", err)
		return
	}
	fmt.Println("✅ GoLinkFinder done.")
	fmt.Println(string(output))
}
func RunUrlGrab(domain, outputDir string) {
	fmt.Println("🌐 Running urlgrab...")

	cmd := exec.Command("urlgrab", "-d", domain, "-o", outputDir+"/urlgrab.txt")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ urlgrab error: %v\n", err)
		return
	}
	fmt.Println("✅ urlgrab done.")
	fmt.Println(string(output))
}
func RunWaybackUrls(domain, outputDir string) {
	fmt.Println("📦 Running waybackurls...")

	cmd := exec.Command("waybackurls", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ waybackurls error: %v\n", err)
		return
	}
	err = os.WriteFile(outputDir+"/waybackurls.txt", output, 0644)
	if err != nil {
		fmt.Printf("❌ Write error: %v\n", err)
	}
	fmt.Println("✅ waybackurls done.")
}
func RunGau(domain, outputDir string) {
	fmt.Println("🌐 Running gau...")

	cmd := exec.Command("gau", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ gau error: %v\n", err)
		return
	}
	err = os.WriteFile(outputDir+"/gau.txt", output, 0644)
	if err != nil {
		fmt.Printf("❌ Write error: %v\n", err)
	}
	fmt.Println("✅ gau done.")
}
func RunWaymore(domain, outputDir string) {
	fmt.Println("🕸️ Running Waymore...")

	cmd := exec.Command("waymore", "-i", domain, "-mode", "U")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Waymore error: %v\n", err)
		return
	}

	// Move result to our output folder
	src := filepath.Join(os.Getenv("HOME"), ".config", "waymore", "results", domain, "waymore.txt")
	dest := filepath.Join(outputDir, "waymore.txt")

	data, err := os.ReadFile(src)
	if err == nil {
		os.WriteFile(dest, data, 0644)
		fmt.Println("✅ Waymore done.")
	} else {
		fmt.Printf("❌ Couldn't read waymore.txt: %v\n", err)
	}

	fmt.Println(string(output))
}

func RunParamSpider(domain, outputDir string) {
	fmt.Println("🔍 Running ParamSpider...")

	cmd := exec.Command("paramspider", "-d", domain)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ ParamSpider error: %v\n", err)
		return
	}

	// Move result to outputDir
	src := filepath.Join("results", domain+".txt")
	dest := filepath.Join(outputDir, "params.txt")

	input, err := os.ReadFile(src)
	if err == nil {
		err = os.WriteFile(dest, input, 0644)
		if err != nil {
			fmt.Printf("❌ Failed to move ParamSpider output: %v\n", err)
		} else {
			fmt.Println("✅ ParamSpider done. Output saved to:", dest)
		}
	} else {
		fmt.Println("❌ Couldn't read ParamSpider result:", err)
	}

	fmt.Println(string(output))
}

func RunArjun(domain, outputDir string) {
	fmt.Println("🔍 Running Arjun...")

	cmd := exec.Command("arjun", "-u", "https://"+domain, "-o", outputDir+"/arjun_params.json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("❌ Arjun error: %v\n", err)
		return
	}
	fmt.Println("✅ Arjun done.")
	fmt.Println(string(output))
}
