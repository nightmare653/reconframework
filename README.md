# 🔎 ReconFramework

**ReconFramework** is a modular, extensible, and AI-powered reconnaissance automation tool built in Go with a Streamlit UI. It enables security researchers, bug bounty hunters, and red teamers to perform advanced recon with minimal manual effort.

---

tools to be installed

🔍 1. Subdomain Enumeration

    ✅ subfinder

    ✅ amass (passive)

    ✅ subdominator

🌐 2. DNS Resolution & Live Host Detection

    ✅ dnsx (resolves all_subdomains.txt)

    ✅ httpx

    ✅ httprobe

📸 3. Screenshot Capture

    ✅ gowitness (replaces aquatone)

⚡ 4. Port Scanning

    ✅ nmap (quick scan on port 80/443)

📜 5. JavaScript & Content Discovery

    ✅ gau (old)

    ✅ gauplus (planned to replace gau)

    ✅ waybackurls

    ✅ golinkfinder

    ✅ hakrawler

    ⏳ katana (pending)

    ⏳ linkfinder, subjs, getJS, xnLinkFinder (planned via script integration)

🧠 6. Tech Stack Detection

    ✅ wappalyzer

    ✅ whatweb

🧬 7. Secrets & Sensitive Data Discovery

    ✅ Gitleaks

    ✅ SecretFinder (Python)

    ✅ JSSecretScanner (custom)

    ✅ RegexFlagger

    ✅ Disclo

    ✅ hakcheckurl

🛠️ 8. Parameter & Vulnerability Scanning

    ✅ gf (patterns: xss, sqli, ssrf, etc.)

    ✅ paramspider

    ✅ arjun

    ✅ ffuf

☁️ 9. 3rd-Party Exposure & Cloud Misconfig Detection

    ✅ corsy

    ✅ wpscan (WordPress detection if fingerprinted)

    ⏳ git-hound, awsfinder, cloudfail, lazyS3 (pending full integration)

🧠 10. AI Integration

    ✅ AI Planner (LLaMA + attack reasoning)

    ✅ AI Assistant Chatbot (Ollama-based, in UI)

📊 11. Reporting & Summary

    ✅ summary_writer.go

    ✅ generate_summary.go

    ✅ HTML Report Generation

    ✅ Timeline & Stats Tracker

    ✅ Screenshot Viewer in UI



## 🖥️ Streamlit Dashboard

```
pip install streamlit
```

Run the dashboard:

```bash
streamlit run dashboard.py

```

🔗 Requirements

    Go (v1.20+)

    Python (3.8+)

    Ollama installed & running (LLaMA3)

    Tools installed & accessible in $PATH:

        subfinder, dnsx, httpx, nmap, gowitness, etc.

    Optional Python tools:

        Corsy, SecretFinder, etc.

📦 Setup

git clone https://github.com/nightmare653/reconframework.git
cd reconframework
go build -o reconengine ./cmd/main.go

✅ Usage
CLI:

./reconengine -d example.com --tools subfinder,httpx,gau
./reconengine --list domains.txt --tools all

Dashboard:

streamlit run dashboard.py

📄 Report Generation

HTML reports can be downloaded from the UI.
🧠 AI Assistant

Powered by your local Ollama LLaMA model:

    Summarize recon data

    Identify vulnerabilities

    Suggest attack paths

🙌 Contributions

PRs, suggestions, and tool integrations welcome!
📜 License

MIT © nightmare653


