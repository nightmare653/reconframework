# 🔎 ReconFramework

**ReconFramework** is a modular, extensible, and AI-powered reconnaissance automation tool built in Go with a Streamlit UI. It enables security researchers, bug bounty hunters, and red teamers to perform advanced recon with minimal manual effort.

---


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


