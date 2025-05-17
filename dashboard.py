import streamlit as st
import subprocess
import os
import json
from glob import glob
from datetime import datetime
from weasyprint import HTML  # ✅ PDF support

st.set_page_config(page_title="ReconEngine Dashboard", layout="wide")

st.sidebar.title("🛠️ ReconEngine Controls")
menu = st.sidebar.radio("Select Action", ["🚀 Launch Scan", "📊 View Results", "📂 View All Files", "🤖 AI Assistant"])

BASE_OUTPUT_DIR = "output"
DOMAINS_FILE = "domains.txt"
TOOLS = [
    "amass", "dnsx", "httprobe", "aquatone", "nmap", "subfinder",
    "gauplus", "katana", "linkfinder", "subjs", "getJS", "xnLinkFinder",
    "whatweb", "wpscan", "uro", "git-hound", "awsfinder",
    "dirsearch", "lazyS3", "cloudfail"
]

def stream_logs(process, log_output):
    output = ""
    for line in process.stdout:
        output += line
        log_output.code(output, language="bash")
    process.wait()
    return process.returncode

# === LAUNCH SCAN ===
if menu == "🚀 Launch Scan":
    st.header("🚀 Launch Recon Scan")
    scan_type = st.radio("Scan Type", ["Single Domain", "Domain List File"])
    domain_input, uploaded_file = "", None

    if scan_type == "Single Domain":
        domain_input = st.text_input("Enter domain to scan:")
    else:
        uploaded_file = st.file_uploader("Upload domains.txt")
        if uploaded_file:
            with open(DOMAINS_FILE, "wb") as f:
                f.write(uploaded_file.read())

    selected_tools = st.multiselect("Select tools to run:", TOOLS)

    if st.button("🚀 Start Scan"):
        if scan_type == "Single Domain" and not domain_input:
            st.warning("Please enter a domain.")
        elif scan_type == "Domain List File" and not uploaded_file:
            st.warning("Please upload a domain list file.")
        else:
            log_output = st.empty()
            command = ["./reconengine"]

            if scan_type == "Single Domain":
                command += ["-d", domain_input]
            else:
                command += ["--list", DOMAINS_FILE]

            if selected_tools:
                command += ["--tools", ",".join(selected_tools)]

            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            output = ""
            for line in process.stdout:
                output += line
                log_output.code(output, language="bash")
            process.wait()

# === VIEW RESULTS ===
elif menu == "📊 View Results":
    st.header("📊 Recon Results Viewer")
    domains = sorted([os.path.basename(d) for d in glob(f"{BASE_OUTPUT_DIR}/*") if os.path.isdir(d)])

    if not domains:
        st.warning("⚠️ No scanned domains found.")
    else:
        selected_domain = st.selectbox("Select domain:", domains)
        domain_dir = os.path.join(BASE_OUTPUT_DIR, selected_domain)

        st.subheader("📊 Stats")
        for fname in ["all_subdomains.txt", "all_urls.txt", "gf_xss.txt", "gf_sqli.txt"]:
            path = os.path.join(domain_dir, fname)
            if os.path.exists(path):
                with open(path) as f:
                    lines = [line.strip() for line in f if line.strip()]
                    st.markdown(f"- **{fname}**: `{len(lines)} entries`")

        st.subheader("⏳ Timeline")
        log_path = os.path.join(domain_dir, "execution.log")
        if os.path.exists(log_path):
            with open(log_path) as f:
                for line in f:
                    st.text(line.strip())

        st.subheader("🖼 Screenshot Preview")
        for shot in ["aquatone_report.html", "screenshots/index.html"]:
            path = os.path.join(domain_dir, shot)
            if os.path.exists(path):
                st.markdown(f"📸 [Open Screenshot Viewer]({path})")

        st.subheader("📌 Summary")
        summary_path = os.path.join(domain_dir, "recon_summary.json")
        if os.path.exists(summary_path):
            with open(summary_path) as f:
                summary_data = json.load(f)
                st.json(summary_data)

            with st.expander("📄 Export Report"):
                with open("report_template.html") as template_file:
                    template = template_file.read()
                    html = template.replace("{{SUMMARY_JSON}}", json.dumps(summary_data, indent=2))

                    st.download_button("💾 Download HTML", html, file_name=f"{selected_domain}_report.html")

                    # Generate PDF
                    pdf_path = f"{selected_domain}_report.pdf"
                    HTML(string=html).write_pdf(pdf_path)
                    with open(pdf_path, "rb") as f:
                        st.download_button("📄 Download PDF", f.read(), file_name=pdf_path, mime="application/pdf")

# === FILE EXPLORER ===
elif menu == "📂 View All Files":
    st.header("📂 File Explorer")
    domains = sorted([os.path.basename(d) for d in glob(f"{BASE_OUTPUT_DIR}/*") if os.path.isdir(d)])

    if not domains:
        st.warning("⚠️ No scan output available.")
    else:
        selected_domain = st.selectbox("Select domain:", domains)
        domain_dir = os.path.join(BASE_OUTPUT_DIR, selected_domain)
        files = sorted(glob(f"{domain_dir}/*"))

        if not files:
            st.warning("⚠️ No files found.")
        else:
            selected_file = st.selectbox("Select file:", files)
            st.caption(f"📄 {os.path.basename(selected_file)}")

            if selected_file.endswith(".json"):
                with open(selected_file) as f:
                    try:
                        data = json.load(f)
                        st.json(data)
                        st.download_button("📥 Download JSON", json.dumps(data, indent=2), file_name=os.path.basename(selected_file))
                    except:
                        st.error("❌ Failed to parse JSON.")
            elif selected_file.endswith(".txt"):
                with open(selected_file) as f:
                    content = f.read()
                    search = st.text_input("🔍 Filter lines:")
                    if search:
                        matches = [line for line in content.splitlines() if search.lower() in line.lower()]
                        st.code("\n".join(matches), language="bash")
                    else:
                        st.code(content, language="bash")
                    st.download_button("📥 Download TXT", content, file_name=os.path.basename(selected_file))
            else:
                st.warning("⚠️ Unsupported file type.")

# === AI ASSISTANT ===
elif menu == "🤖 AI Assistant":
    st.header("🤖 Ask ReconEngine (powered by Ollama)")

    domains = sorted([os.path.basename(d) for d in glob(f"{BASE_OUTPUT_DIR}/*") if os.path.isdir(d)])
    if not domains:
        st.warning("⚠️ No scanned domains available.")
    else:
        selected_domain = st.selectbox("Choose a domain to chat with:", domains)
        summary_path = os.path.join(BASE_OUTPUT_DIR, selected_domain, "recon_summary.json")

        if not os.path.exists(summary_path):
            st.error("❌ recon_summary.json not found.")
        else:
            with open(summary_path) as f:
                summary_data = json.load(f)

            if "chat_history" not in st.session_state:
                st.session_state.chat_history = []

            for msg in st.session_state.chat_history:
                role = "👤 You" if msg["role"] == "user" else "🤖 AI"
                st.chat_message(role).write(msg["content"])

            if prompt := st.chat_input("Ask about the scan results..."):
                st.chat_message("👤 You").write(prompt)
                st.session_state.chat_history.append({"role": "user", "content": prompt})

                from ollama import chat
                full_prompt = f"Here is recon data:\n{json.dumps(summary_data, indent=2)}\n\nNow answer this: {prompt}"
                with st.spinner("🤖 Thinking..."):
                    res = chat(model='llama3', messages=[{"role": "user", "content": full_prompt}])
                    answer = res['message']['content']
                    st.chat_message("🤖 AI").write(answer)
                    st.session_state.chat_history.append({"role": "assistant", "content": answer})
