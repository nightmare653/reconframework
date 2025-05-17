import streamlit as st
import subprocess
import os
import json
from glob import glob
import pandas as pd
from datetime import datetime

st.set_page_config(page_title="ReconEngine Dashboard", layout="wide")

st.sidebar.title("🛠️ ReconEngine Controls")
menu = st.sidebar.radio("Select Action", ["🛱 Launch Scan", "📊 View Results", "📂 View All Files"])

# Paths
BASE_OUTPUT_DIR = "output"
DOMAINS_FILE = "domains.txt"
STATE_FILE = "recon_state.json"
SCREENSHOT_FILE_NAMES = ["aquatone_report.html", "screenshots/index.html"]

def load_state():
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return json.load(f)
    return {}

def stream_logs(process, log_output):
    output = ""
    for line in process.stdout:
        output += line
        log_output.code(output, language="bash")
    process.wait()
    return process.returncode

def show_progress(domain, state_data, total_modules=25):
    completed = state_data.get(domain, {})
    count = len([k for k, v in completed.items() if v])
    st.progress(count / total_modules)
    st.caption(f"{count} of {total_modules} modules completed")

def try_parse_json_file(path):
    try:
        with open(path) as f:
            return json.load(f)
    except:
        return None

def try_parse_txt_file(path):
    try:
        with open(path) as f:
            return f.read().splitlines()
    except:
        return []

if menu == "🛱 Launch Scan":
    st.header("🛱 Launch Recon Scan")

    if not os.path.exists(DOMAINS_FILE):
        st.error("❌ domains.txt not found.")
    else:
        with open(DOMAINS_FILE) as f:
            domain_list = [line.strip() for line in f if line.strip()]

        state_data = load_state()

        col1, col2 = st.columns([3, 1])
        selected_domain = col1.selectbox("Select a domain:", domain_list)
        scan_all = col2.checkbox("🔁 Scan All Domains")

        if st.button("🚀 Start Scan"):
            log_output = st.empty()

            def run_scan(domain):
                log_output.markdown(f"**🔍 Running ReconEngine for `{domain}`...**")
                show_progress(domain, state_data)
                process = subprocess.Popen(["./reconengine", "-d", domain],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           text=True)
                return stream_logs(process, log_output)

            def run_nucleifuzzer(domain):
                log_output.markdown(f"**🧪 Running NucleiFuzzer on `{domain}`...**")
                process = subprocess.Popen(["nf", "-d", domain, "-o", f"output/{domain}", "-v", "-r", "2"],
                                           stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT,
                                           text=True)
                return stream_logs(process, log_output)

            failed = []
            domains_to_scan = domain_list if scan_all else [selected_domain]

            for domain in domains_to_scan:
                ret1 = run_scan(domain)
                ret2 = run_nucleifuzzer(domain)

                if ret1 != 0 or ret2 != 0:
                    failed.append(domain)
                    st.error(f"❌ Failed: {domain}")
                else:
                    st.success(f"✅ Completed: {domain}")

            if failed:
                st.warning(f"⚠️ Scan failed for: {', '.join(failed)}")
            else:
                st.success("🎉 All scans completed successfully.")

elif menu == "📊 View Results":
    st.header("📊 Recon Results Viewer")

    domains = sorted([os.path.basename(d) for d in glob(f"{BASE_OUTPUT_DIR}/*") if os.path.isdir(d)])
    state_data = load_state()

    if not domains:
        st.warning("⚠️ No scanned domains found yet.")
    else:
        selected_domain = st.selectbox("Select domain to view results:", domains)
        show_progress(selected_domain, state_data)

        summary_file = os.path.join(BASE_OUTPUT_DIR, selected_domain, "recon_summary.json")

        if os.path.exists(summary_file):
            with open(summary_file) as f:
                data = json.load(f)

            st.subheader("📌 Recon Summary")
            st.json(data, expanded=False)

        st.subheader("📊 Stats")
        stats_files = ["all_subdomains.txt", "all_urls.txt", "gf_xss.txt", "gf_sqli.txt"]
        for fname in stats_files:
            full_path = os.path.join(BASE_OUTPUT_DIR, selected_domain, fname)
            lines = try_parse_txt_file(full_path)
            if lines:
                st.write(f"{fname}: **{len(lines)} entries**")

        st.subheader("⏳ Timeline")
        log_file = os.path.join(BASE_OUTPUT_DIR, selected_domain, "execution.log")
        if os.path.exists(log_file):
            with open(log_file) as f:
                lines = [line.strip() for line in f if line.strip()]
                for line in lines:
                    st.text(line)

        st.subheader("🖼 Screenshot Preview")
        for name in SCREENSHOT_FILE_NAMES:
            shot = os.path.join(BASE_OUTPUT_DIR, selected_domain, name)
            if os.path.exists(shot):
                st.markdown(f"[📸 Open Screenshot Viewer]({shot})")

elif menu == "📂 View All Files":
    st.header("📂 File Explorer & Viewer")
    domains = sorted([os.path.basename(d) for d in glob(f"{BASE_OUTPUT_DIR}/*") if os.path.isdir(d)])

    if not domains:
        st.warning("⚠️ No scan output available.")
    else:
        selected_domain = st.selectbox("Select a scanned domain:", domains)
        domain_dir = os.path.join(BASE_OUTPUT_DIR, selected_domain)
        files = sorted(glob(f"{domain_dir}/*"))

        if not files:
            st.warning("No files found for selected domain.")
        else:
            selected_file = st.selectbox("Select a file to view:", files)
            st.caption(f"📄 Showing: {os.path.basename(selected_file)}")

            if selected_file.endswith(".json"):
                with open(selected_file) as f:
                    try:
                        data = json.load(f)
                        st.json(data, expanded=False)
                        st.download_button("📥 Download JSON", json.dumps(data, indent=2), file_name=os.path.basename(selected_file))
                    except json.JSONDecodeError:
                        st.error("❌ Invalid JSON format.")
            elif selected_file.endswith(".txt"):
                with open(selected_file) as f:
                    content = f.read()
                    search = st.text_input("🔍 Search:")
                    if search:
                        matches = [line for line in content.splitlines() if search.lower() in line.lower()]
                        st.code("\n".join(matches), language="bash")
                    else:
                        st.code(content, language="bash")
                    st.download_button("📥 Download TXT", content, file_name=os.path.basename(selected_file))
            else:
                st.warning("⚠️ Unsupported file type.")
