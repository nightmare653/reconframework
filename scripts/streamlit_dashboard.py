import streamlit as st
import os
import json
import glob

st.set_page_config(page_title="AI Recon Dashboard", layout="wide")
st.title("🔍 AI-Powered Recon Dashboard")

# --- Sidebar config ---
st.sidebar.header("Configuration")
output_base = "output"
domains = sorted([d for d in os.listdir(output_base) if os.path.isdir(os.path.join(output_base, d))])

selected_domain = st.sidebar.selectbox("Select Domain", domains)
selected_folder = os.path.join(output_base, selected_domain)

# --- Load JSON files ---
def load_json_files(path_pattern):
    files = sorted(glob.glob(path_pattern))
    data = []
    for f in files:
        try:
            with open(f) as j:
                parsed = json.load(j)
                data.append((os.path.basename(f), parsed))
        except:
            continue
    return data

# --- Display Nuclei AI Results ---
st.subheader("🧠 Nuclei AI Scan Results")
ai_jsons = load_json_files(f"{selected_folder}/nuclei_ai_*.json")

if not ai_jsons:
    st.warning("No AI scan results found.")
else:
    for fname, result in ai_jsons:
        with st.expander(f"📁 {fname}"):
            if isinstance(result, list):
                for item in result:
                    st.json(item)
            elif isinstance(result, dict):
                st.json(result)

# --- Recon Summary ---
st.subheader("📊 Recon Summary")
sum_path = os.path.join(selected_folder, "recon_summary.json")
if os.path.exists(sum_path):
    with open(sum_path) as f:
        summary = json.load(f)
        st.json(summary)
else:
    st.warning("recon_summary.json not found")

# --- Secrets Found ---
st.subheader("🔐 Secret Detection Results")
secrets_path = os.path.join(selected_folder, "all_secrets.txt")
if os.path.exists(secrets_path):
    with open(secrets_path) as f:
        content = f.read()
        st.code(content, language='text')
else:
    st.info("No secrets file found.")

# --- Raw Output Viewer ---
st.subheader("🗂️ View Other Output Files")
files = glob.glob(f"{selected_folder}/*.txt") + glob.glob(f"{selected_folder}/*.log")
selected_file = st.selectbox("Select Output File", [os.path.basename(f) for f in files])
if selected_file:
    with open(os.path.join(selected_folder, selected_file)) as f:
        st.code(f.read(), language='text')
