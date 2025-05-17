import json
import re
from pathlib import Path
from tqdm import tqdm
from ollama import chat

# === CONFIGURATION ===
DATASET_PATH = Path(r"D:\NEWAIPROJECT\CYBERAI_v2\CYBERAI_v2\dataset_factory\generated_dataset_shuffled\merged_train.jsonl")
OUTPUT_PATH = DATASET_PATH.parent / "cleaned_llama3_train.jsonl"
MODEL_NAME = "llama3"  # Or "llama3:8b-instruct" if that's your tag

# === SYSTEM PROMPT ===
SYSTEM_PROMPT = """You are an AI dataset cleaner for code-related instructions. 
For each code snippet:
- Rewrite the instruction to clearly explain what the code does
- Update the input field if it’s incorrect or not useful
- If the code is broken or irrelevant, set "keep": false

Respond ONLY with JSON like:
{
  "instruction": "...",
  "input": "...",
  "keep": true
}
"""

# === Prompt Builder ===
def build_prompt(instruction, input_field, output):
    trimmed_output = "\n".join(output.strip().splitlines()[:300])  # truncate long code
    return f"""Instruction: {instruction}
Input: {input_field}
Code:
{trimmed_output}

Return a JSON response with cleaned instruction and input.
"""

# === Safe JSON Extractor ===
def extract_json(text):
    try:
        match = re.search(r"\{.*?\}", text, re.DOTALL)
        if not match:
            return None
        candidate = match.group()
        candidate = candidate.replace("“", '"').replace("”", '"')  # smart quotes
        candidate = candidate.replace("'", '"')  # single quotes to double quotes
        candidate = re.sub(r'\\n', '', candidate)  # remove escaped newlines
        return json.loads(candidate)
    except Exception as e:
        print("❌ JSON extraction failed:", e)
        return None

# === MAIN PROCESS ===
def clean_dataset():
    buffer = []
    saved_count = 0

    with open(DATASET_PATH, "r", encoding="utf-8") as infile, open(OUTPUT_PATH, "w", encoding="utf-8") as outfile:
        for i, line in enumerate(tqdm(infile, desc="🧹 Cleaning entries")):
            try:
                data = json.loads(line)
                if not all(k in data for k in ("instruction", "input", "output")):
                    print(f"⚠️ Missing keys in entry {i}")
                    continue

                user_prompt = build_prompt(data["instruction"], data["input"], data["output"])

                response = chat(
                    model=MODEL_NAME,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": user_prompt}
                    ]
                )

                reply = extract_json(response["message"]["content"])
                if not reply or not reply.get("keep", False):
                    print(f"⏩ Skipped entry {i} (keep=false or invalid)")
                    continue

                # Validate fields
                instruction = reply.get("instruction")
                input_field = reply.get("input")
                if not instruction or not isinstance(instruction, str):
                    print(f"⚠️ Skipped entry {i} due to missing/invalid instruction")
                    continue

                cleaned_entry = {
                    "instruction": instruction.strip(),
                    "input": input_field.strip() if isinstance(input_field, str) else "",
                    "output": data["output"].strip()
                }

                if cleaned_entry["instruction"] and cleaned_entry["output"]:
                    buffer.append(cleaned_entry)
                    saved_count += 1

                # Write every 5 entries
                if len(buffer) >= 5:
                    for entry in buffer:
                        json.dump(entry, outfile)
                        outfile.write("\n")
                    buffer = []

            except Exception as e:
                print(f"⚠️ Skipped entry {i} due to error:", e)
                continue

        # Write any remaining entries
        for entry in buffer:
            json.dump(entry, outfile)
            outfile.write("\n")

    print(f"\n✅ Cleaning complete. Saved {saved_count} entries to: {OUTPUT_PATH}")

# === ENTRY POINT ===
if __name__ == "__main__":
    clean_dataset()
