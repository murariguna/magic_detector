import os
import json
import hashlib
from datetime import datetime

SIGNATURE_DB = "magic_signatures.json"
LOG_FILE = "logs/forensic_log.json"
READ_BYTES = 32

#reading the first 32 bytes of the file
def read_magic_bytes(file_path, num_bytes=READ_BYTES):
    with open(file_path, "rb") as f:
        data = f.read(num_bytes)
        return data.hex().upper()

#load the magic number from the db to the memory for comparition
def load_signatures():
    with open(SIGNATURE_DB, "r") as f:
        data = json.load(f)

    # Handle wrapped JSON like { "signatures": [...] }
    if isinstance(data, dict) and "signatures" in data:
        return data["signatures"]

    # Handle correct list format
    if isinstance(data, list):
        return data

    raise ValueError("Invalid magic_signatures.json format")
def match_signature(file_hex, signatures):
    file_hex = file_hex.upper()

    for sig in signatures:
        if not isinstance(sig, dict):
            continue

        magic = sig.get("magic_hex")
        offset = sig.get("offset", 0)

        if not magic:
            continue

        # Normalize: remove spaces from magic hex
        magic = magic.replace(" ", "").upper()

        start = offset * 2
        end = start + len(magic)

        if file_hex[start:end] == magic:
            return sig

    return None




# ---------------- PHASE 5 ----------------
def analyze_extension(file_path, detected_sig):
    ext = os.path.splitext(file_path)[1].lower().lstrip(".")

    if not detected_sig:
        return "UNKNOWN"

    valid_exts = detected_sig.get("extensions", [])

    if ext in valid_exts:
        return "LOW"

    if detected_sig.get("file_class", "").lower().find("executable") != -1:
        return "CRITICAL"

    return "HIGH"



# ---------------- PHASE 6 ----------------
def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()


def log_forensic_event(log_entry):
    os.makedirs("logs", exist_ok=True)

    logs = []

    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
                if not isinstance(logs, list):
                    logs = []
        except json.JSONDecodeError:
            logs = []  # Recover from empty/corrupt log

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)


# ---------------- PHASE 7 ----------------
def display_report(report):
    print("\n========== FILE ANALYSIS REPORT ==========")
    for key, value in report.items():
        print(f"{key:<18}: {value}")
    print("=========================================\n")
            

def detect_file(file_path):
    if not os.path.exists(file_path):
        print("[ERROR] File not found.")
        return

    if os.path.isdir(file_path):
        print("[ERROR] Path is a directory. Please provide a file.")
        return

    file_hex = read_magic_bytes(file_path)
    signatures = load_signatures()
    detected_sig = match_signature(file_hex, signatures)

    sha256 = calculate_sha256(file_path)

    risk = analyze_extension(file_path, detected_sig)

    if detected_sig:
        detected_type = detected_sig.get("description", "UNKNOWN")
        exts = detected_sig.get("extensions", [])
        expected_exts = ", ".join(exts) if isinstance(exts, list) else "N/A"
        magic = detected_sig.get("magic_hex", "N/A")
    else:
        detected_type = "UNKNOWN"
        expected_exts = "N/A"
        magic = "N/A"

    report = {
        "File Name": os.path.basename(file_path),
        "File Extension": os.path.splitext(file_path)[1],
        "Detected Description": detected_type,
        "Expected Extensions": expected_exts,
        "Magic Number": magic,
        "SHA-256": sha256,
        "Risk Level": risk,
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    display_report(report)

    log_forensic_event(report)



# ---------------- MAIN (CLI) ----------------
if __name__ == "__main__":
    print("=== Magic Number File Type Identifier ===")
    path = input("Enter file path to scan: ").strip()
    detect_file(path)
