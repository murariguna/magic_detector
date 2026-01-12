<div align="center">

# 🔐 Magic Number File Type Identifier  
### *Binary-Level File Validation for Security & Digital Forensics*

</div>

---

## 🧭 Overview

Most operating systems and applications **trust file extensions** to determine file type.  
This assumption makes systems vulnerable to **file spoofing, disguised executables, and misleading uploads**.

This project implements a **binary-level file type identification tool** that determines the **true nature of a file** by analyzing its **magic numbers (file signatures)** instead of relying on extensions.

> 🛡️ **Trust the bytes, not the name.**

---

## 🎯 Project Objectives

- Validate file identity at the **binary level**
- Detect **extension spoofing**
- Identify **container-based ambiguity**
- Support **security analysis and forensic validation**
- Avoid false trust in user-controlled metadata

---

## ⚙️ How It Works

##File Input
-↓
-Binary Header Reader
-↓
-Magic Number Extraction
-↓
-Signature Database Matching
-↓
-Extension Comparison
-↓
-Risk Classification
-↓
-Forensic Report Generation
---

## 🔍 Key Features

✔ Reads files in **binary mode**  
✔ Extracts and analyzes **magic numbers**  
✔ Matches against a curated **signature database**  
✔ Detects **extension vs content mismatches**  
✔ Identifies **ZIP-based document containers**  
✔ Assigns **security risk levels**  
✔ Generates **forensic-ready reports**:
- SHA-256 hash
- Timestamp
- Detection metadata

---

## 🚨 Risk Classification Logic

| Condition | Risk Level |
|--------|------------|
| Extension matches signature | LOW |
| Known safe format | LOW |
| Container format detected (ZIP) | MEDIUM |
| Container + ambiguous structure | **HIGH** |
| Executable disguised as document | **CRITICAL** |

> ⚠️ Risk is assigned **conservatively** to avoid false trust.

---

## 📌 Important Note on ZIP-Based Formats

Modern document formats such as:

- `.docx`
- `.pptx`
- `.xlsx`
- OpenDocument formats

are **ZIP-based containers** and share the same magic number:

50 4B 03 04


At the current phase, the tool **identifies only the container**, not the internal document type.  
Without container-aware inspection, such files are **intentionally classified as HIGH risk**.

> This behavior is **by design** and aligned with security best practices.

---

## 🧪 Example Output

========== FILE ANALYSIS REPORT ==========
File Name : invoice.pdf
File Extension : .pdf
Detected Type : Windows Executable (EXE)
Magic Number : 4D 5A
SHA-256 : a9c1e5...
Risk Level : CRITICAL
Timestamp : 2026-01-12 15:12:23

---

## 🧠 Scope Clarification

### ✅ This Project IS
- Binary-level file validation
- Signature-based detection
- Security & forensics focused
- Conservative by design

### ❌ This Project Is NOT
- Antivirus software
- Malware behavioral analysis
- Steganography detection
- Content semantics inspection

> Detecting hidden data or malware requires **deeper content analysis**, which is intentionally out of scope for this phase.

---

## 🚀 Planned Enhancements

- ZIP container inspection (DOCX / PPTX / XLSX)
- Recursive archive analysis
- Executable detection inside containers
- Improved risk scoring logic
- Optional SIEM integration

---

## 🛠️ Technologies Used

- **Python**
- Binary file I/O
- Cryptographic hashing (SHA-256)
- Signature-based matching logic

---

## 📂 Use Cases

- Secure file upload validation
- Email gateway filtering
- Malware triage
- Digital forensic analysis
- Academic & security research

---

## 📜 License

This project is intended for **educational and research purposes**.

---

<div align="center">

### 🧠 *“If you trust the extension, you trust the attacker.”*

</div>
