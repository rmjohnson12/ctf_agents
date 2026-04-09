# CTF_Agents: Autonomous Security Operations

**CTF_Agents** is an advanced, iterative multi-agent system designed to autonomously solve Capture The Flag (CTF) challenges. Unlike traditional linear scanners, this system uses an **iterative feedback loop** to reason about artifacts, execute complex tools, and adapt its strategy in real time.

## 🔥 Demo: Natural Language Interface

You can now give instructions in plain English. The system automatically maps your request to the right tools and files.

```bash
# Example: Password Cracking
python3 ask.py "Decrypt hash 68a96446a5afb4ab69a2d15091771e39 using my_passwords.txt"

# Example: PDF Forensics
python3 ask.py "Analyze suspicious.pdf and find the password"
```

**[ROUTER]** target=crypto_agent action=run_agent  
→ *Isolated hash from prompt*  
→ *Detected wordlist: my_passwords.txt*  
→ *Executing Hashcat (mode 0)...*

✅ **Flag recovered:** `emilybffl`

---

## 🧠 TL;DR
An iterative, multi-agent CTF system that reasons → acts → observes → adapts → solves (iteratively).

---

## 🚀 Key Innovations

### 1. Natural Language Entry (`ask.py`)
No more manual JSON challenge files. Just type what you want to do. The system:
*   **Identifies Files**: Automatically detects filenames in your prompt that exist in the directory.
*   **Auto-Categorizes**: Maps tasks to Web, Crypto, or Forensics based on keywords and file extensions.
*   **Heuristic Fallback**: Works even without an OpenAI API key using robust rule-based logic.

### 2. Specialized Red Team Agents
*   **Web Agent**: Automated reconnaissance via **Playwright**, directory discovery via **dirsearch**, and SQL injection via **sqlmap**.
*   **Crypto Agent**: Deep integration with **Hashcat** and **John the Ripper**. Supports raw-md5, dictionary attacks, and wordlist auto-detection.
*   **Forensics Agent**: Sequential analysis using **Binwalk**, **ExifTool**, **Strings**, and **QPDF**.
*   **Coding Agent**: Generates and executes Python scripts to solve logic/math puzzles, with **Self-Correction** (auto-fixes crashing scripts).

### 3. NCL & HTB Optimized
*   **SKY-XXXX-####**: Native support for NCL Cyber Skyline flag patterns.
*   **HTB{...}**: Optimized for Hack The Box style flags and session-authenticated browser snapshots.
*   **Universal Detection**: Centralized logic catches flags across all tool outputs, logs, and artifacts.

### 4. Standardized Tool & Result Layer
*   **BaseTool**: All tools (nmap, binwalk, hashcat, etc.) use a unified interface with strict timeouts and safety boundaries.
*   **Result Manager**: findings are persisted in `results/{challenge_id}/` with dedicated folders for reports, artifacts, and flags.

---

## 🚦 Getting Started

### Prerequisites
*   Python 3.10+
*   Security Tools: `hashcat`, `john`, `binwalk`, `exiftool`, `strings`, `qpdf`, `nmap`.
*   *(Optional)* OpenAI API Key in `.env` for advanced reasoning.

### Installation
```bash
git clone https://github.com/YOUR_USERNAME/CTF_Agents.git
cd CTF_Agents
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Usage
```bash
# General usage
python3 ask.py "Your instruction here"

# Use specific wordlists for cracking
python3 ask.py "crack this hash <hash> using custom_list.txt"
```

---

## 🧪 Testing
```bash
pytest tests/unit/
```

---

## 🔒 Security & Ethics
This system is intended for **authorized CTF competitions**, **security research**, and **educational use**. 
**Do not use against live systems without explicit, written permission.**

---

## 🙏 Acknowledgments
*   Original architecture by **TonyZeroArch**.
*   Built for the global CTF and AI Security research community.
