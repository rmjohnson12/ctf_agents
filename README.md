# CTF_Agents: Autonomous Security Operations

**CTF_Agents** is an advanced, iterative multi-agent system designed to autonomously solve Capture The Flag (CTF) challenges. Unlike traditional linear scanners, this system uses an **iterative feedback loop** to reason about artifacts, execute complex tools, and adapt its strategy in real time.

## 🔥 Demo: Natural Language Interface

You can now give instructions in plain English. The system automatically maps your request to the right tools and files.

```bash
# Example: Reverse Engineering (Analyze logic + Verify)
python3 ask.py "Find a password for ~/Downloads/PYTHON1.py"

# Example: Password Cracking
python3 ask.py "Decrypt hash 68a96446a5afb4ab69a2d15091771e39 using my_passwords.txt"
```

**[ROUTER]** target=reverse_agent action=run_agent  
→ *Extracted constraints: Sum=1000, Length=10, Index 1='S'*  
→ *Derived candidate: mSeeeeeeee*  
→ *Executing PYTHON1.py mSeeeeeeee...*

✅ **Verification SUCCESS:** Program returned 'correct'

---

## 🧠 TL;DR
An iterative, multi-agent CTF system that reasons → acts → observes → adapts → solves (iteratively).

---

## 🚀 Key Innovations

### 1. Natural Language Entry (`ask.py`)
Just type what you want to do. The system:
*   **Identifies Files**: Automatically detects filenames and paths (including `~/`) in your prompt.
*   **Auto-Categorizes**: Maps tasks to Web, Crypto, Forensics, or Reverse Engineering based on content.
*   **Heuristic Fallback**: Works with high reliability even without an OpenAI API key.

### 2. Specialized Red Team Agents
*   **Reverse Engineering Agent**: Static analysis of source code (`.py`) and binaries. Features a **Constraint Solver** that extracts mathematical logic and **Verifies** solutions via live execution before reporting.
*   **Web Agent**: Automated reconnaissance via **Playwright**, directory discovery via **dirsearch**, and SQL injection via **sqlmap**.
*   **Crypto Agent**: Deep integration with **Hashcat** and **John the Ripper**. Supports raw-md5, dictionary attacks, and wordlist auto-detection.
*   **Forensics Agent**: Sequential analysis using **Binwalk**, **ExifTool**, **Strings**, and **QPDF**.
*   **Coding Agent**: Generates and executes Python scripts to solve logic/math puzzles, with **Self-Correction** (auto-fixes crashing scripts).

### 3. NCL & HTB Optimized
*   **SKY-XXXX-####**: Native support for NCL Cyber Skyline flag patterns.
*   **HTB{...}**: Optimized for Hack The Box style flags and session-authenticated browser snapshots.
*   **Universal Detection**: Centralized logic catches flags across all tool outputs, logs, and artifacts.

### 4. Standardized Tool & Result Layer
*   **BaseTool**: All tools use a unified interface with strict timeouts and safety boundaries.
*   **Result Manager**: Findings are persisted in `results/{challenge_id}/` with dedicated folders for reports, artifacts, and flags.

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
