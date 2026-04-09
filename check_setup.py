import os
import shutil
import sys
from pathlib import Path
from dotenv import load_dotenv

def check():
    print("=== CTF_Agents: Pre-Flight Check ===")
    load_dotenv()
    
    # 1. Check API Key
    key = os.getenv("OPENAI_API_KEY")
    if not key or key == "your_openai_api_key_here":
        print("[-] OpenAI API Key: MISSING (Running in Heuristic Mode)")
    else:
        print("[+] OpenAI API Key: CONFIGURED (Full Autonomy Enabled)")

    # 2. Check Security Tools
    tools = {
        "Web": ["sqlmap", "dirsearch"],
        "Crypto": ["hashcat", "john"],
        "Forensics": ["binwalk", "exiftool", "tshark", "qpdf"],
        "General": ["python3", "curl"]
    }
    
    for category, tool_list in tools.items():
        found = []
        missing = []
        for t in tool_list:
            if shutil.which(t):
                found.append(t)
            else:
                missing.append(t)
        
        status = "[+]" if not missing else "[!]"
        print(f"{status} {category} Tools: {', '.join(found)} " + (f"(MISSING: {', '.join(missing)})" if missing else ""))

    # 3. Check Workspace
    rockyou = Path.home() / "Downloads" / "rockyou.txt"
    if rockyou.exists():
        print(f"[+] Wordlist: Found at {rockyou}")
    else:
        print(f"[-] Wordlist: rockyou.txt not found in ~/Downloads (Cracking will be limited)")

    print("\n[!] Setup complete. If tools are missing, install them via Homebrew:")
    print("    brew install hashcat john-ripper tshark qpdf binwalk exiftool dirsearch sqlmap")

if __name__ == "__main__":
    check()
