import shutil
from typing import Dict, List

def get_available_tools() -> List[str]:
    """
    Checks the system for common security and CTF tools.
    """
    tools_to_check = [
        # Web
        "sqlmap", "dirb", "dirsearch", "nikto", "gobuster", "ffuf",
        # Crypto/Hash
        "john", "hashcat", "openssl",
        # Forensics
        "binwalk", "exiftool", "qpdf", "foremost", "volatility",
        # Reverse/Pwn
        "gdb", "radare2", "r2", "ghidra", "objdump", "strings",
        # Network
        "nmap", "tshark", "tcpdump", "wireshark", "aircrack-ng", "snort",
        # General/Exploit
        "msfconsole", "searchsploit", "curl", "wget", "python3"
    ]
    
    available = []
    for tool in tools_to_check:
        if shutil.which(tool):
            available.append(tool)
            
    return available

def get_system_context() -> str:
    """Returns a string describing the available tools."""
    tools = get_available_tools()
    if not tools:
        return "No standard security tools detected in PATH."
    return f"Available system tools: {', '.join(tools)}"
