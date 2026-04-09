"""
Forensics Specialist Agent

Specialized agent for forensics-based CTF challenges.
"""

import json
import os
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent, AgentType
from tools.forensics.binwalk import BinwalkTool
from tools.forensics.exiftool import ExiftoolTool
from tools.forensics.qpdf import QPDFTool
from tools.network.tshark import TsharkTool
from tools.network.scapy_tool import ScapyTool
from tools.common.strings import StringsTool
from core.utils.flag_utils import find_first_flag


class ForensicsAgent(BaseAgent):
    """
    Specialist agent for forensics challenges.
    """

    def __init__(
        self, 
        agent_id: str = "forensics_agent", 
        binwalk_tool: Optional[BinwalkTool] = None,
        exiftool_tool: Optional[ExiftoolTool] = None,
        strings_tool: Optional[StringsTool] = None,
        qpdf_tool: Optional[QPDFTool] = None,
        tshark_tool: Optional[TsharkTool] = None,
        scapy_tool: Optional[ScapyTool] = None
    ):
        super().__init__(agent_id, AgentType.SPECIALIST)
        self.binwalk_tool = binwalk_tool or BinwalkTool()
        self.exiftool_tool = exiftool_tool or ExiftoolTool()
        self.strings_tool = strings_tool or StringsTool()
        self.qpdf_tool = qpdf_tool or QPDFTool()
        self.tshark_tool = tshark_tool or TsharkTool()
        self.scapy_tool = scapy_tool or ScapyTool()
        self.capabilities = [
            "forensics",
            "file_analysis",
            "binwalk",
            "exiftool",
            "strings",
            "pdf_decryption",
            "pcap_analysis",
            "artifact_extraction",
            "steganography",
            "metadata",
        ]

    def analyze_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        description = challenge.get("description", "").lower()
        files = challenge.get("files", [])
        tags = " ".join(challenge.get("tags", [])).lower()
        
        indicators = ["artifact", "file", "disk", "memory", "pcap", "extract", "binwalk", "forensics"]
        is_forensics = any(k in description or k in tags for k in indicators) or bool(files)
        
        confidence = 0.9 if is_forensics or challenge.get("category") == "forensics" else 0.2

        return {
            "agent_id": self.agent_id,
            "can_handle": is_forensics or challenge.get("category") == "forensics",
            "confidence": confidence,
            "approach": "Perform file analysis and artifact extraction",
        }

    def solve_challenge(self, challenge: Dict[str, Any]) -> Dict[str, Any]:
        analysis = self.analyze_challenge(challenge)
        steps: List[str] = []
        flag = None

        files = challenge.get("files", [])
        if not files:
            steps.append("No files provided for forensics analysis.")
            return {
                "challenge_id": challenge.get("id"),
                "agent_id": self.agent_id,
                "status": "failed",
                "flag": None,
                "steps": steps,
            }

        steps.append(f"Analyzing {len(files)} files...")
        all_artifacts = {
            "binwalk": [],
            "exiftool": [],
            "strings": [],
            "pdf": [],
            "pcap": []
        }

        for file_path in files:
            # 0a. PDF Detection & Inspection
            if file_path.lower().endswith(".pdf"):
                steps.append(f"Detected PDF file: {file_path}")
                try:
                    pdf_res = self.qpdf_tool.run(file_path)
                    if pdf_res.is_encrypted:
                        steps.append(f"  [!] PDF is encrypted. Encryption check result in artifacts.")
                        all_artifacts["pdf"].append({
                            "file": file_path,
                            "encrypted": True,
                            "raw_info": pdf_res.raw.stdout or pdf_res.raw.stderr
                        })
                    else:
                        steps.append("  PDF is not encrypted. Proceeding with standard analysis.")
                except Exception as e:
                    steps.append(f"  QPDF error: {e}")

            # 0b. PCAP Detection & Analysis
            if file_path.lower().endswith(".pcap") or file_path.lower().endswith(".pcapng"):
                steps.append(f"Detected PCAP file: {file_path}")
                try:
                    # 1. Summary (IPs/Hosts)
                    pcap_res = self.tshark_tool.run(file_path)
                    steps.append(f"  Extracted {len(pcap_res.ips)} unique IPs and {len(pcap_res.hostnames)} hostnames.")
                    
                    # 2. Stream Reconstruction (Deep Analysis with Scapy)
                    steps.append("  Deep stream reconstruction (Scapy)...")
                    scapy_streams = self.scapy_tool.reconstruct_all_streams(file_path)
                    for i, stream in enumerate(scapy_streams):
                        # Combine c2s and s2c for full text search, but also analyze individually
                        stream_text_c2s = stream.data_c2s.decode('utf-8', errors='ignore')
                        stream_text_s2c = stream.data_s2c.decode('utf-8', errors='ignore')
                        
                        # Standard flag check
                        for text in [stream_text_c2s, stream_text_s2c]:
                            found_flag = find_first_flag(text)
                            if found_flag and not flag:
                                flag = found_flag
                                steps.append(f"  Flag found in stream {i}: {flag}")
                        
                        # Raw protocol analysis (custom structures)
                        if not flag:
                            # Try both directions
                            for raw_data in [stream.data_c2s, stream.data_s2c]:
                                raw_flag = self._analyze_raw_protocol(raw_data)
                                if raw_flag:
                                    flag = raw_flag
                                    steps.append(f"  Flag found via deep protocol analysis in stream {i}: {flag}")
                                    break

                        # NCL/SKY check
                        if not flag:
                            import re
                            for text in [stream_text_c2s, stream_text_s2c]:
                                m = re.search(r"(SKY|NCL)-[A-Z0-9-]+", text)
                                if m:
                                    flag = m.group(0)
                                    steps.append(f"  NCL/SKY flag found in stream {i}: {flag}")
                                    break

                    all_artifacts["pcap"].append({
                        "file": file_path,
                        "ips": pcap_res.ips[:20],
                        "hostnames": pcap_res.hostnames,
                        "streams_analyzed": len(scapy_streams)
                    })
                except Exception as e:
                    steps.append(f"  Tshark error: {e}")

            # 1. Binwalk
            steps.append(f"Running binwalk on {file_path}")
            try:
                res = self.binwalk_tool.run(file_path)
                if res.signatures:
                    steps.append(f"  Found {len(res.signatures)} binwalk signatures")
                    for s in res.signatures:
                        all_artifacts["binwalk"].append({"file": file_path, "description": s.description})
                        found_flag = find_first_flag(s.description)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in binwalk: {flag}")
            except Exception as e:
                steps.append(f"  Binwalk error: {e}")

            # 2. Exiftool
            steps.append(f"Running exiftool on {file_path}")
            try:
                res = self.exiftool_tool.run(file_path)
                if res.metadata:
                    all_artifacts["exiftool"].append({"file": file_path, "metadata": res.metadata})
                    # Scan metadata values for flags
                    metadata_str = json.dumps(res.metadata)
                    found_flag = find_first_flag(metadata_str)
                    if found_flag and not flag:
                        flag = found_flag
                        steps.append(f"  Flag found in metadata: {flag}")
            except Exception as e:
                steps.append(f"  Exiftool error: {e}")

            # 3. Strings
            steps.append(f"Running strings on {file_path}")
            try:
                res = self.strings_tool.run(file_path)
                if res.strings:
                    # Scan for flags in extracted strings
                    for s in res.strings:
                        found_flag = find_first_flag(s)
                        if found_flag and not flag:
                            flag = found_flag
                            steps.append(f"  Flag found in strings: {flag}")
                            break
            except Exception as e:
                steps.append(f"  Strings error: {e}")

        # Heuristic: Answer "What is the IP" questions if artifacts found
        if not flag and ("ip" in challenge.get("description", "").lower() or "server" in challenge.get("description", "").lower()):
            for pcap_art in all_artifacts.get("pcap", []):
                if pcap_art.get("ips"):
                    ips = pcap_art["ips"]
                    if ips:
                        answer = f"Possible server IPs found in PCAP: {', '.join(ips[:3])}"
                        steps.append(f"  Heuristic answer for IP question: {answer}")
                        flag = answer

        return {
            "challenge_id": challenge.get("id"),
            "agent_id": self.agent_id,
            "status": "solved" if flag else "attempted",
            "flag": flag,
            "steps": steps,
            "artifacts": all_artifacts
        }

    def _analyze_raw_protocol(self, data: str) -> Optional[str]:
        """
        Heuristic analysis of raw protocol data (custom binary structures).
        Inspired by protocol reversing scripts (like analyze_pcap2.py).
        """
        # Convert to bytes for binary analysis if possible
        try:
            raw_bytes = data.encode('latin-1') if isinstance(data, str) else data
        except:
            return None

        # NCL/SKY Pattern in common structured data (Base64 chunks)
        # 1. Try to find concatenated base64 chunks
        import base64
        import re

        # Look for magic numbers or structure (e.g., 4 bytes length + data)
        if len(raw_bytes) > 8:
            # Heuristic: Is the first 4 bytes a small integer (count)?
            try:
                n = int.from_bytes(raw_bytes[:4], byteorder='big')
                if 0 < n < 500: # Reasonable number of chunks
                    pos = 4
                    all_chunks = []
                    for _ in range(n):
                        if pos + 6 > len(raw_bytes): break
                        # Header: 2 bytes check + 4 bytes length
                        chunk_len = int.from_bytes(raw_bytes[pos+2:pos+6], byteorder='big')
                        if chunk_len > 10000: break # Too large for a chunk
                        chunk_data = raw_bytes[pos+6 : pos+6+chunk_len]
                        all_chunks.append(chunk_data)
                        pos += 6 + chunk_len
                    
                    if all_chunks:
                        combined = b"".join(all_chunks)
                        # Clean and decode
                        clean = combined.replace(b' ', b'').replace(b'\n', b'').replace(b'\r', b'')
                        while len(clean) % 4 != 0: clean += b'='
                        try:
                            decoded = base64.b64decode(clean)
                            found = find_first_flag(decoded.decode('utf-8', errors='ignore'))
                            if found: return found
                        except: pass
            except: pass

        # 2. General greedy base64 extraction from raw stream
        # (Useful if the protocol structure isn't exactly as above)
        b64_pattern = b'[A-Za-z0-9+/]{20,}={0,2}'
        for m in re.finditer(b64_pattern, raw_bytes):
            try:
                decoded = base64.b64decode(m.group(0))
                found = find_first_flag(decoded.decode('utf-8', errors='ignore'))
                if found: return found
            except: continue

        return None

    def get_capabilities(self) -> List[str]:
        return self.capabilities
