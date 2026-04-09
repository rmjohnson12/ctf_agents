from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Set

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class TsharkResult:
    file_path: str
    ips: List[str]
    hostnames: List[str]
    raw: ToolResult

class TsharkTool(BaseTool):
    """
    Standard tool for analyzing PCAP files using tshark.
    """

    @property
    def tool_name(self) -> str:
        return "tshark"

    def reconstruct_streams(self, file_path: str, protocol: str = "tcp", timeout_s: int = 60) -> List[str]:
        """
        Reconstruct and extract data from streams (e.g., TCP/UDP).
        Uses tshark -z follow features.
        """
        # 1. Identify active streams
        id_args = ["-r", file_path, "-T", "fields", "-e", f"{protocol}.stream"]
        id_res = self.execute(id_args, timeout_s=timeout_s)
        
        streams = set()
        if id_res.exit_code == 0:
            for line in id_res.stdout.splitlines():
                if line.strip(): streams.add(line.strip())
        
        reconstructed = []
        # 2. Follow each stream (limit to top 5 for performance)
        for stream_id in sorted(list(streams))[:5]:
            follow_args = ["-r", file_path, "-z", f"follow,{protocol},ascii,{stream_id}"]
            res = self.execute(follow_args, timeout_s=timeout_s)
            if res.exit_code == 0:
                # Extract the actual data from the tshark follow output
                # (tshark wraps the data in some headers/footers)
                reconstructed.append(res.stdout)
                
        return reconstructed

    def run(self, file_path: str, timeout_s: int = 60) -> TsharkResult:
        """
        Extract a summary of IPs and Hostnames from a PCAP.
        """
        # 1. Get unique IPs (Source and Destination)
        # Using -T fields for structured output
        ip_args = ["-r", file_path, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]
        ip_res = self.execute(ip_args, timeout_s=timeout_s)
        
        ips: Set[str] = set()
        if ip_res.exit_code == 0:
            for line in ip_res.stdout.splitlines():
                parts = line.split('\t')
                for p in parts:
                    if p: ips.add(p)

        # 2. Get HTTP hostnames
        host_args = ["-r", file_path, "-Y", "http.host", "-T", "fields", "-e", "http.host"]
        host_res = self.execute(host_args, timeout_s=timeout_s)
        
        hosts: Set[str] = set()
        if host_res.exit_code == 0:
            for line in host_res.stdout.splitlines():
                if line.strip(): hosts.add(line.strip())

        return TsharkResult(
            file_path=file_path,
            ips=sorted(list(ips)),
            hostnames=sorted(list(hosts)),
            raw=ip_res # Include the main IP scan as raw
        )
