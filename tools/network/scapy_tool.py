from __future__ import annotations
import os
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
import scapy.all as scapy
from scapy.layers.inet import TCP, UDP, IP
from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class ScapyStream:
    protocol: str
    client: str
    server: str
    sport: int
    dport: int
    data_c2s: bytes
    data_s2c: bytes

class ScapyTool(BaseTool):
    """
    Advanced PCAP analysis using Scapy for deep protocol inspection.
    """

    @property
    def tool_name(self) -> str:
        return "scapy"

    def reconstruct_all_streams(self, file_path: str) -> List[ScapyStream]:
        """
        Reconstruct all TCP/UDP streams from a PCAP file.
        Returns a list of ScapyStream objects containing the raw data.
        """
        if not os.path.exists(file_path):
            return []

        try:
            packets = scapy.rdpcap(file_path)
        except Exception:
            return []

        streams: Dict[tuple, Dict[str, Any]] = {}
        
        for pkt in packets:
            if not pkt.haslayer(IP) or not pkt.haslayer(scapy.Raw):
                continue

            proto = "tcp" if pkt.haslayer(TCP) else "udp" if pkt.haslayer(UDP) else None
            if not proto:
                continue

            layer = pkt[TCP] if proto == "tcp" else pkt[UDP]
            
            # Create a unique key for the stream (fwd and rev)
            tuple_fwd = (proto, pkt[IP].src, layer.sport, pkt[IP].dst, layer.dport)
            tuple_rev = (proto, pkt[IP].dst, layer.dport, pkt[IP].src, layer.sport)
            
            if tuple_fwd not in streams and tuple_rev not in streams:
                streams[tuple_fwd] = {
                    "proto": proto,
                    "c2s": b"", 
                    "s2c": b"", 
                    "client": pkt[IP].src, 
                    "server": pkt[IP].dst, 
                    "sport": layer.sport, 
                    "dport": layer.dport
                }
            
            if tuple_fwd in streams:
                streams[tuple_fwd]["c2s"] += pkt[scapy.Raw].load
            else:
                streams[tuple_rev]["s2c"] += pkt[scapy.Raw].load

        results = []
        for data in streams.values():
            results.append(ScapyStream(
                protocol=data["proto"],
                client=data["client"],
                server=data["server"],
                sport=data["sport"],
                dport=data["dport"],
                data_c2s=data["c2s"],
                data_s2c=data["s2c"]
            ))
        
        return results

    def run(self, file_path: str) -> List[ScapyStream]:
        return self.reconstruct_all_streams(file_path)
