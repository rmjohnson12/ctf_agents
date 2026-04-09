from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class DirsearchEntry:
    status: int
    size: str
    url: str

@dataclass(frozen=True)
class DirsearchResult:
    target_url: str
    entries: List[DirsearchEntry]
    raw: ToolResult

class DirsearchTool(BaseTool):
    """
    Standardized wrapper for dirsearch.
    Automates directory and file discovery.
    """

    @property
    def tool_name(self) -> str:
        return "dirsearch"

    def run(self, url: str, extensions: str = "php,html,js,txt", timeout_s: int = 300) -> DirsearchResult:
        """
        Run a directory discovery scan.
        """
        args = ["-u", url, "-e", extensions, "--format=plain"]
        
        res = self.execute(args, timeout_s=timeout_s)
        
        entries = []
        # Parse plain output: [12:34:56] 200 -   1KB - /index.html
        for line in res.stdout.splitlines():
            m = re.search(r"(\d{3})\s+-\s+([0-9KMGTB ]+)\s+-\s+(/.+)", line)
            if m:
                status = int(m.group(1))
                if 200 <= status < 400: # Only interesting findings
                    entries.append(
                        DirsearchEntry(
                            status=status,
                            size=m.group(2).strip(),
                            url=m.group(3).strip()
                        )
                    )
                
        return DirsearchResult(target_url=url, entries=entries, raw=res)
