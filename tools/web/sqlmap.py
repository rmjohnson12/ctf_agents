from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class SqlmapResult:
    target_url: str
    vulnerable: bool
    db_type: Optional[str]
    payloads: List[str]
    raw: ToolResult

class SqlmapTool(BaseTool):
    """
    Standardized wrapper for sqlmap.
    Focuses on non-interactive automated detection.
    """

    @property
    def tool_name(self) -> str:
        return "sqlmap"

    def run(self, url: str, batch: bool = True, timeout_s: int = 300) -> SqlmapResult:
        """
        Run a basic SQL injection scan against a URL.
        """
        args = ["-u", url]
        if batch:
            args.append("--batch")
        
        # Add some common safe flags for automation
        args.extend(["--random-agent", "--level=1", "--risk=1"])
        
        res = self.execute(args, timeout_s=timeout_s)
        
        # Heuristic parsing of sqlmap output
        vulnerable = "is vulnerable" in res.stdout or "back-end DBMS" in res.stdout
        
        db_type = None
        db_match = re.search(r"back-end DBMS: ([A-Za-z0-9 ]+)", res.stdout)
        if db_match:
            db_type = db_match.group(1).strip()
            
        payloads = re.findall(r"Payload: ([^\n]+)", res.stdout)
        # Clean up payloads if they were captured too greedily (heuristic)
        payloads = [p.split('    ')[0].strip() for p in payloads]
        
        return SqlmapResult(
            target_url=url,
            vulnerable=vulnerable,
            db_type=db_type,
            payloads=payloads,
            raw=res
        )
