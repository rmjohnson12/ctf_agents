from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class HashcatResult:
    hash_str: str
    cracked_password: Optional[str]
    raw: ToolResult

class HashcatTool(BaseTool):
    """
    Standardized wrapper for hashcat.
    Automates password cracking for many hash types.
    """

    @property
    def tool_name(self) -> str:
        return "hashcat"

    def run(self, hash_str: str, wordlist: Optional[str] = None, mode: int = 0, timeout_s: int = 300) -> HashcatResult:
        """
        Attempt to crack a hash using hashcat.
        Mode 0 is raw MD5.
        """
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(hash_str)
            hash_path = f.name

        try:
            # --potfile-disable ensures we actually try to crack it even if already cracked before
            # so we can see the output in the log
            args = ["-m", str(mode), "-a", "0", hash_path]
            
            if wordlist and Path(wordlist).exists():
                args.append(wordlist)
            else:
                # If no wordlist, maybe just return failure for now as brute force is slow
                return HashcatResult(hash_str, None, ToolResult([], "", "No wordlist provided", 1, False, 0))

            # Add --force for some environments, and --quiet to keep logs cleaner
            args.extend(["--force", "--potfile-disable"])

            res = self.execute(args, timeout_s=timeout_s)
            
            # Hashcat outputs the cracked hash in the format hash:password at the end
            cracked_password = self._parse_hashcat_output(res.stdout, hash_str)
            
            return HashcatResult(
                hash_str=hash_str,
                cracked_password=cracked_password,
                raw=res
            )
        finally:
            try:
                Path(hash_path).unlink()
            except OSError:
                pass

    @staticmethod
    def _parse_hashcat_output(stdout: str, hash_str: str) -> Optional[str]:
        """
        Hashcat output often contains the result line at the end:
        <hash>:<password>
        """
        for line in stdout.splitlines():
            if line.startswith(hash_str) and ":" in line:
                return line.split(":", 1)[1].strip()
        return None
