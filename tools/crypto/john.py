from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class JohnResult:
    hash_str: str
    cracked_password: Optional[str]
    raw: ToolResult

class JohnTool(BaseTool):
    """
    Standardized wrapper for John the Ripper (john).
    Automates password cracking and hash analysis.
    """

    @property
    def tool_name(self) -> str:
        return "john"

    def run(self, hash_str: str, wordlist: Optional[str] = None, timeout_s: int = 300) -> JohnResult:
        """
        Attempt to crack a hash string using a dictionary attack or incremental mode.
        """
        # Create a temporary file for the hash
        with tempfile.NamedTemporaryFile(mode='w', suffix='.hash', delete=False) as f:
            f.write(hash_str)
            hash_path = f.name

        try:
            args = [hash_path]
            if wordlist and Path(wordlist).exists():
                args.append(f"--wordlist={wordlist}")
            else:
                args.append("--incremental")

            # Heuristic: If 32 chars, it's likely raw MD5 which John needs help with
            if len(hash_str) == 32:
                args.append("--format=raw-md5")

            # First run: attempt to crack
            res = self.execute(args, timeout_s=timeout_s)
            
            # Second run: show cracked passwords
            # We must pass the same --format to --show if we used it during cracking
            show_args = ["--show", hash_path]
            if "--format=raw-md5" in args:
                show_args.append("--format=raw-md5")
                
            show_res = self.execute(show_args)
            
            cracked_password = self._parse_show_output(show_res.stdout)
            
            return JohnResult(
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
    def _parse_show_output(stdout: str) -> Optional[str]:
        """
        John --show output format:
        0 password hashes cracked, 0 left
        or:
        hash:password
        1 password hash cracked, 0 left
        """
        lines = stdout.splitlines()
        for line in lines:
            if ":" in line and not line.startswith("0 password hashes") and not "password hash cracked" in line:
                # Format is usually filename:password or hash:password
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[1].strip()
        return None
