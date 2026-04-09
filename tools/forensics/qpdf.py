from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from tools.base_tool import BaseTool
from tools.common.result import ToolResult

@dataclass(frozen=True)
class QPDFResult:
    file_path: str
    is_encrypted: bool
    decrypted_path: Optional[str]
    password: Optional[str]
    raw: ToolResult

class QPDFTool(BaseTool):
    """
    Wrapper for qpdf. Handles PDF inspection and decryption.
    """

    @property
    def tool_name(self) -> str:
        return "qpdf"

    def check_encryption(self, file_path: str) -> bool:
        """Check if a PDF is encrypted."""
        res = self.execute(["--show-encryption", file_path])
        return "is encrypted" in res.stdout or res.exit_code != 0

    def run(self, file_path: str, password: Optional[str] = None, output_path: Optional[str] = None) -> QPDFResult:
        """
        Attempt to decrypt or inspect a PDF.
        """
        if not output_path:
            output_path = file_path.replace(".pdf", "_decrypted.pdf")

        args = [file_path]
        if password:
            args = [f"--password={password}", "--decrypt", file_path, output_path]
        else:
            args = ["--show-encryption", file_path]

        res = self.execute(args)
        
        is_encrypted = "is encrypted" in res.stdout or "password" in res.stderr.lower()
        
        # If we provided a password and it worked
        success = res.exit_code == 0 and password is not None
        
        return QPDFResult(
            file_path=file_path,
            is_encrypted=is_encrypted,
            decrypted_path=output_path if success else None,
            password=password if success else None,
            raw=res
        )
