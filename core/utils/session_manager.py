import json
from pathlib import Path
from typing import List, Dict, Any, Optional

class SessionManager:
    """
    Manages session cookies for authenticated requests (e.g., HTB).
    Supports loading cookies from JSON files (e.g., exported from browser).
    """
    def __init__(self, session_dir: str = "config/sessions"):
        self.session_dir = Path(session_dir)
        self.session_dir.mkdir(parents=True, exist_ok=True)

    def load_cookies(self, session_name: str) -> List[Dict[str, Any]]:
        """
        Load cookies from a JSON file in the session directory.
        """
        path = self.session_dir / f"{session_name}.json"
        if not path.exists():
            return []
        
        try:
            with open(path, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return []

    def save_cookies(self, session_name: str, cookies: List[Dict[str, Any]]):
        """
        Save cookies to a JSON file.
        """
        path = self.session_dir / f"{session_name}.json"
        with open(path, "w") as f:
            json.dump(cookies, f, indent=2)

    def get_default_htb_session(self) -> List[Dict[str, Any]]:
        """
        Convenience method to get the 'htb' session cookies.
        """
        return self.load_cookies("htb")
