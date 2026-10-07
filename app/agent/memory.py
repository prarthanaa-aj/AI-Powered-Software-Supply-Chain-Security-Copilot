"""Small JSON-backed long-term store for user preferences only."""
import json
from pathlib import Path
from app.config import ROOT


class LongTermMemory:
    def __init__(self, path: Path | None = None):
        self.path = path or ROOT / "data" / "processed" / "preferences.json"

    def read(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            return payload if isinstance(payload, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def update(self, user_id: str, preference: str) -> dict:
        if preference not in {"concise", "detailed"}:
            raise ValueError("Supported preferences: concise, detailed")
        data = self.read()
        data[user_id[:80]] = preference
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    def reset(self, user_id: str | None = None) -> None:
        if user_id is None:
            if self.path.exists():
                self.path.unlink()
            return
        data = self.read()
        data.pop(user_id, None)
        if data:
            self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        elif self.path.exists():
            self.path.unlink()
