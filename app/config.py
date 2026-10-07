"""Project configuration and safe local secret loading."""
from pathlib import Path
import os
import yaml
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parents[1]
SRC_ENV = ROOT / "src" / ".env"
ROOT_ENV = ROOT / ".env"
load_dotenv(SRC_ENV if SRC_ENV.exists() else ROOT_ENV, override=False)
CONFIG_PATH = ROOT / "config.yaml"
try:
    _CONFIG = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8-sig")) or {}
except (OSError, yaml.YAMLError):
    _CONFIG = {}


def setting(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


VOC_API_KEY = setting("VOC_API_KEY")
VOC_BASE_URL = setting("VOC_BASE_URL", "https://openai.vocareum.com/v1")
VOC_MODEL = setting("VOC_MODEL", _CONFIG.get("llm", {}).get("model", "gpt-4o-mini"))
APP_ENV = setting("APP_ENV", "development")
MAX_AGENT_STEPS = int(setting("MAX_AGENT_STEPS", str(_CONFIG.get("agent", {}).get("max_steps", 8))))
RAG_TOP_K = int(setting("RAG_TOP_K", str(_CONFIG.get("rag", {}).get("top_k", 5))))
MEMORY_ENABLED = setting("MEMORY_ENABLED", "true").casefold() == "true"
