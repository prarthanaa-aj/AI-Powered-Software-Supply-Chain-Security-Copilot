"""Privacy-preserving operational event logging."""
import json
from datetime import datetime, timezone
from app.config import ROOT


def record_event(event: dict) -> None:
    safe = {key: value for key, value in event.items() if key in {"event", "status", "latency_seconds", "tool_count", "step_count", "error_type", "llm_status", "tools", "tool_statuses", "llm_call_count", "rag_latency_seconds", "llm_latency_seconds", "prompt_tokens", "completion_tokens"}}
    safe["timestamp"] = datetime.now(timezone.utc).isoformat()
    target = ROOT / "logs" / "events.jsonl"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(safe, ensure_ascii=True) + "\n")
    except OSError:
        pass

