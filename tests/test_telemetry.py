import json
import app.telemetry as telemetry


def test_event_logs_metrics_but_never_question_or_secret(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "ROOT", tmp_path)
    telemetry.record_event({"event": "analysis", "status": "success", "latency_seconds": 1.2,
                            "llm_call_count": 2, "rag_latency_seconds": 0.02,
                            "prompt_tokens": 100, "completion_tokens": 50,
                            "question": "private question", "api_key": "secret-value"})
    entry = json.loads((tmp_path / "logs" / "events.jsonl").read_text(encoding="utf-8"))
    assert entry["llm_call_count"] == 2
    assert entry["rag_latency_seconds"] == 0.02
    assert "question" not in entry
    assert "api_key" not in entry
    assert "secret-value" not in json.dumps(entry)
