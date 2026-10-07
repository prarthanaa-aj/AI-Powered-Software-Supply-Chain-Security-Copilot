import json
from types import SimpleNamespace
from app.agent.orchestrator import CopilotAgent
from app.models import LookupResult
import app.agent.orchestrator as orchestrator


class ToolCall:
    id = "call-invalid"
    function = SimpleNamespace(name="lookup_vulnerability", arguments=json.dumps({"name": "bad name!", "version": "1.0"}))
    def model_dump(self, exclude_none=True):
        return {"id": self.id, "type": "function", "function": {"name": self.function.name, "arguments": self.function.arguments}}


class RecoveringLLM:
    available = True
    def __init__(self): self.count = 0
    def complete(self, messages, tools=None, max_tokens=900):
        self.count += 1
        if self.count == 1:
            message = SimpleNamespace(content=None, tool_calls=[ToolCall()])
        else:
            message = SimpleNamespace(content="The package name was invalid; no lookup was performed. Please provide an exact PyPI package and version.", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_invalid_tool_call_returns_error_and_agent_recovers():
    llm = RecoveringLLM()
    result = CopilotAgent(llm=llm).respond("Look up the invalid package name")
    assert llm.count == 2
    assert result["tool_events"][0]["status"] == "invalid_input"
    assert "invalid" in result["answer"]


class NamedToolCall:
    def __init__(self, name, arguments, call_id):
        self.id = call_id
        self.function = SimpleNamespace(name=name, arguments=json.dumps(arguments))

    def model_dump(self, exclude_none=True):
        return {"id": self.id, "type": "function", "function": {"name": self.function.name, "arguments": self.function.arguments}}


def test_llm_tool_loop_binds_risk_score_to_manifest_and_osv(monkeypatch):
    monkeypatch.setattr(orchestrator, "lookup_vulnerabilities", lambda name, version: LookupResult(
        package=name, version=version, status="success", retrieved_at="2026-01-01T00:00:00Z",
        vulnerabilities=[{"id": "OSV-TEST-1", "cvss_score": 9.8}],
    ))

    class EvidenceSelectingLLM:
        available = True
        def __init__(self): self.turn = 0
        def complete(self, messages, tools=None, max_tokens=900):
            self.turn += 1
            if self.turn == 1:
                message = SimpleNamespace(content=None, tool_calls=[NamedToolCall("lookup_vulnerability", {"name": "requests", "version": "2.31.0"}, "lookup")])
            elif self.turn == 2:
                message = SimpleNamespace(content=None, tool_calls=[NamedToolCall("prioritize_risk", {"name": "requests", "cvss": 0, "exploit_known": False}, "risk")])
            else:
                message = SimpleNamespace(content="The score is heuristic and based on the OSV record.", tool_calls=[])
            return SimpleNamespace(choices=[SimpleNamespace(message=message)])

    result = CopilotAgent(llm=EvidenceSelectingLLM()).respond("Review requests risk", manifest_text="requests==2.31.0", include_rag=False)
    risk_output = next(item["result"] for item in result["tool_outputs"] if item["tool"] == "prioritize_risk")
    assert risk_output["factors"]["cvss_normalized"] == 0.98
    assert risk_output["advisory_ids"] == ["OSV-TEST-1"]
    assert [event["tool"] for event in result["tool_events"]] == ["lookup_vulnerability", "prioritize_risk"]
