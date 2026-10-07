from types import SimpleNamespace
from app.agent.orchestrator import CopilotAgent
from app.agent.memory import LongTermMemory
from app.agent.state import ShortTermMemory


class CaptureLLM:
    available = True
    def __init__(self): self.requests = []
    def complete(self, messages, tools=None, max_tokens=900):
        self.requests.append(list(messages))
        message = SimpleNamespace(content="Reviewed with supplied evidence.", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def test_multiturn_context_and_feedback_change_prompt(tmp_path, monkeypatch):
    import app.agent.orchestrator as module
    monkeypatch.setattr(module, "MEMORY_ENABLED", True)
    llm = CaptureLLM()
    agent = CopilotAgent(llm=llm, memory=ShortTermMemory(), long_term=LongTermMemory(tmp_path / "prefs.json"))
    agent.respond("Review package alpha", session_id="analyst", include_rag=False)
    agent.feedback.record("analyst", "too_long")
    agent.respond("What evidence should I check next?", session_id="analyst", include_rag=False)
    second_messages = llm.requests[1]
    assert any(message.get("content") == "Review package alpha" for message in second_messages)
    assert "Prefer a concise answer" in second_messages[0]["content"]
    agent.feedback.record("analyst", "too_short")
    agent.respond("Summarize the result", session_id="analyst", include_rag=False)
    assert "Give a more detailed answer" in llm.requests[2][0]["content"]
    agent.reset("analyst", clear_preference=True)
    assert agent.feedback.preference("analyst") == "balanced"
