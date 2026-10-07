from threading import Lock

from app.agent.langchain_agent import LangChainCopilotAgent, _budgeted_tool_call, _history_messages
from app.agent.memory import LongTermMemory
from app.agent.orchestrator import CopilotAgent
from app.agent.state import ShortTermMemory
from app.config import ROOT
from app.security.guardrails import MAX_TOOL_CALLS


def test_langchain_tool_adapter_enforces_shared_call_budget():
    counter = {"calls": 0}
    calls = []
    lock = Lock()

    def tool(value):
        calls.append(value)
        return {"value": value}

    for index in range(MAX_TOOL_CALLS):
        assert _budgeted_tool_call(counter, lock, "sample", tool, value=index) == {"value": index, "status": "success"}
    assert _budgeted_tool_call(counter, lock, "sample", tool, value="over-budget") == {
        "status": "blocked", "message": "Tool call limit reached for this request."
    }
    assert len(calls) == MAX_TOOL_CALLS


def test_langchain_tool_adapter_sanitizes_tool_exception():
    result = _budgeted_tool_call({"calls": 0}, Lock(), "sample",
                                lambda: (_ for _ in ()).throw(ValueError("private details")))
    assert result == {"status": "error", "error_type": "ValueError", "message": "Tool operation failed."}
    assert "private details" not in str(result)


def test_langchain_tool_adapter_blocks_repeated_identical_call():
    counter = {"calls": 0}
    seen = set()
    calls = []
    invoke = lambda package: calls.append(package) or {"package": package}
    first = _budgeted_tool_call(counter, Lock(), "lookup", invoke,
                                seen_calls=seen, package="flask")
    second = _budgeted_tool_call(counter, Lock(), "lookup", invoke,
                                 seen_calls=seen, package="flask")
    assert first["status"] == "success"
    assert second["status"] == "blocked"
    assert len(calls) == 1


def test_langchain_tool_adapter_allows_different_inputs_for_same_tool():
    counter = {"calls": 0}
    seen = set()
    calls = []
    invoke = lambda: calls.append(True) or {"status": "success"}
    for name, version in (("requests", "2.31.0"), ("flask", "2.2.5")):
        result = _budgeted_tool_call(counter, Lock(), "lookup_vulnerability", invoke,
                                     seen_calls=seen, signature_args={"name": name, "version": version})
        assert result["status"] == "success"
    assert len(calls) == 2


def test_adapter_delegates_memory_feedback_and_reset():
    short_term = ShortTermMemory()
    long_term = LongTermMemory(ROOT / ".pytest-work" / "langchain-test-preferences.json")
    base = CopilotAgent(memory=short_term, long_term=long_term)
    adapter = LangChainCopilotAgent(base_agent=base)

    short_term.append("session-a", "user", "prior question")
    short_term.append("session-a", "assistant", "prior answer")
    assert _history_messages(short_term.get("session-a")) == [
        ("human", "prior question"), ("ai", "prior answer")
    ]
    assert adapter.record_feedback("session-a", "too_short") == "detailed"
    assert base.feedback.preference("session-a") == "detailed"

    adapter.reset("session-a")
    assert short_term.get("session-a") == []
    assert base.feedback.preference("session-a") == "detailed"
    adapter.reset("session-a", clear_preference=True)
    assert base.feedback.preference("session-a") == "balanced"


def test_langchain_executor_selects_registered_tool_and_returns_its_output():
    from langchain_core.messages import AIMessage
    from langchain_core.runnables import RunnableLambda

    class FakeToolCallingModel:
        def __init__(self):
            self.calls = 0

        def bind_tools(self, tools, **kwargs):
            def respond(_prompt):
                self.calls += 1
                if self.calls == 1:
                    return AIMessage(content="", tool_calls=[{
                        "name": "dependency_scanner", "args": {},
                        "id": "scan-1", "type": "tool_call",
                    }])
                return AIMessage(content="The manifest contains requests 2.31.0.")
            return RunnableLambda(respond)

    model = FakeToolCallingModel()
    agent = LangChainCopilotAgent(base_agent=CopilotAgent(llm=type("NoLLM", (), {"available": False})()), model=model)
    result = agent.respond("List the dependencies", manifest_text="requests==2.31.0", include_rag=False)

    assert model.calls == 2
    assert result["tool_events"] == [{"tool": "dependency_scanner", "status": "success"}]
    assert result["tool_outputs"][0]["result"]["dependencies"][0]["name"] == "requests"
    assert "requests 2.31.0" in result["answer"]


def test_langchain_adapter_refuses_prohibited_action_before_model():
    class NeverModel:
        calls = 0
        def bind_tools(self, tools, **kwargs):
            self.calls += 1
            raise AssertionError("model should not be initialized for prohibited action")

    model = NeverModel()
    agent = LangChainCopilotAgent(base_agent=CopilotAgent(llm=type("NoLLM", (), {"available": False})()), model=model)
    result = agent.respond("Delete the vulnerable package from my project.")
    assert "can’t make changes" in result["answer"]
    assert result["tool_events"] == []
    assert model.calls == 0


def test_langchain_adapter_returns_safe_fallback_on_model_failure(monkeypatch):
    from langchain_core.runnables import RunnableLambda
    import app.agent.langchain_agent as module

    events = []
    monkeypatch.setattr(module, "record_event", events.append)

    class FailingModel:
        def bind_tools(self, tools, **kwargs):
            def fail(_prompt):
                raise RuntimeError("private provider diagnostic")
            return RunnableLambda(fail)

    agent = LangChainCopilotAgent(base_agent=CopilotAgent(llm=type("NoLLM", (), {"available": False})()), model=FailingModel())
    result = agent.respond("List packages", manifest_text="requests==2.31.0", include_rag=False)
    assert result["llm_status"] == "llm_unavailable"
    assert "requests==2.31.0" in result["answer"]
    assert "private provider diagnostic" not in result["answer"]
    assert events[0]["event"] == "analysis"
    assert "question" not in events[0]
