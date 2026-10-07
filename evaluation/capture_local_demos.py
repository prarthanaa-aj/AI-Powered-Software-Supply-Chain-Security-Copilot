"""Record offline safety, tool-recovery, memory, and RAG demo traces."""
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from app.agent.memory import LongTermMemory
from app.agent.orchestrator import CopilotAgent
from app.agent.state import ShortTermMemory
from app.config import ROOT


class _NoLLM:
    available = False


class _Call:
    id = "demo-invalid-call"
    function = SimpleNamespace(name="lookup_vulnerability", arguments=json.dumps({"name": "bad name!", "version": "1.0"}))

    def model_dump(self, exclude_none=True):
        return {"id": self.id, "type": "function", "function": {"name": self.function.name, "arguments": self.function.arguments}}


class _RecoveringLLM:
    available = True

    def __init__(self):
        self.calls = 0

    def complete(self, messages, tools=None, max_tokens=900):
        self.calls += 1
        if self.calls == 1:
            message = SimpleNamespace(content=None, tool_calls=[_Call()])
        else:
            message = SimpleNamespace(content="The package identity was invalid; no lookup was performed. Provide an exact PyPI package and version.", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class _CaptureLLM:
    available = True

    def __init__(self):
        self.requests = []

    def complete(self, messages, tools=None, max_tokens=900):
        self.requests.append(list(messages))
        message = SimpleNamespace(content="Reviewed with supplied evidence.", tool_calls=[])
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def run() -> dict:
    safety = CopilotAgent(llm=_NoLLM()).respond("Delete the vulnerable package from my project.")
    unavailable = CopilotAgent(llm=_NoLLM()).respond(
        "Analyze dependencies", manifest_text="requests==2.31.0", include_rag=False
    )

    recovering_llm = _RecoveringLLM()
    recovery = CopilotAgent(llm=recovering_llm).respond("Look up the invalid package name")

    llm = _CaptureLLM()
    agent = CopilotAgent(llm=llm, memory=ShortTermMemory(), long_term=LongTermMemory(ROOT / "evaluation" / "results" / "demo_preferences.json"))
    agent.respond("Review package alpha", session_id="demo-user", include_rag=False)
    initial_prompt = llm.requests[0][0]["content"]
    agent.feedback.record("demo-user", "too_short")
    agent.respond("What evidence should I check next?", session_id="demo-user", include_rag=False)
    detailed_prompt = llm.requests[1][0]["content"]
    remembered_context = any(item.get("content") == "Review package alpha" for item in llm.requests[1])
    detailed_preference = "Give a more detailed answer." in detailed_prompt
    agent.feedback.record("demo-user", "too_long")
    agent.respond("Summarize the evidence briefly.", session_id="demo-user", include_rag=False)
    concise_prompt = llm.requests[2][0]["content"]
    concise_preference = "Prefer a concise answer." in concise_prompt
    agent.reset("demo-user", clear_preference=True)
    reset_preference = agent.feedback.preference("demo-user")

    question = "How should I verify the exact installed package version and affected version range?"
    with_rag = CopilotAgent(llm=_NoLLM()).respond(question, include_rag=True)
    without_rag = CopilotAgent(llm=_NoLLM()).respond(question, include_rag=False)
    unsupported_question = "What is the capital of France?"
    missing_knowledge = CopilotAgent(llm=_NoLLM()).respond(unsupported_question, include_rag=True)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "suite": "local non-provider demo traces; fake LLM used where noted",
        "safety": {"status": safety["llm_status"], "answer": safety["answer"], "tool_events": safety["tool_events"]},
        "llm_unavailable": {"status": unavailable["llm_status"], "answer": unavailable["answer"],
                            "tool_events": unavailable["tool_events"], "llm_simulated": True},
        "tool_recovery": {"llm_calls": recovering_llm.calls, "tool_events": recovery["tool_events"], "answer": recovery["answer"], "llm_simulated": True},
        "memory_adaptation": {"default_has_no_preference": "Give a more detailed answer." not in initial_prompt,
                               "prior_turn_in_context": remembered_context,
                               "too_short_changed_prompt_to_detailed": detailed_preference,
                               "too_long_changed_prompt_to_concise": concise_preference,
                               "reset_preference": reset_preference, "llm_simulated": True},
        "rag_comparison": {"query": question,
                           "with_rag_sources": [hit["source"] for hit in with_rag["evidence"]["retrieved_guidance"]],
                           "without_rag_sources": [hit["source"] for hit in without_rag["evidence"]["retrieved_guidance"]],
                           "missing_knowledge_query": unsupported_question,
                           "missing_knowledge_sources": [hit["source"] for hit in missing_knowledge["evidence"]["retrieved_guidance"]]},
        "limitations": ["The tool-recovery and memory LLMs are fakes; these traces validate local control flow, not live model behavior.",
                        "The RAG comparison records local retrieval context only, not paired generated-answer quality."],
    }


if __name__ == "__main__":
    report = run()
    target = ROOT / "evaluation" / "results" / "local_demo_traces.json"
    target.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    print(json.dumps({"output": str(target), "safety": report["safety"]["status"],
                      "recovery_events": report["tool_recovery"]["tool_events"],
                      "unavailable": report["llm_unavailable"]["status"],
                      "memory": report["memory_adaptation"], "rag": report["rag_comparison"]}, indent=2))
