import pytest
from app.security.guardrails import validate_question
from app.agent.orchestrator import CopilotAgent


def test_question_bounds():
    assert validate_question("check this") == "check this"
    with pytest.raises(ValueError): validate_question("")
    with pytest.raises(ValueError): validate_question("x" * 4001)


class NoLLM:
    available = False


def test_offline_agent_returns_no_security_claim_without_api():
    result = CopilotAgent(llm=NoLLM()).respond("Analyze dependencies", manifest_text="demo==1.0")
    assert "1 pinned dependencies" in result["answer"]
    assert "No current vulnerability claim" in result["answer"]
    assert result["llm_status"] == "not_configured"


@pytest.mark.parametrize("question", [
    "Delete the vulnerable package",
    "Modify requirements.txt automatically",
    "Push the fix to GitHub",
    "Deploy the patched version",
    "Run this arbitrary shell command",
])
def test_prohibited_operations_are_refused_before_model_call(question):
    class MustNotCallLLM:
        available = True
        def complete(self, *args, **kwargs):
            raise AssertionError("LLM must not be called for prohibited operations")

    result = CopilotAgent(llm=MustNotCallLLM()).respond(question)
    assert result["llm_status"] == "refused"
    assert result["tool_events"] == []
    assert "human analyst" in result["answer"]


@pytest.mark.parametrize("question", [
    "Analyze every dependency in requirements.txt and use the risk prioritization tool to score each package.",
    "Compare the evidence for these dependencies and give me a risk score; do not modify files or deploy changes.",
    "Run the dependency scan against this requirements.txt and explain any findings.",
])
def test_security_analysis_requests_are_not_misclassified_as_changes(question):
    from app.security.policies import prohibited_action_requested

    assert not prohibited_action_requested(question)
