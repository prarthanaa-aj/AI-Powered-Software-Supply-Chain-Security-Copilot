from app.agent.orchestrator import CopilotAgent
from app.rag.retriever import retrieve
from types import SimpleNamespace


class NoLLM:
    available = False


def test_without_rag_excludes_retrieved_context():
    question = "Review dependency advisory evidence and recommendations"
    with_rag = CopilotAgent(llm=NoLLM()).respond(question, include_rag=True)
    without_rag = CopilotAgent(llm=NoLLM()).respond(question, include_rag=False)
    assert with_rag["evidence"]["retrieval_mode"] == "with_rag"
    assert with_rag["evidence"]["retrieved_guidance"]
    assert without_rag["evidence"]["retrieval_mode"] == "without_rag"
    assert without_rag["evidence"]["retrieved_guidance"] == []


def test_without_rag_also_removes_retrieval_tool():
    class ToolSpy:
        available = True
        def complete(self, messages, tools=None, max_tokens=900):
            self.tools = tools
            return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="No retrieval used.", tool_calls=[]))])

    llm = ToolSpy()
    CopilotAgent(llm=llm).respond("Review a dependency", include_rag=False)
    assert "search_security_guidance" not in {tool["function"]["name"] for tool in llm.tools}
