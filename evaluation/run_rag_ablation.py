"""Capture paired live answers with local guidance retrieval on and off."""
import json
from datetime import datetime, timezone
from app.agent.langchain_agent import LangChainCopilotAgent
from app.config import ROOT, VOC_BASE_URL, VOC_MODEL


QUESTION = "What should I conclude when an OSV lookup returns no records, and what should an analyst check next?"


def run() -> dict:
    with_rag = LangChainCopilotAgent().respond(QUESTION, session_id="rag-ablation-on", include_rag=True)
    without_rag = LangChainCopilotAgent().respond(QUESTION, session_id="rag-ablation-off", include_rag=False)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "configured Vocareum-compatible endpoint",
        "base_url": VOC_BASE_URL,
        "model": VOC_MODEL,
        "question": QUESTION,
        "with_rag": {"answer": with_rag["answer"], "sources": [
            item["source"] for item in with_rag["evidence"].get("retrieved_guidance", [])],
            "tool_events": with_rag["tool_events"], "latency_seconds": with_rag.get("latency_seconds")},
        "without_rag": {"answer": without_rag["answer"], "sources": [
            item["source"] for item in without_rag["evidence"].get("retrieved_guidance", [])],
            "tool_events": without_rag["tool_events"], "latency_seconds": without_rag.get("latency_seconds")},
        "answer_text_differs": with_rag["answer"].strip() != without_rag["answer"].strip(),
        "limitations": [
            "One paired model run is descriptive only and does not establish that RAG improves answer quality.",
            "The authored retrieval corpus and concept vocabulary are small; human grounding review is required.",
        ],
    }
    target = ROOT / "evaluation" / "results" / "rag_ablation.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    return report


if __name__ == "__main__":
    result = run()
    print(json.dumps({"output": "evaluation/results/rag_ablation.json",
                      "with_rag_sources": result["with_rag"]["sources"],
                      "without_rag_sources": result["without_rag"]["sources"],
                      "answer_text_differs": result["answer_text_differs"]}, indent=2))
