"""Evaluate local RAG relevance and unsupported-query rejection on a small rubric."""
import json
from datetime import datetime, timezone
from app.config import ROOT
from app.rag.retriever import retrieve, load_documents


def run() -> dict:
    cases = json.loads((ROOT / "evaluation" / "rag_cases.json").read_text(encoding="utf-8-sig"))
    results = []
    for case in cases:
        hits = retrieve(case["query"], top_k=3)
        top = hits[0] if hits else None
        # Relevance is measured over retrieved top-k passages, not only rank 1.
        corpus = "\n".join(hit["text"] for hit in hits).casefold()
        matched = [term for term in case["required_terms"] if term.casefold() in corpus]
        passed = bool(hits) and len(matched) >= min(2, len(case["required_terms"])) if case["answerable"] else not hits
        results.append({"id": case["id"], "answerable": case["answerable"], "passed": passed,
                        "top_source": top["source"] if top else None,
                        "top_similarity": top["similarity"] if top else None,
                        "relevant_sources": sorted({hit["source"] for hit in hits if any(term.casefold() in hit["text"].casefold() for term in case["required_terms"])}),
                        "required_terms": case["required_terms"], "matched_terms": matched})
    answerable = [item for item in results if item["answerable"]]
    unanswerable = [item for item in results if not item["answerable"]]
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "suite": "curated RAG relevance and abstention rubric",
              "total": len(results), "passed": sum(item["passed"] for item in results), "results": results,
              "retrieval_backend": "offline concept-expanded sparse vectors with cosine similarity",
              "corpus_documents": len({item["source"] for item in load_documents()}),
              "metrics": {"answerable_relevance_pass_rate": round(sum(i["passed"] for i in answerable) / len(answerable), 4),
                          "unanswerable_rejection_rate": round(sum(i["passed"] for i in unanswerable) / len(unanswerable), 4)},
              "limitations": ["Manually authored queries over four project-authored guidance files; not a broad or independent benchmark.",
                              "Required phrase overlap is only a retrieval relevance proxy; it does not measure generated-answer correctness or grounding.",
                              "Offline vectors use curated synonym classes rather than a pretrained neural model and may miss unlisted paraphrases."]}
    output = ROOT / "evaluation" / "results" / "rag_evaluation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    report = run()
    print(json.dumps({"total": report["total"], "passed": report["passed"], "metrics": report["metrics"]}, indent=2))
