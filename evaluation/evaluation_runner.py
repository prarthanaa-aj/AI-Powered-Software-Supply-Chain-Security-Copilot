"""Run the offline evaluation suite and save reproducible metrics."""
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from app.config import ROOT
from app.rag.retriever import retrieve
from app.security.guardrails import validate_question
from app.tools.dependency_graph import build_dependency_graph, summarize_graph
from app.tools.dependency_scanner import scan_requirements_text
from app.tools.risk_prediction import heuristic_risk


def run(cases_path: Path | None = None) -> dict:
    path = cases_path or ROOT / "evaluation" / "test_cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))
    results = []
    for case in cases:
        try:
            category = case["category"]
            if category == "scan":
                actual = len(scan_requirements_text(case["content"]).dependencies)
                passed = actual == case["expected_count"]
            elif category == "risk":
                actual = heuristic_risk(case["features"])["level"]
                passed = actual == case["expected_level"]
            elif category == "graph":
                graph = build_dependency_graph(case["dependencies"], case["edges"])
                actual = summarize_graph(graph)
                depth = next(item["depth"] for item in actual["dependencies"] if item["name"] == case["target"])
                passed = depth == case["expected_depth"]
                actual = {"target_depth": depth}
            elif category == "safety":
                try:
                    validate_question(case["question"])
                    actual = True
                except ValueError:
                    actual = False
                passed = actual == case["accepted"]
            elif category == "retrieval":
                actual = [item["source"].replace(chr(92), "/") for item in retrieve(case["query"], top_k=3)]
                passed = case["expected_source"] in actual
            else:
                actual, passed = "unknown category", False
            results.append({"id": case["id"], "category": category, "passed": bool(passed), "actual": actual})
        except Exception as exc:
            results.append({"id": case.get("id", "unknown"), "category": case.get("category", "unknown"), "passed": False, "error_type": type(exc).__name__})
    total = len(results)
    passed = sum(item["passed"] for item in results)
    by_category = {}
    for category in sorted({item["category"] for item in results}):
        group = [item for item in results if item["category"] == category]
        by_category[category] = {"passed": sum(i["passed"] for i in group), "total": len(group), "pass_rate": round(sum(i["passed"] for i in group) / len(group), 4)}
    report = {"generated_at": datetime.now(timezone.utc).isoformat(), "suite": "offline deterministic evaluation", "total": total, "passed": passed, "failed": total - passed, "pass_rate": round(passed / total, 4) if total else 0.0, "categories": by_category, "results": results, "limitations": ["Does not measure live LLM answer quality or OSV freshness.", "The risk score is a heuristic, not a validated predictive model.", "Retrieval cases cover the small included guidance corpus only."]}
    out = ROOT / "evaluation" / "results" / "latest.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    result = run()
    print(json.dumps({k: result[k] for k in ("total", "passed", "failed", "pass_rate", "categories")}, indent=2))

