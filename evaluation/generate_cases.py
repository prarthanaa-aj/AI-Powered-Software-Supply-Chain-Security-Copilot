"""Generate a deterministic 100-case offline evaluation set."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
cases = []
for i in range(20):
    cases.append({"id": f"SCAN{i+1:03}", "category": "scan", "content": f"demo_pkg_{i:02}==1.2.{i}\n", "expected_count": 1})

risk_sets = [
    ({"cvss": 0.5, "exploit_known": False, "direct": False, "dependency_depth": 4, "vulnerability_count": 0}, "LOW"),
    ({"cvss": 6.0, "exploit_known": False, "direct": True, "dependency_depth": 1, "vulnerability_count": 1}, "MEDIUM"),
    ({"cvss": 8.5, "exploit_known": True, "direct": True, "dependency_depth": 2, "vulnerability_count": 2}, "HIGH"),
    ({"cvss": 9.5, "exploit_known": True, "direct": True, "dependency_depth": 1, "vulnerability_count": 5}, "CRITICAL"),
]
for i in range(20):
    features, level = risk_sets[i % len(risk_sets)]
    cases.append({"id": f"RISK{i+1:03}", "category": "risk", "features": features, "expected_level": level})

for i in range(20):
    cases.append({"id": f"GRAPH{i+1:03}", "category": "graph", "dependencies": [{"name": f"direct_{i}", "version": "1.0", "direct": True}, {"name": f"transitive_{i}", "version": "2.0", "direct": False}], "edges": [[f"direct_{i}", f"transitive_{i}"]], "target": f"transitive_{i}", "expected_depth": 2})

valid_questions = ["Review this project", "What is the risk?", "Show evidence", "Check a dependency", "Explain a CVE", "Summarize the graph", "Find package guidance", "Prioritize the alert", "Review a manifest", "What data is missing?"]
for i in range(10):
    cases.append({"id": f"SAFE{i+1:03}", "category": "safety", "question": valid_questions[i], "accepted": True})
for i in range(10):
    cases.append({"id": f"SAFE{i+11:03}", "category": "safety", "question": "x" * (4001 + i), "accepted": False})

retrieval_queries = [
    "dependency advisory source", "verify package version", "direct transitive dependency path", "exploit evidence and advisory", "source date and stale records",
    "conflicting vulnerability records", "human analyst remediation decision", "security standards and package review", "API credentials and source code privacy", "upgrade compatibility and tests",
    "missing lookup result unknown coverage", "review CVE package identity", "dependency graph provenance", "risk score is not authoritative", "minimum context to language model",
    "curated security guidance document", "check affected version range", "analyst owns remediation", "external sources and timestamps", "dependency security review evidence",
]
for i, query in enumerate(retrieval_queries):
    cases.append({"id": f"RAG{i+1:03}", "category": "retrieval", "query": query, "expected_source": "data/knowledge_base/standards/analyst_review.md"})

assert len(cases) == 100
(ROOT / "evaluation" / "test_cases.json").write_text(json.dumps(cases, indent=2), encoding="utf-8")
print(f"Generated {len(cases)} offline cases")

