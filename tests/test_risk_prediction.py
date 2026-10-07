import csv
from app.tools.risk_prediction import heuristic_risk, predict_with_model, train_logistic_csv
from app.agent.orchestrator import CopilotAgent


def test_heuristic_is_monotonic_for_severity_and_exploit_evidence():
    low = heuristic_risk({"cvss": 2, "exploit_known": False, "direct": False, "dependency_depth": 3, "vulnerability_count": 1})
    high = heuristic_risk({"cvss": 9, "exploit_known": True, "direct": True, "dependency_depth": 1, "vulnerability_count": 3})
    assert high["score"] > low["score"]
    assert high["method"] == "transparent_heuristic"


def test_optional_model_requires_labeled_rows_and_marks_experimental(tmp_path):
    source = tmp_path / "labels.csv"
    fields = ["cvss", "exploit_known", "direct", "dependency_depth", "vulnerability_count", "label"]
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields); writer.writeheader()
        for i in range(24):
            writer.writerow({"cvss": i % 10, "exploit_known": i % 2, "direct": (i // 2) % 2, "dependency_depth": i % 4 + 1, "vulnerability_count": i % 5, "label": i % 2})
    path = tmp_path / "model.json"
    trained = train_logistic_csv(str(source), str(path), epochs=10)
    prediction = predict_with_model({"cvss": 8, "exploit_known": 1, "direct": 1, "dependency_depth": 1, "vulnerability_count": 2}, str(path))
    assert trained["status"] == "experimental_unvalidated"
    assert prediction["method"] == "experimental_logistic_regression"


def test_agent_risk_tool_uses_manifest_and_osv_evidence_only():
    agent = CopilotAgent(llm=type("NoLLM", (), {"available": False})())
    dependencies = [{"name": "requests", "version": "2.31.0", "direct": True}]
    no_lookup = agent._execute_tool("prioritize_risk", {"name": "requests", "cvss": 10, "exploit_known": True}, dependencies, {})
    assert no_lookup["status"] == "insufficient_evidence"
    evidence = {("requests", "2.31.0"): {"status": "success", "retrieved_at": "2026-01-01T00:00:00Z", "vulnerabilities": [{"id": "OSV-TEST-1", "severity_vectors": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}]}}
    scored = agent._execute_tool("prioritize_risk", {"name": "requests", "cvss": 0, "exploit_known": False}, dependencies, evidence)
    assert scored["status"] == "success"
    assert scored["factors"]["cvss_normalized"] == 0.98
    assert scored["advisory_ids"] == ["OSV-TEST-1"]
    assert scored["method"] == "transparent_heuristic"
    no_numeric_cvss = {("requests", "2.31.0"): {"status": "success", "vulnerabilities": [{"id": "OSV-TEST-2", "severity": "HIGH"}]}}
    assert agent._execute_tool("prioritize_risk", {"name": "requests"}, dependencies, no_numeric_cvss)["status"] == "insufficient_evidence"
    no_findings = {("requests", "2.31.0"): {"status": "success", "vulnerabilities": []}}
    assert agent._execute_tool("prioritize_risk", {"name": "requests"}, dependencies, no_findings)["status"] == "no_findings"
    assert agent._execute_tool("prioritize_risk", {"name": "unlisted"}, dependencies, evidence)["status"] == "insufficient_evidence"
