from app.project_analyzer import analyze_project_files, build_project_genome
from app.risk.contextual_risk import calculate_contextual_risk, risk_category, simulate_lookup_change


def _project(source=True):
    files = {"requirements.txt": "requests==2.25.1\nflask==2.2.5"}
    if source:
        files["src/api.py"] = "import requests\nfrom flask import Flask"
        files["src/auth.py"] = "from requests import get"
    return analyze_project_files(files)


def test_project_analysis_finds_source_usage_and_drift_without_executing_code():
    result = _project()
    assert result["source_analysis_status"] == "completed"
    assert result["used_dependencies"] == ["flask", "requests"]
    assert len(result["imports_by_file"]) == 2
    assert result["transitive_dependency_status"] == "not_available_from_supported_inputs"


def test_project_analysis_distinguishes_source_unavailable_and_invalid_manifest():
    no_source = analyze_project_files({"requirements.txt": "requests==2.25.1"})
    assert no_source["source_analysis_status"] == "not_provided"
    assert no_source["apparently_unused_dependencies"] == []
    invalid = analyze_project_files({"requirements.txt": "not a valid pin"})
    assert invalid["dependencies"] == []
    assert invalid["files"][0]["issues"]
    assert analyze_project_files({})["source_analysis_status"] == "not_provided"


def test_project_analysis_detects_conflicting_manifest_declarations():
    result = analyze_project_files({"requirements.txt": "requests==2.31.0",
                                    "requirements-dev.txt": "requests==2.25.1"})
    assert result["version_conflicts"] == [{"package": "requests", "versions": ["2.31.0", "2.25.1"]}]
    assert result["drift_signals"][-1]["type"] == "conflicting_manifest_versions"


def test_project_analysis_surfaces_unpinned_declaration_without_querying_it():
    result = analyze_project_files({"requirements.txt": "requests>=2.0"})
    assert result["dependencies"][0]["name"] == "requests"
    assert result["dependencies"][0]["version"] is None
    assert result["dependencies"][0]["pinned"] is False
    assert result["dependencies"][0]["direct"] is None


def test_project_analysis_reports_declared_unused_and_unmatched_import_as_signals():
    result = analyze_project_files({"requirements.txt": "requests==2.25.1\nflask==2.2.5",
                                    "src/api.py": "import requests\nimport customlib"})
    assert result["apparently_unused_dependencies"] == ["flask"]
    assert "customlib" in result["unmatched_import_candidates"]
    assert len(result["drift_signals"]) == 2


def test_project_analysis_handles_syntax_error_and_size_limits():
    result = analyze_project_files({"requirements.txt": "requests==2.25.1",
                                    "bad.py": "def broken(:\n"})
    assert result["source_analysis_status"] == "partial"
    assert result["import_errors"][0]["status"] == "syntax_error"
    large = analyze_project_files({"large.py": "x" * 200_001})
    assert large["files"][0]["status"] == "rejected"


def test_project_genome_only_contains_evidenced_relationships():
    project = _project()
    graph = build_project_genome(project, [{"package": "requests", "version": "2.25.1",
                                            "vulnerabilities": [{"id": "OSV-TEST"}]}])
    assert graph.has_edge("project", "requests")
    assert graph.has_edge("source:src/api.py", "requests")
    assert graph.has_edge("requests", "advisory:OSV-TEST")
    assert not graph.has_edge("requests", "flask")


def test_risk_unknown_lookup_never_becomes_zero_risk():
    risk = calculate_contextual_risk(_project(False), [])
    assert risk["score"] is None
    assert risk["category"] == "INSUFFICIENT EVIDENCE"
    assert all(dep["risk_score"] is None for dep in risk["dependencies"])


def test_risk_no_findings_is_evidence_bounded():
    project = analyze_project_files({"requirements.txt": "requests==2.25.1"})
    risk = calculate_contextual_risk(project, [{"package": "requests", "version": "2.25.1",
                                                "status": "success", "vulnerabilities": []}])
    assert risk["score"] == 0
    assert risk["dependencies"][0]["vulnerability_status"] == "no_verified_vulnerability_found"
    assert "does not mean the package is secure" in risk["dependencies"][0]["explanation"]


def test_contextual_vulnerability_risk_uses_cvss_and_static_usage_evidence():
    project = _project()
    risk = calculate_contextual_risk(project, [{"package": "requests", "version": "2.25.1",
                                                "status": "success", "vulnerabilities": [
                                                    {"id": "CVE-TEST", "cvss_score": 9.8, "severity": "CRITICAL"}]}])
    row = next(item for item in risk["dependencies"] if item["package"] == "requests")
    assert row["risk_score"] is not None
    assert row["category"] in {"LOW", "MEDIUM", "HIGH"}
    assert "src/api.py" in row["affected_modules"]
    assert row["components"]["supply_chain_trust"]["status"] == "unknown"
    assert "heuristic" in row["explanation"]


def test_analyst_context_changes_exposure_interpretation_and_is_attributed():
    project = _project()
    lookups = [{"package": "requests", "version": "2.25.1", "status": "success",
                "vulnerabilities": [{"id": "CVE-TEST", "cvss_score": 8.0}]}]
    baseline = calculate_contextual_risk(project, lookups)
    feedback = calculate_contextual_risk(project, lookups, {
        "package": "requests", "classification": "development_only"})
    before = next(r for r in baseline["dependencies"] if r["package"] == "requests")
    after = next(r for r in feedback["dependencies"] if r["package"] == "requests")
    assert after["risk_score"] < before["risk_score"]
    assert after["components"]["exposure_static_usage"]["normalized_value"] == .25
    assert "not independently verified" in after["risk_reducers"][0]


def test_risk_boundaries():
    assert [risk_category(n) for n in (39, 40, 59, 60, 79, 80, 100)] == [
        "NO SIGNIFICANT VERIFIED RISK", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH"]


def test_invalid_risk_boundary_rejected():
    import pytest
    with pytest.raises(ValueError):
        risk_category(101)


def test_simulation_requires_successful_hypothetical_lookup_and_never_mutates():
    project = _project()
    lookups = [{"package": "requests", "version": "2.25.1", "status": "success",
                "vulnerabilities": [{"id": "CVE-TEST", "cvss_score": 9.8}]}]
    before = project["dependencies"][0]["version"]
    missing = simulate_lookup_change(project, lookups, "requests", {"version": "2.32.0", "status": "unavailable"})
    assert missing["status"] == "insufficient_evidence"
    scenario = simulate_lookup_change(project, lookups, "requests", {
        "version": "2.32.0", "status": "success", "vulnerabilities": []})
    assert scenario["simulation_only"] is True
    assert scenario["files_modified"] is False
    simulated = scenario["after_dependency"]
    assert simulated["risk_score"] == 0
    assert scenario["after"]["score"] is None
    assert scenario["before_dependency"]["risk_score"] is not None
    assert scenario["score_delta"] < 0
    assert project["dependencies"][0]["version"] == before


def test_simulation_rejects_unknown_package():
    result = simulate_lookup_change(_project(), [], "missing-package",
                                    {"version": "1.0", "status": "success", "vulnerabilities": []})
    assert result["status"] == "invalid_input"
