from app.security.response_guardrails import enforce_empty_lookup_language


def test_empty_osv_result_cannot_be_called_safe_or_cited_as_vulnerable():
    outputs = [{"tool": "lookup_vulnerability", "result": {"status": "success", "vulnerabilities": []}}]
    for unsafe in (
        "No known vulnerabilities were found, so this package is safe.",
        "No known reported vulnerabilities appear in the database.",
        "This package is secure.",
        "OSV-2026-123 proves this is critical.",
    ):
        answer, changed = enforce_empty_lookup_language(unsafe, outputs)
        assert changed
        assert "returned no records" in answer
        assert "does not establish" in answer


def test_failed_lookup_cannot_be_reported_as_clean():
    answer, changed = enforce_empty_lookup_language("No vulnerabilities were found; package is safe.", [{"tool": "lookup_vulnerability", "result": {"status": "unavailable", "vulnerabilities": []}}])
    assert changed
    assert "did not complete successfully" in answer


def test_invalid_input_is_described_as_local_rejection_before_osv():
    answer, changed = enforce_empty_lookup_language(
        "OSV.dev returned an error for this invalid package.",
        [{"tool": "lookup_vulnerability", "result": {"status": "invalid_input", "source": "local_input_validation"}}],
    )
    assert changed
    assert "before contacting OSV.dev" in answer
    assert "No vulnerability lookup was performed" in answer


def test_nonempty_lookup_does_not_trigger_empty_result_guard():
    answer = "OSV-2025-123 affects the reported package."
    output, changed = enforce_empty_lookup_language(answer, [{"tool": "lookup_vulnerability", "result": {"status": "success", "vulnerabilities": [{"id": "OSV-2025-123"}]}}])
    assert output == answer
    assert not changed


def test_missing_numeric_risk_evidence_cannot_be_reported_as_low_risk():
    output = [{"tool": "prioritize_risk", "result": {"status": "insufficient_evidence"}}]
    answer, changed = enforce_empty_lookup_language("The package is low risk with a risk score of 0.22.", output)
    assert changed
    assert "risk category or priority was not assigned" in answer
    answer, changed = enforce_empty_lookup_language("The risk score of 0.22 indicates low risk.", output)
    assert changed
    assert "risk category or priority was not assigned" in answer


def test_missing_risk_evidence_blocks_priority_ranking_claim():
    outputs = [{"tool": "prioritize_risk", "result": {"status": "insufficient_evidence"}}]
    answer, changed = enforce_empty_lookup_language(
        "The highest priority package should be upgraded first.", outputs
    )
    assert changed
    assert "priority was not assigned" in answer
