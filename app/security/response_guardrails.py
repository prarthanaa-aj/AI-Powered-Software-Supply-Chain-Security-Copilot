"""Deterministic post-generation checks for unsupported advisory conclusions."""
import re

_UNSAFE_EMPTY_CLAIM = re.compile(
    r"\b(?:safe|secure)\b|\bno\s+(?:(?:known|reported|recorded|identified)\s+)*(?:vulnerabilities?|security issues?|cves?)\b|\b(?:CVE-\d{4}-\d+|GHSA-[A-Z0-9-]+|OSV-\d{4}-\d+|PYSEC-\d{4}-\d+)\b",
    re.IGNORECASE,
)
_UNSUPPORTED_RISK_CLAIM = re.compile(
    r"\b(?:low|medium|high|critical)\s+(?:overall\s+)?risk\b|"
    r"\brisk(?:\s+(?:score|level))?\s*(?:is|:|=|of)\s*(?:low|medium|high|critical|\d+(?:\.\d+)?)|"
    r"\b(?:priorit(?:y|ize|ized|ization)|highest\s+priority|lowest\s+priority)\b",
    re.IGNORECASE,
)


def enforce_empty_lookup_language(answer: str, tool_outputs: list[dict]) -> tuple[str, bool]:
    lookups = [item.get("result", {}) for item in tool_outputs if item.get("tool") == "lookup_vulnerability"]
    invalid_inputs = [result for result in lookups if result.get("status") == "invalid_input"]
    if invalid_inputs:
        return (
            "Local input validation rejected the invalid package name or version before contacting OSV.dev. "
            "No vulnerability lookup was performed. Provide a valid PyPI package name and concrete version to retry.",
            True,
        )
    empties = [result for result in lookups if result.get("status") == "success" and not result.get("vulnerabilities")]
    failures = [result for result in lookups if result.get("status") in {"unavailable", "invalid_input", "error"}]
    if empties and _UNSAFE_EMPTY_CLAIM.search(answer or ""):
        return (
            "OSV.dev returned no records for the queried package/version. This result covers only that source and lookup time; "
            "it does not establish that the package is safe or free of vulnerabilities. Review other relevant sources and project context before deciding.",
            True,
        )
    if failures and _UNSAFE_EMPTY_CLAIM.search(answer or ""):
        return (
            "The OSV lookup did not complete successfully. No conclusion about the package’s vulnerability status can be made from this attempt. Check the package identity or source availability and retry.",
            True,
        )
    risk_gaps = [item.get("result", {}) for item in tool_outputs
                 if item.get("tool") == "prioritize_risk"
                 and item.get("result", {}).get("status") in {"insufficient_evidence", "no_findings"}]
    if risk_gaps and _UNSUPPORTED_RISK_CLAIM.search(answer or ""):
        return (
            "A risk category or priority was not assigned for at least one package because the risk tool lacked sufficient evidence. "
            "Review the successful OSV lookup results and tool statuses shown below. Do not infer a risk ranking from this response; "
            "request prioritization again after a successful exact-version lookup, and have an analyst review the advisory evidence.",
            True,
        )
    return answer, False
