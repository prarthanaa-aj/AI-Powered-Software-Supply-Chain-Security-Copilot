"""A deterministic, intentionally limited Phase 2 baseline."""


def rule_based_response(question: str) -> str:
    """Return a fixed response based on a few keywords, without an LLM."""
    text = question.casefold().strip()
    if any(word in text for word in ("dependency", "dependencies", "requirements", "package")):
        return (
            "Baseline: I can only give a fixed dependency-analysis response. "
            "Provide a pinned Python requirements.txt file for local parsing. "
            "I cannot look up current vulnerabilities or reason across evidence yet."
        )
    if any(word in text for word in ("vulnerability", "cve", "risk", "secure")):
        return (
            "Baseline: I cannot retrieve current vulnerability evidence or explain "
            "risk. This rule-based version does not understand security context."
        )
    return (
        "Baseline: I recognize only a few keywords and return fixed responses. "
        "I cannot understand the request or analyze security evidence."
    )
