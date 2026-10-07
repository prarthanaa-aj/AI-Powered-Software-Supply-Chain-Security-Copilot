"""Small deterministic planner that provides intent hints to the LLM."""


def plan_question(question: str, dependency_count: int = 0) -> dict:
    text = question.casefold()
    tools = []
    if any(word in text for word in ("vulnerability", "cve", "advisory", "exploit", "affected")):
        tools.append("lookup_vulnerability")
    if any(word in text for word in ("transitive", "direct", "path", "graph", "dependency tree")):
        tools.append("summarize_dependency_graph")
    if any(word in text for word in ("priority", "prioritize", "risk", "score", "urgent")):
        tools.append("prioritize_risk")
    if any(word in text for word in ("guidance", "recommendation", "what should", "best practice", "standard")):
        tools.append("search_security_guidance")
    return {
        "intent": "dependency_analysis" if dependency_count or any(w in text for w in ("dependency", "package", "manifest")) else "security_question",
        "dependency_count": dependency_count,
        "suggested_tools": tools,
        "limit": "Use only available evidence; the language model may choose a different allowlisted tool or none.",
    }
