"""Deterministic limits for inputs and allowed tool operations."""
MAX_QUESTION_CHARS = 4000
MAX_TOOL_CALLS = 6
MAX_TOOL_RESULT_CHARS = 7000


def validate_question(question: str) -> str:
    question = (question or "").strip()
    if not question:
        raise ValueError("Enter a question")
    if len(question) > MAX_QUESTION_CHARS:
        raise ValueError(f"Question exceeds {MAX_QUESTION_CHARS} characters")
    return question


def limit_tool_payload(value: str) -> str:
    return value[:MAX_TOOL_RESULT_CHARS]
