"""Feedback-to-preference adaptation with explicit opt-in storage."""
from app.agent.memory import LongTermMemory


class FeedbackStore:
    def __init__(self, memory: LongTermMemory | None = None):
        self.memory = memory or LongTermMemory()

    def record(self, user_id: str, rating: str) -> str:
        mapping = {"too_long": "concise", "too_short": "detailed"}
        if rating not in mapping:
            raise ValueError("Feedback must be too_long or too_short")
        return self.memory.update(user_id, mapping[rating])[user_id]

    def preference(self, user_id: str) -> str:
        return self.memory.read().get(user_id, "balanced")

    def clear(self, user_id: str | None = None) -> None:
        self.memory.reset(user_id)
