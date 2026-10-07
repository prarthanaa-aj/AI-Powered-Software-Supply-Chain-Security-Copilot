"""Conversation state and bounded short-term context."""
from dataclasses import dataclass, field


@dataclass
class AgentState:
    session_id: str
    history: list[dict] = field(default_factory=list)
    tool_events: list[dict] = field(default_factory=list)
    step_count: int = 0

    def reset(self) -> None:
        self.history.clear()
        self.tool_events.clear()
        self.step_count = 0


class ShortTermMemory:
    def __init__(self, max_messages: int = 12):
        self.max_messages = max_messages
        self._sessions: dict[str, list[dict]] = {}

    def get(self, session_id: str) -> list[dict]:
        return list(self._sessions.get(session_id, []))

    def append(self, session_id: str, role: str, content: str) -> None:
        messages = self._sessions.setdefault(session_id, [])
        messages.append({"role": role, "content": content[:6000]})
        self._sessions[session_id] = messages[-self.max_messages:]

    def reset(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
