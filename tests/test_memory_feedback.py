from app.agent.memory import LongTermMemory
from app.agent.feedback import FeedbackStore
from app.agent.state import ShortTermMemory


def test_short_term_memory_is_bounded_and_resettable():
    memory = ShortTermMemory(max_messages=2)
    memory.append("s", "user", "one"); memory.append("s", "assistant", "two"); memory.append("s", "user", "three")
    assert len(memory.get("s")) == 2
    memory.reset("s")
    assert memory.get("s") == []


def test_feedback_persists_only_supported_style(tmp_path):
    store = FeedbackStore(LongTermMemory(tmp_path / "prefs.json"))
    assert store.record("analyst", "too_long") == "concise"
    assert store.preference("analyst") == "concise"
    try:
        store.record("analyst", "unsafe")
        assert False
    except ValueError:
        pass
    store.clear("analyst")
    assert store.preference("analyst") == "balanced"
