# Phase 6: Planning and memory

The deterministic planner in `app/agent/planner.py` identifies a broad intent and suggests relevant tools. It is a hint to the LangChain agent, not a substitute for tool results. LangChain dynamically selects registered tools; the agent applies the configured graph recursion limit, a six-call tool limit, and duplicate-call blocking.

Short-term memory retains at most 12 messages per session, with each message truncated to 6,000 characters; it is process-local and is lost on process restart. Long-term memory is a local answer-length preference (`concise` or `detailed`) stored in the ignored `data/processed/preferences.json` file until cleared or overwritten. It is keyed by the app session/user identifier, which is not a verified identity. API keys and analyzed manifests are not stored in memory. The UI reset action clears conversation state and, when requested, the current preference.

A multi-turn session reuses recent question/answer context. Memory can be disabled with `MEMORY_ENABLED=false`.

The local capture `evaluation/results/local_demo_traces.json` records fake-LLM prompt context checks: default, feedback “too short” → detailed instruction, “too long” → concise instruction, and reset → empty preference. It verifies changed prompt instructions and context retention, not a guaranteed response-quality improvement.

The planner proposes candidate tools; it does not enforce a separate fixed sequence. LangChain can choose a different tool sequence or none. Graph recursion is bounded by the configured step budget and tool execution is capped at 6 calls. Repeated identical tool inputs are blocked. Regression tests cover the guard; a real multi-tool live run is not evidence that the loop limit itself was triggered.
