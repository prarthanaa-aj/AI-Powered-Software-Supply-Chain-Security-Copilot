# Phase 8: Local deployment and telemetry

## Run the interface

From the repository root with `.venv` active:

```powershell
streamlit run app/ui/streamlit_app.py
```

The interface accepts a UTF-8 pinned Python requirements file, an analyst question, and a RAG on/off option. It displays the response, parsed evidence, tool events, source status, latency, and the human-review reminder. The LLM receives parsed dependency names/versions rather than raw manifest comments.

## Telemetry

The app returns per-analysis latency, LLM status, tool events, and whether an answer guardrail fired. `app/telemetry.py` writes minimal JSONL events to ignored `logs/events.jsonl`; it excludes questions, manifests, advisory payloads, and credentials. The LLM client logs only model, timing, and token counts. UI errors show the exception type rather than environment or secret values.

This is a local prototype, not a hardened multi-user deployment. The persistent preference file is local to the workspace.

A final local Streamlit startup smoke check succeeded; `/_stcore/health` returned `ok`. The app process was stopped after verification.
