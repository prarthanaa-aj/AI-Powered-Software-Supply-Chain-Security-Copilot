# Local Deployment and Telemetry

This remains a local Streamlit prototype; cloud deployment and hosted operations have not been configured or verified. Configure `VOC_API_KEY` and, if required, `VOC_BASE_URL` and `VOC_MODEL` in the existing ignored `src/.env`; do not commit credentials. Vocareum remains the active provider. The LangChain integration uses an OpenAI-compatible transport pointed at the existing Vocareum endpoint; it does not switch providers.

The verified local environment is Python 3.14.8. `requirements-lock.txt` records its installed package versions for repeatable setup. Install with `python -m pip install -r requirements-lock.txt`. To resolve fresh versions for another environment, use `requirements.txt`; regenerate and review the lock file after changing dependencies with `python -m pip freeze > requirements-lock.txt`.

Run from the repository root:

```powershell
.\.venv\Scripts\Activate.ps1
streamlit run app/ui/streamlit_app.py
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for that terminal only, or invoke `streamlit` through `.\.venv\Scripts\streamlit.exe`.

Minimal JSONL telemetry is written to ignored `logs/events.jsonl`. Events include run status, total/LLM/RAG latency, model call count, token counts when the provider returns usage, step/tool counts, tool status, and error type. Upload and UI analysis rejections/failures record their event and exception type. Questions, uploaded manifest contents, tool payloads, and secrets are filtered out. This is local operational logging, not a hosted monitoring or multi-user security setup. Provider usage fields may be absent; missing values are recorded as zero for the call-level counters.
