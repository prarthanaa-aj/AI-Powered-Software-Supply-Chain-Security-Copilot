# Phase 2: Python baseline

## Purpose

Establish a deterministic starting point before adding retrieval, tools, or an LLM. `app/baseline.py` maps a few keywords to fixed responses and makes no network requests.

## Demonstrated limitations

- It recognizes isolated keywords rather than intent or context.
- It cannot parse or validate a manifest in response to a natural-language request.
- It cannot retrieve current vulnerability data.
- It cannot connect findings to dependency paths or explain evidence.
- Similar questions can only receive the same canned response.

These limitations motivate the later stages: structured tools provide verifiable data, retrieval supplies curated guidance, and the LLM explains evidence in natural language.

## Run

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m app.baseline_cli "Analyze my dependencies"
```

The baseline is retained as a comparison point; later phases do not silently replace its behavior or claim that it has reasoning capabilities.
