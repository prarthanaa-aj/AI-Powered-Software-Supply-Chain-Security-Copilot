# Test and verification results

## Latest local results

| Check | Result | Interpretation |
|---|---:|---|
| Automated pytest suite | 74 passed | Component and regression tests, including Project Genome and simulation |
| Deterministic evaluation | 100/100 | 20 each for scanning, risk categories, graph behavior, safety, and retrieval |
| RAG relevance/abstention rubric | 12/12 | Nine answerable and three unanswerable curated queries |
| Streamlit result-view AppTest | 9 views, 0 app exceptions | Fixture result rendered the evidence graph and mixed scored/unscored dependencies |
| Streamlit health endpoint | HTTP 200, body "ok" | Local server startup check |
| Python compilation | Passed | Updated analyzer, risk engine, UI, prompt, and orchestrator modules |

## Scope

The pytest and deterministic suites use local fixtures/mocks where applicable. The Streamlit result-view smoke test was seeded with fixture analysis data; it is not a live security finding. The latest verification did not make live Vocareum or OSV calls. These results do not measure advisory coverage, production detection accuracy, or open-ended LLM quality.

## Reproduction

From the repository root, run:

    .\.venv\Scripts\python.exe -B -m pytest -q --basetemp=.pytest-tmp
    .\.venv\Scripts\python.exe -B -m evaluation.evaluation_runner
    .\.venv\Scripts\python.exe -B -m evaluation.rag_evaluation

Machine-readable offline reports are written under evaluation/results/, which is Git-ignored and must be selected explicitly for packaging.
