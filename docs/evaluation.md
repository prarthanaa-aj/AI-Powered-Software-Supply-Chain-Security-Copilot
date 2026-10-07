# Evaluation Protocol and Results

## Commands

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp=.pytest-work
.\.venv\Scripts\python.exe -B -m evaluation.evaluation_runner
.\.venv\Scripts\python.exe -B -m evaluation.rag_evaluation
.\.venv\Scripts\python.exe -B -m evaluation.validate_risk_model data/risk_labels.csv
.\.venv\Scripts\python.exe -B -m evaluation.run_live_demo
.\.venv\Scripts\python.exe -B -m evaluation.run_rag_ablation
.\.venv\Scripts\python.exe -B -m evaluation.capture_local_demos
```

The global Windows temporary directory may be unavailable to pytest in a restricted environment; `--basetemp=.pytest-work` keeps temporary test files in this repository.

## Interpretation

The deterministic suite exercises parser, heuristic, graph, input-bound, and retrieval fixtures. Additional tests check prohibited-action refusal before any model call, risk evidence binding, unanswerable retrieval, CVSS v3.1 example vectors, and a deterministic group-disjoint risk-validation holdout path. Mocked OSV and fake LLM cases validate orchestration logic without claiming live provider behavior.

The RAG rubric is intentionally small and manually authored (nine answerable, three unanswerable). It validates local retrieval relevance proxies and abstention, not generated answer grounding. The sparse vector implementation maps curated domain synonyms to shared dimensions; it is not a pretrained neural embedding model. The ML validation tool refuses to emit metrics without enough labeled examples. No project-specific independent risk labels are currently supplied; therefore there is no valid project ML score. Do not infer security accuracy from fixture pass rates or synthetic test data. Its holdout is group-disjoint using `group_id`, and records hashes of split group IDs so separation can be audited without exposing group names.

Generated JSON reports are in ignored `evaluation/results/`. They are reproducible local artifacts, not proof of external validity or an independent benchmark.

The live demo uses LangChain `create_agent` with the configured Vocareum provider and external OSV service, and writes `live_demo.json`. It records one time-specific interaction only. A single successful trace demonstrates the integrated path; it is not a measure of model reliability.

`run_rag_ablation` makes two live calls with the exact same question, one with local retrieval and one without, and writes both answers and retrieved source paths to ignored `rag_ablation.json`. The current artifact shows a difference in answer text and source context; one pair does not demonstrate an improvement in answer quality.

`capture_local_demos` writes `local_demo_traces.json` for the safety refusal, invalid-tool recovery, feedback/memory, and with/without-RAG scenarios. The recovery and memory model responses are simulated. These are repeatable control-flow demonstrations, not live LLM evidence.
