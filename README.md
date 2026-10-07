# AI-Powered Software Supply-Chain Security Copilot

A decision-support prototype for analysts reviewing Python dependency risks. Project Genome combines pinned requirements, local static Python import analysis, OSV.dev lookups, local security guidance, a contextual heuristic risk index, and LangChain tool orchestration through the configured Vocareum-compatible endpoint. It never modifies the analyzed project.

## Status

The prototype includes the original Phase 0–9 workflow and the Project Genome extension. Read `docs/project_report.md` and `docs/project_genome.md` for scope, evaluation, and limitations. The architecture diagram is `docs/architecture.svg`.

## Environment and installation

The API key stays in `src/.env` under `VOC_API_KEY`. That file is ignored by Git. The root `.env.example` contains placeholders only.

For a reproducible install matching the verified Windows Python 3.14.8 environment, use the lock file:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-lock.txt
```

Use `requirements.txt` when resolving dependencies for another supported environment.

## Run the CLI

Rule-based Phase 2 baseline:

```powershell
.\.venv\Scripts\python.exe -m app.main --baseline "Analyze my dependencies"
```

Copilot with a sample project manifest:

```powershell
.\.venv\Scripts\python.exe -m app.main "Review the dependency risks and evidence" --requirements data/sample_projects/sample_project/requirements.txt
```

## Run the Streamlit app

```powershell
streamlit run app/ui/streamlit_app.py
```

Project Genome accepts supported requirements*.txt files and Python .py files for local static import analysis; paste input is also supported. It shows an evidence graph, declared-versus-observed import signals, contextual risk with unknown dimensions, and an OSV-backed hypothetical-version simulator. Current lookups go to OSV.dev. The LLM can call only allowlisted analysis tools. See [Project Genome scope and scoring](docs/project_genome.md) for supported formats and limitations.

## Evaluate

```powershell
.\.venv\Scripts\python.exe -B -m pytest -q -p no:cacheprovider --basetemp=.pytest-work
.\.venv\Scripts\python.exe -B -m evaluation.evaluation_runner
.\.venv\Scripts\python.exe -B -m evaluation.rag_evaluation
.\.venv\Scripts\python.exe -B -m evaluation.validate_risk_model data/risk_labels.csv
.\.venv\Scripts\python.exe -B -m evaluation.run_live_demo
.\.venv\Scripts\python.exe -B -m evaluation.run_rag_ablation
.\.venv\Scripts\python.exe -B -m evaluation.capture_local_demos
```

The evaluation is offline and deterministic; it does not claim live vulnerability coverage or LLM answer accuracy.

See [framework justification](docs/framework_justification.md), [methodology](docs/methodology.md), [risk labeling](docs/risk_labeling.md), [evaluation](docs/evaluation.md), [safety](docs/safety.md), [deployment](docs/deployment.md), [failure analysis](docs/failure_analysis.md), and [demo script](docs/demo_script.md) for current limits and repeatable scenarios. The risk validation command intentionally reports `insufficient_data` until you provide independently assigned labels in the documented CSV format.

The live demo command sends the sample manifest and question to the configured Vocareum endpoint and queries OSV; its response and tool trace are saved to ignored `evaluation/results/live_demo.json`.
The local demo command records safety, tool-recovery, feedback/memory, and RAG traces without contacting Vocareum; simulated LLM behavior is marked in the report.

## Safety and current limits

- Human review is required; no file modification, package installation, command execution, pull request, or deployment tools are available to the agent.
- Requirements files and Python source only; static import analysis does not prove runtime usage. Direct-versus-transitive status and complete transitive edges remain unknown without supported lock data.
- Advisory lookups are time-dependent. An empty OSV response is not evidence that a package is safe.
- Retrieval uses local concept-expanded sparse vectors and a small project-authored corpus. It is offline and includes synonym-based matching, but it does not use pretrained neural embeddings or establish production semantic-search quality.
- Risk scores are heuristics by default. Any trained logistic model is marked experimental and needs independent labeled-data evaluation.
- Vocareum Chat Completions works; a Responses API probe returned HTTP 400 for this endpoint.


Submission source materials: [problem framing](docs/problem_framing.md), [prompt comparison](docs/prompt_comparison.md), [test results](docs/test_results.md), [engineering/product justification](docs/engineering_product_justification.md), [setup](docs/setup.md), and [limitations](docs/limitations.md). PDF exports and UI screenshots are separate packaging tasks.
