# Capstone project report (implementation status)

## Project

AI-Powered Software Supply-Chain Security Operations Copilot — a decision-support prototype for analysts reviewing Python package dependencies.

## Delivered phases

- **Phase 0:** Vocareum Chat Completions connectivity verified with `VOC_API_KEY`.
- **Phase 1:** Problem framing, workflow, and architecture defined.
- **Phase 2:** Deterministic keyword baseline retained for comparison.
- **Phase 3:** Vocareum LLM adapter, three prompt variants, and nine-request prompt comparison. Responses API support returned HTTP 400 at the configured endpoint; Chat Completions is used.
- **Phase 4:** Local chunked concept-expanded sparse-vector retrieval with source paths, an on/off demo control, TF-IDF fallback, and a 12-case relevance/abstention rubric. It is not a pretrained neural embedding system.
- **Phase 5:** Requirements scanner, OSV lookup, dependency graph, evidence-bound transparent risk heuristic, and bounded tool calling. The optional logistic learner is excluded from the agent's production decision path pending independent labels and validation.
- **Phase 6:** Planner, bounded short-term context, local preference memory, and reset.
- **Phase 7:** Feedback adapts answer length only.
- **Phase 8:** Streamlit UI and privacy-limited telemetry.
- **Phase 9:** Offline evaluation, tests, prompt comparison, and failure analysis.
- **Project Genome extension:** Bounded Python AST import analysis, manifest drift signals, evidence-only SVG graph, contextual risk dimensions with unknowns, exact-version what-if lookup, and session-only analyst context correction.
- **Hardening:** Deterministic pre-LLM refusal for prohibited operations; risk calculations bind only to manifest and same-run OSV evidence; separate RAG answerable/unanswerable rubric; holdout model validator; expanded privacy-filtered latency/token telemetry; five repeatable demo scenarios; LangChain `create_agent` orchestration with Vocareum and bounded custom tools.

## Evaluation summary

The offline evaluation contains 100 deterministic cases across five component categories. Its latest machine-readable result is `evaluation/results/latest.json`; the human-readable summary is in `docs/phase9_evaluation.md`. Automated tests include separate parser, graph, OSV parsing, retrieval, risk, memory, safety, and tool-recovery checks.

Live OSV lookups and LLM answers depend on external service state and are not equivalent to validated vulnerability-detection performance. The initial risk ordering is a heuristic. The optional supervised model has not been trained or validated on a project-specific labeled dataset.

## Remaining evidence needed for a production claim

- Add and validate lockfile parsing for transitive dependency paths.
- Curate a larger authoritative knowledge base.
- Establish a licensed, representative labeled dataset and independent model evaluation.
- Evaluate live tool selection and answer quality with analyst-rated cases.
- Review privacy, retention, source terms, operational monitoring, and deployment controls for the intended environment.

## Final implementation verification

- 74 automated tests passed in the latest local suite.
- 100/100 offline deterministic evaluation cases passed (20 each for parsing, risk heuristic categories, graph depth, input guardrails, and retrieval).
- Three prompt variants were compared over three scenarios; the role/evidence prompt is selected with deterministic empty-result post-processing.
- One live LangChain/Vocareum run selected OSV lookup and risk prioritization for all three sample dependencies; OSV advisories and heuristic scores are recorded with the run timestamp.
- Streamlit started locally and its health endpoint returned `ok`.
- Streamlit AppTest rendered all nine Project Genome result views without application exceptions using local fixture evidence.

These are prototype checks. They do not validate vulnerability coverage, model quality, or the optional ML scorer for production use.

The RAG rubric currently reports 12/12 on nine answerable and three unanswerable queries. This small hand-authored set and project-authored corpus do not establish broad retrieval quality; retrieval uses an authored concept map rather than pretrained neural embeddings. The risk model validation report currently returns `insufficient_data` with zero labeled rows, as intended; no predictive ML result is claimed.

Live LangChain/Vocareum/OSV analysis and malformed-input recovery are recorded in `evaluation/results/live_demo.json` and `live_demo_tool_recovery.json`. A paired live RAG on/off answer is in `rag_ablation.json`. Earlier traces preserve the BOM parsing issue, unsupported scoring behavior, and duplicate-call-guard bug. OSV's CVSS v3.1 vectors are parsed using the FIRST base-score equations and checked against published examples. Offline safety, memory, and RAG traces are stored in `local_demo_traces.json`; simulated portions are labeled.

