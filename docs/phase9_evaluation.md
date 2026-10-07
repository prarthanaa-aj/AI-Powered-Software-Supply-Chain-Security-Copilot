# Phase 9: Evaluation and failure analysis

## Offline evaluation

`evaluation/test_cases.json` contains 100 deterministic cases: 20 each for requirements parsing, heuristic risk classes, dependency-graph depth, input guardrails, and local retrieval. `evaluation/evaluation_runner.py` writes a detailed result to ignored `evaluation/results/latest.json`.

The automated test suite also covers OSV response parsing with a mocked response, invalid lookup inputs, bounded RAG chunking, experimental model training requirements, preference memory, empty-result language guardrails, and invalid tool-call recovery.

## Live prompt comparison

Three prompts were run on the same three evidence scenarios (nine Vocareum calls). Prompt C was selected for evidence structure. Its raw output initially overclaimed from an empty OSV result; the deterministic response guardrail was added and the comparison rerun with post-processing. This identifies a real model failure and a code-level mitigation instead of treating prompt wording as a complete safety control.

## Measures and limits

The offline suite measures deterministic component behavior, not live vulnerability accuracy or open-ended answer quality. It does not establish advisory-source completeness, retrieval quality beyond the included corpus, or validity of an ML model. Tool-selection accuracy and recommendation quality require a separately labeled evaluation set and human review. The optional logistic model has no project-specific training dataset yet and remains experimental.

### Prompt comparison summary

The recorded comparison uses a shared fixed set of three synthetic evidence cases and three prompt variants (A basic, B structured, C security analyst), for nine Vocareum calls. The artifact stores each raw answer, guarded answer, and whether the deterministic empty-result guardrail changed it.

| Variant | Prompt intent | Cases | Guardrail rewrites | Qualitative result |
| --- | --- | ---: | ---: | --- |
| A — basic | Clear, concise answer | 3 | 1/3 | Shortest; least consistent section/evidence structure |
| B — structured | Fixed findings/evidence/priority/follow-up/limits sections | 3 | 1/3 | More complete structure; still requires evidence review |
| C — security analyst | Decision support, evidence boundaries, uncertainty, no invented claims | 3 | 1/3 | Most explicit evidence/uncertainty structure; selected default |

The rewrite count is deterministic handling of the empty-lookup case, not a prompt quality score. Prompt C was selected by qualitative review, not a blinded or independently rated study. Raw output may still overstate unsupported details; compare it with supplied evidence. The exact responses are in ignored `evaluation/results/prompt_comparison.json`.

## Failure analysis

The first evaluation attempt scored 80/100 because all 20 retrieval cases compared a Windows source path against a slash-normalized expected path. The underlying retrieval unit test passed. The runner was corrected to normalize separators, after which the full offline suite passed. A separate prompt comparison found unsafe empty-result wording; `app/security/response_guardrails.py` now replaces that wording when a successful OSV lookup returns no records.

## Latest recorded results (2026-10-07)

| Check | Result |
| --- | ---: |
| Automated tests | 74 passed (latest local suite) |
| Offline deterministic cases | 100/100 passed |
| Requirements parsing | 20/20 |
| Heuristic risk classes | 20/20 |
| Dependency graph depth | 20/20 |
| Input guardrails | 20/20 |
| Local retrieval | 20/20 |
| Prompt comparison | 9 Vocareum responses (3 prompts × 3 scenarios) |
| End-to-end tool loop | Vocareum selected OSV lookup; tool returned success |
| Live OSV sample query | `requests==2.31.0`: six records at check time |
| Streamlit health endpoint | `ok` |

The empty-result guardrail was tested against positive safety claims and fabricated advisory IDs. The first full evaluation had 80/100 because the retrieval expected path used forward slashes while Windows returned backslashes; path normalization fixed all 20 cases. These pass rates cover the project’s deterministic fixtures only and should not be interpreted as production security accuracy.

The suite also verifies a two-turn memory interaction and checks the concise/detailed instruction before and after feedback.

## Hardening verification (2026-10-07)

The latest local run reports 74 passing automated tests, 100/100 deterministic component cases, and 12/12 RAG rubric cases. The separate risk-model validator reports `insufficient_data` with zero labeled rows and emits no model metrics. Tests cover pre-LLM refusal, evidence-bound risk scoring, CVSS v3.1 examples, bounded duplicate tool calls, project source-import analysis, risk boundaries, non-mutating simulation, and a LangChain executor selecting and running the dependency scanner.

The Project Genome UI was exercised with a fixture result through Streamlit AppTest: all nine views rendered without application exceptions, including the evidence graph SVG and mixed scored/unscored dependencies. A separate local Streamlit server health check returned HTTP 200 with body `ok`. These are local UI checks, not a fresh live Vocareum/OSV analysis.

Retrieval maps curated domain synonyms into shared sparse-vector concepts, applies cosine ranking and an overlap threshold, and retains TF-IDF as a fallback. The twelve-case RAG rubric is a small, manually authored relevance/abstention check rather than an independent benchmark. A separate paired live RAG-on/off answer capture is in `evaluation/results/rag_ablation.json`; it is descriptive, not proof of quality improvement.

## Checklist evidence map

| Requirement | Current evidence | Remaining limitation |
| --- | --- | --- |
| Agent framework | CLI, Streamlit, and live demo use LangChain `create_agent`; custom tools and guardrails remain domain code | One live provider run is recorded; broad tool-selection quality still needs analyst-rated cases |
| Prompt variants on same set | 3 prompts × 3 fixed cases in `prompt_comparison.json` | Tiny qualitative set; no blinded human ratings |
| RAG, relevance, missing knowledge | Chunked cosine search over curated sparse concept vectors; 12-case rubric and one paired live RAG on/off answer | Not pretrained neural embeddings; small corpus and no generated-answer quality score |
| Tool choice / failed call recovery | Real tool-selection trace in `live_demo.json`; invalid-input local trace and tests | Recovery model turn in offline artifact is simulated |
| Loop prevention / planning | Configured 8-step and 6-tool-call limits; planner and regression tests | Limit test, not a user-facing forced live loop trace |
| Memory / adaptive behavior | Session bounded context, preference storage/reset; local before/after fake-LLM trace | Prompt change is shown; quality improvement is not independently rated |
| Safety / graceful failure / telemetry | Pre-LLM refusal tests, empty-result guardrail, local unavailable-provider fallback, filtered JSONL events | Local prototype; no hosted monitoring, alerting, or multi-user deployment |
| Deployment reproducibility | Pinned project requirements and documented local Streamlit launch | No cloud target, cloud deployment, or hosted operations evidence |
| Change explanation / root cause | `docs/failure_analysis.md` records observations, causes, mitigations, and limits | No independent reviewer sign-off or broad before/after user study |
| ML quality metrics | Group-disjoint validator and label template | No independent labels; status correctly remains `insufficient_data` |

For a short reviewer walkthrough of the evidence and exact expected checks, see `docs/demo_script.md`. Distinguish actual provider/OSV evidence from simulated control-flow evidence explicitly.

One real live demo through LangChain `create_agent`, the configured Vocareum endpoint, and OSV is saved in ignored `evaluation/results/live_demo.json`; a live malformed-input recovery is in `live_demo_tool_recovery.json`, and the duplicate-call-guard defect is preserved in a before-fix trace. The first runs also revealed a BOM parsing defect and unsupported scoring behavior. The current implementation parses valid CVSS v3.1 vectors using FIRST's published formula; the live report records the resulting evidence-bound scores. Offline traces for safety, memory, and local RAG controls are in `evaluation/results/local_demo_traces.json`; simulated portions are labeled.

