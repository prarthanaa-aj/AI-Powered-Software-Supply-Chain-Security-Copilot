# Engineering and product justification

## Product decision

Project Genome frames dependency review as evidence about a supplied project, not simply a package/version lookup. The interface connects manifest declarations, statically observed imports, returned OSV advisories, local security guidance, contextual prioritization, and analyst review. Unknown relationships remain unknown; static imports are not runtime reachability.

## LangChain and Vocareum

LangChain create_agent provides tool selection and bounded orchestration for the existing analysis tools. Custom Python tools retain responsibility for parsing, exact-version lookups, graph summaries, risk checks, limits, and recovery. The model explains evidence but is not an authority over it.

The existing OpenAI-compatible transport remains pointed at Vocareum using VOC_API_KEY, VOC_BASE_URL, and VOC_MODEL. This preserves the configured endpoint and avoids a provider migration. Live model use depends on credentials and service availability.

## Vulnerability intelligence and RAG

OSV is queried for exact package/version evidence and remains distinct from the locally authored guidance corpus. RAG supplies general security guidance; it cannot establish that the project contains a vulnerability. Project input and source evidence take precedence over advisory records, which take precedence over guidance, which takes precedence over generated interpretation.

Retrieval uses chunked local text, curated concept-expanded sparse vectors, cosine ranking, and fallback matching. This avoids an external embedding service, but the corpus and relevance rubric are small and do not establish broad semantic retrieval quality.

## Contextual risk instead of ML

No independently labeled project-level risk dataset is available. The system therefore uses a transparent weighted heuristic and exposes evidence coverage, drivers, and missing dimensions. Unknown dimensions are not silently fabricated. The score is an analyst prioritization aid, not a validated prediction or probability.

Static imports supply limited project context and blast-radius evidence. They do not prove that a vulnerable code path executes. Supply-chain trust, deployment exposure, exploitability, and complete transitive relationships remain unknown unless reliable evidence is added.

## Safety and tradeoffs

The application is decision support only. It has no file-edit, package installation, arbitrary command, commit/push, or deployment capability. What-if analysis performs an exact-version evidence lookup and recalculates a hypothetical result without changing project files. Analyst-provided development-only feedback is explicitly labeled unverified and session-scoped.

The prototype trades broad format coverage for bounded requirements parsing and AST analysis that are inspectable. It is local-first and has repeatable test/evaluation commands, but it is not a cloud deployment or production security control.

## Verification basis

Current local evidence is summarized in docs/test_results.md. Automated tests and curated offline evaluations establish regression behavior for tested cases only; they do not establish real-world vulnerability detection quality or LLM answer accuracy.
