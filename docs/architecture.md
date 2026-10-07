# System architecture
Current Project Genome architecture is illustrated in [architecture.svg](architecture.svg). The diagram reflects implemented inputs, AST analysis, OSV/RAG paths, risk calculation, UI, simulation, and feedback. The sections below retain the original phase design notes.


## Architecture goals

- Separate deterministic parsing and evidence collection from probabilistic language generation.
- Preserve provenance from input file or external source through the final report.
- Make partial coverage, uncertainty, and failures visible.
- Keep the system advisory: no automatic project modifications or deployment actions.
- Allow API providers and implementations to change behind a narrow LLM client boundary.

## High-level architecture

```text
+-------------------------------+
| Analyst interface             |
| project input + question      |
+---------------+---------------+
                |
                v
+-------------------------------+
| Workflow / orchestration      |
| state, status, error handling  |
+---+-----------+-----------+---+
    |           |           |
    v           v           v
 Ingestion   Validation   Configuration
    |           |
    +-----+-----+
          v
+-------------------------------+
| Dependency inventory + graph  |
+---------------+---------------+
                |
       +--------+---------+
       |                  |
       v                  v
+--------------+   +-----------------+
| Advisory     |   | Curated guidance|
| connectors   |   | retrieval       |
+------+-------+   +--------+--------+
       |                    |
       +---------+----------+
                 v
+--------------------------------+
| Evidence normalization and     |
| provenance-aware prioritizer   |
+----------------+---------------+
                 |
       +---------+-----------+
       |                     |
       v                     v
 Optional risk model   LLM client adapter
       |                     |
       +----------+----------+
                  v
+--------------------------------+
| Report / analyst review        |
| evidence, rationale, limits    |
+--------------------------------+
```

## Component responsibilities

| Component | Responsibility | Trust and output rules |
| --- | --- | --- |
| Analyst interface | Accept project input/context and display status/report | States supported formats, external data use, and decision-support limits. |
| Workflow/orchestrator | Coordinate steps, track partial completion, route recoverable errors | Never reports success for a step that failed or was skipped. |
| Ingestion | Discover and parse supported dependency files | Reads only supported inputs; records file and parse provenance. |
| Validation/normalization | Validate package identifiers and versions | Keeps original identifiers; flags ambiguous or invalid values. |
| Dependency graph | Represent known package relationships and paths | Stores edge provenance; unknown relationships remain unknown. |
| Advisory connectors | Query configured vulnerability/advisory sources | Preserve raw source identity, retrieval time, affected ranges, and errors. |
| Knowledge retrieval | Retrieve curated security documents | Returns document references and relevant passages; does not establish vulnerability existence. |
| Evidence normalizer | Convert source records into a stable internal schema | Does not discard conflicts or source metadata. |
| Prioritizer | Sort findings by transparent, documented factors | Explains available/missing factors; separates rules from model output. |
| Risk model (later phase) | Estimate risk from validated features and data | Disabled or explicitly experimental until evaluated; never sole basis for a recommendation. |
| LLM client | Explain structured evidence and retrieved context | Receives minimal context; cannot create authoritative findings or perform remediation. |
| Report builder | Present findings, evidence, caveats, and next steps | Every evidence claim links to supplied records; identifies partial coverage. |
| Configuration/secrets | Load endpoint/model settings and credentials | Secret values are not logged or committed; `.env` is ignored by version control. |

## Data flow and core records

The workflow passes structured records rather than relying on free-form LLM text as its internal state.

- **Dependency:** ecosystem, original name/version, normalized name/version, direct/transitive status when known, input source, and validation status.
- **Relationship:** parent and child package identifiers, relationship type, and source/provenance.
- **Advisory evidence:** source name, advisory identifier, package/ecosystem, affected range, severity/CVSS when provided, exploit evidence when provided, retrieval timestamp, source URL/reference, and source status.
- **Knowledge passage:** document identifier, source, revision/date when known, and retrieved excerpt/reference.
- **Prioritized finding:** linked dependency and evidence IDs, ranking factors, missing information, uncertainty, and optional separately labeled model score.
- **Report:** analysis ID/time, input coverage, source status, findings, narrative, limitations, and human-review status.

## LLM and Vocareum integration boundary

The application uses an LLM client interface so orchestration, evidence handling, and reporting do not depend directly on a provider-specific request shape. The configured endpoint and `VOC_API_KEY` remain the project’s Phase 0 setup. The existing connectivity check verified a Vocareum-compatible Chat Completions request. It did not verify Responses API support.

The configured Vocareum endpoint was verified with Chat Completions. Keep `VOC_API_KEY`, `VOC_BASE_URL`, `VOC_MODEL`, and the Chat Completions adapter for this project unless the user explicitly changes the provider requirement. Model and endpoint remain configurable; the key remains secret.

The LLM receives a bounded prompt containing structured findings and retrieved evidence. It may summarize, explain, and propose analyst follow-up. It may not be treated as an advisory source, and it may not edit or execute project files.

## Security, privacy, and failure design

- Treat uploaded manifests and package metadata as untrusted input.
- Apply file-size and parsing bounds in implementation phases.
- Avoid sending source code or complete project contents when package metadata suffices.
- Do not log credentials, full sensitive inputs, or unnecessary prompt contents.
- Keep external source failures attached to analysis status so “no result” cannot be confused with “source unavailable.”
- If LLM generation fails, return structured evidence without a generated explanation.
- If model scoring is unavailable or unevaluated, omit it or mark it experimental.
- Never change source files, package state, or deployments automatically.

## Architectural decisions and open questions

### Decisions for the prototype

1. Decision-support only; the analyst retains remediation authority.
2. Structured evidence and provenance are the source of truth; LLM output is explanatory.
3. Parsing, validation, advisory lookup, graphing, retrieval, prioritization, LLM explanation, and presentation are separate responsibilities.
4. Retain `VOC_API_KEY` and the tested Vocareum endpoint configuration.
5. Keep the LLM API format behind an adapter because Phase 0 validated Chat Completions only.

### To resolve before implementation of the corresponding component

- Which dependency file formats are in the first supported release?
- Which advisory sources and terms/rate limits are acceptable?
- What curated documents are available and how will they be updated?
- What labeled data and baseline will validate an ML risk model?
- Does the configured Vocareum endpoint support the Responses API, or is Chat Completions the compatible route?
- What deployment environment and data-retention rules apply?

## Phase 1 completion checks

- The architecture has a named responsibility for each stage in the analyst workflow.
- Structured records retain package identity and evidence provenance.
- The report can distinguish no findings, missing data, and source failure.
- LLM explanation and any future ML score are separated from authoritative source evidence.
- All automated changes remain out of scope.
- Provider/API uncertainty is recorded accurately: Phase 0 verified Vocareum Chat Completions, not Responses API.
