# Analyst workflow

## Purpose

This workflow describes the intended analyst experience for the AI Powered Software Supply Chain Security Operations Copilot. It is a Phase 1 design, not a claim that the application features already exist.

## Main path

```text
Analyst provides project input
          |
          v
Discover supported manifests / inventory
          |
          v
Parse and normalize package identities
          |
          v
Validate names, versions, and source context
          |
          v
Build dependency relationships when available
          |
          +------------------------------+
          |                              |
          v                              v
Query vulnerability sources       Retrieve curated guidance
          |                              |
          +--------------+---------------+
                         v
             Normalize evidence and provenance
                         |
                         v
             Rank findings with visible rationale
                         |
                         v
       Generate an evidence-grounded explanation (optional)
                         |
                         v
             Present report and limitations
                         |
                         v
               Analyst decides what to do
```

## Steps and responsibilities

### 1. Provide input

The analyst selects a project directory or supplies a supported manifest, lockfile, or dependency inventory. The analyst may add project context such as environment and a question. The interface states which file types are supported and which data will be sent to external services.

### 2. Discover and parse

The ingestion component locates only supported dependency files, parses package/version data, and records the source file and parse status. Unsupported or malformed files produce actionable messages. Partial parsing is labeled and never silently treated as complete.

### 3. Normalize and validate

The validation component canonicalizes package identifiers and versions for downstream matching. It rejects malformed values and flags ambiguous identities. The report retains the original identifier alongside any normalized value so an analyst can audit matching.

### 4. Build dependency context

The graph component represents direct and transitive relationships available from the supplied lockfile or other trusted input. Each relationship retains provenance. Missing edges remain unknown; the system does not invent a dependency path or depth.

### 5. Gather vulnerability evidence

The lookup component queries configured advisory sources. Each returned record is associated with its source, retrieval time, affected package/version range, advisory identifier, and severity when provided. Errors, rate limits, and source coverage limitations are retained as report status.

### 6. Retrieve security guidance

The retrieval component searches a curated knowledge base for relevant remediation guidance or security standards. Retrieved documents are supporting context, not a replacement for authoritative package advisories. The report identifies the document/source used.

### 7. Prioritize findings

A transparent prioritization layer combines available evidence such as severity, exploit evidence, dependency exposure, and dependency depth. It explains which factors were available and which were missing. Any later ML score is shown separately from rule-based evidence and is labeled experimental until evaluated.

### 8. Generate explanation

An LLM may summarize the structured findings and retrieved guidance into an analyst-oriented explanation. It receives only the minimum relevant context. Its output must distinguish evidence from interpretation and link claims to provided records. If generation fails or adds unsupported detail, structured findings remain available and the unsupported explanation is suppressed or flagged.

### 9. Review and decide

The analyst reviews findings, evidence, source freshness, uncertainty, and recommendations. The analyst owns remediation and release decisions. The prototype does not edit files, create pull requests, install packages, or deploy changes.

## Alternate and failure paths

- **No usable input:** stop analysis and explain supported input requirements.
- **Partial input:** analyze the valid subset only if the report prominently marks coverage as partial.
- **Ambiguous package match:** preserve candidate identities and ask for review rather than selecting silently.
- **Source unavailable:** continue with available sources and show an explicit incomplete-source notice.
- **No advisory result:** state only that the queried sources returned no result.
- **No graph data:** report package-level evidence without claiming direct/transitive status.
- **No matching knowledge:** provide no document-backed recommendation; general suggestions must be labeled as such.
- **LLM unavailable:** present structured evidence without generated summary.
- **Risk model not ready:** omit model score and use explainable evidence-based ordering.

## Data handling and trust boundaries

- Dependency inputs are treated as untrusted data and parsed with bounded, format-aware readers.
- Secrets, source code, and unrelated files are outside the required analysis input and should not be sent to external services.
- External API requests are limited to package identifiers, versions, and necessary context.
- API keys are loaded from local environment configuration and never included in logs or reports.
- Advisory records and curated documents are evidence; LLM output is interpretation.
- The analyst is the final decision-maker for all remediation.

## User-visible report

The report should include:

- Project/input identity and analysis time.
- Number of dependencies analyzed and coverage/parse status.
- Findings grouped or sorted by priority.
- Package name/version, direct/transitive status, and dependency path when known.
- Advisory identifier, severity, affected-version information, source, and retrieval time.
- Exploit evidence and guidance only when supported by a cited source.
- Prioritization rationale, uncertainty, missing sources, and limitations.
- Suggested analyst follow-up, clearly separated from automated remediation.
- A reminder that the copilot provides decision support and did not modify the project.
