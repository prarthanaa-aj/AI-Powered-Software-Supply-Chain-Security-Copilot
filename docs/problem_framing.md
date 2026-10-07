# Problem framing: AI-Powered Software Supply-Chain Security Copilot

## Persona

Security analyst or DevSecOps engineer reviewing a Python project's dependencies and deciding which evidence-backed signals need follow-up.

## Problem

Dependency scanners can report package/version advisories but often leave an analyst to connect those findings to the supplied project: which packages are declared, which are imported in the supplied source, what evidence supports an advisory, and what remains unknown. An empty database result can also be mistaken for proof of safety.

## Proposed solution

Project Genome combines supported requirements input, static Python import evidence, OSV advisory lookups, a local security-guidance retriever, and an evidence-weighted contextual risk index. It displays observed relationships, drift signals, missing evidence, and analyst review recommendations in a project-centered interface. A what-if view can look up an analyst-entered hypothetical version and compare evidence-derived scores.

The product asks: **How does a dependency relate to the supplied project evidence, what verified risk signal exists, what is unknown, and how would a hypothetical version lookup change the assessment?**

## Inputs and outputs

Supported inputs:

- requirements.txt, requirements-dev.txt, and requirements-prod.txt;
- Python .py source files for local static import analysis;
- an analyst question and optional exact hypothetical version.

Outputs:

- Project Genome graph with manifest declaration, static import, and returned advisory edges;
- dependency inventory, observed import links, and declared-versus-observed signals;
- OSV advisory evidence, statuses, and retrieval information when returned;
- contextual 0–100 heuristic score when evidence supports it, with risk drivers, evidence coverage, and unknown dimensions;
- potential source-to-advisory paths only when both source import and advisory evidence are present;
- a non-mutating what-if comparison and human-review notes.

## Constraints and non-goals

The application is decision support only. It does not modify code or dependency files, install or remove packages, run arbitrary project commands, commit or push, or deploy. Static imports do not prove runtime reachability. Requirements files do not establish direct-versus-transitive status or a complete dependency graph. Production exposure, exploitability, supply-chain provenance, and package maliciousness are not inferred without evidence. Unsupported inputs are reported rather than parsed as if supported.

Risk scores are transparent heuristics, not validated ML predictions or calibrated probabilities. OSV returning no records is limited evidence for the queried package version and time; it is not proof of safety. The Vocareum endpoint remains configured through VOC_API_KEY/VOC_BASE_URL/VOC_MODEL and is not replaced with OpenAI credentials.

## Success criteria and latest local verification

- Preserve the existing LangChain tool-calling agent and Vocareum integration.
- Clearly separate verified source evidence, static project signals, RAG guidance, model interpretation, and unknowns.
- Reject modification requests and keep simulations non-mutating.
- 74 automated tests passed.
- 100/100 offline deterministic evaluation cases passed.
- 12/12 local RAG relevance/abstention cases passed.
- Streamlit AppTest rendered the current nine-view result interface without exceptions for a fixture result.
- Streamlit health endpoint returned HTTP 200 with body "ok".

These checks validate local control flow and curated fixtures; they do not establish live vulnerability coverage or model answer quality.
