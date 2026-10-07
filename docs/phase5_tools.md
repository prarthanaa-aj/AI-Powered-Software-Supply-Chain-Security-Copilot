# Phase 5: Security analysis tools

## Tools

1. **Dependency scanner:** bounded parser for pinned Python `requirements.txt` variants. Unpinned requirements, includes, editable paths, and unsupported syntax are reported as issues.
2. **Vulnerability lookup:** queries the OSV.dev `POST /v1/query` endpoint for an exact PyPI package/version and preserves advisory IDs, references, source, and retrieval time. Source errors are distinct from an empty successful result.
3. **Dependency graph:** NetworkX graph with project-to-direct edges. The current parser does not read lockfile transitive edges, so unknown transitive relationships remain unknown. The LLM cannot inject graph edges into the graph tool.
4. **Risk prioritization:** transparent heuristic by default. An optional logistic regression can be trained from an analyst-labeled CSV with at least 20 rows and both labels. Any trained model remains labeled experimental and is not validated for operational decisions.

The LLM can request only allowlisted tools: vulnerability lookup, graph summary, risk prioritization, and local guidance search. Manifest scanning is deterministic and happens before model context is built. There is no command execution, arbitrary file access, package modification, or deployment tool.

## Evidence and failure handling

A successful lookup with zero records means only that OSV returned no records for that query. It is not a safety conclusion. An invalid package/version or unavailable source is labeled separately. Tool errors are returned to the model in bounded form, and the agent can continue or explain the failure.

## Verification

- A live OSV query for `requests==2.31.0` returned six records during implementation; results are time-dependent and must be rechecked for current analysis.
- A deliberately invalid package tool call is covered by a regression test; the tool returns `invalid_input` without a network request, and the agent produces a recovery message.
- The source API request schema follows the official OSV query documentation: https://google.github.io/osv.dev/post-v1-query/.
