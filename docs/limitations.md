# Known limitations

- Only requirements.txt, requirements-dev.txt, requirements-prod.txt, and Python .py source are understood. Other .txt files are reported unsupported.
- pyproject.toml, Pipfile, lockfiles, ZIP archives, configuration files, and non-Python source are not parsed.
- Project analysis is bounded to 50 files and 200 KB per analyzed file.
- Python analysis reads AST import statements only. It does not execute code, resolve dynamic imports, identify call sites, or prove runtime reachability.
- Manifest entries do not establish direct-versus-transitive status. No complete transitive package graph, dependency resolution, or deployment graph is built.
- Static module counts are a limited blast-radius signal; omitted source files make the observed count incomplete.
- Production configuration, runtime exposure, exploitability, active exploitation, and supply-chain provenance are not verified.
- OSV is one external vulnerability source. An unavailable lookup is unknown; an empty result does not prove safety.
- Severity and contextual risk are evidence-conditioned heuristics, not validated ML predictions or calibrated probabilities.
- Risk depends on which exact-version lookups the agent completes within configured tool-call limits. Unqueried packages remain unknown.
- What-if results use an OSV lookup for an explicitly supplied hypothetical version; they do not prove that changing to it is safe and do not edit files.
- Development-only context feedback is analyst-supplied, unverified, and session-scoped. Persistent feedback currently adjusts answer length only.
- The local RAG corpus and 12-case rubric are small and project-authored. They do not establish broad retrieval or answer quality.
- This is a local prototype. Cloud deployment, multi-user operations, independent analyst-rated evaluation, and labeled project-level ML validation are not established.
