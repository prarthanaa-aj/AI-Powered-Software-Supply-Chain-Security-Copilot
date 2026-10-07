# Project Genome

Project Genome is the project-level view for analyst-led Python dependency review. It extends the pinned requirements parser with bounded static import analysis and an evidence graph.

## Supported inputs

- requirements.txt, requirements-dev.txt, and requirements-prod.txt: only pinned entries are queried for vulnerability intelligence. Unpinned declarations are surfaced as hygiene signals.
- Python .py files: parsed with Python's AST. No project code is imported or executed. Inputs are capped at 50 files and 200 KB per analyzed file.
- Other file types are reported unsupported. pyproject.toml, Pipfile, lockfiles, archives, configuration formats, and source languages other than Python are not parsed.

An import match is static source evidence, not proof that a code path executes. An unmatched import may be a local module, an undeclared distribution, or an unrecognized distribution/import-name mapping. Requirements files do not establish direct-versus-transitive status or resolve the project environment.

## Evidence graph

The graph includes only:

- project-to-package manifest declarations;
- source-file-to-package static imports that match a declared dependency;
- package-to-advisory links returned by the OSV lookup.

No package-to-package edge, runtime path, external-input path, deployment exposure, or affected-module claim is inferred without supplied evidence.

## Contextual risk

The 0–100 contextual index is a transparent weighted mean over observed dimensions. The nominal weights are severity 25, static usage 20, dependency criticality 15, blast radius 10, hygiene 10, supply-chain trust 10, and evidence confidence 10. Unknown dimensions are excluded from the mean and named in the output; evidence coverage is shown separately as a heuristic confidence measure.

The index is withheld when exact-version vulnerability evidence is unavailable, or an advisory has no usable severity. A successful OSV lookup with no advisory returns a zero verified-vulnerability signal, labelled NO SIGNIFICANT VERIFIED RISK; it does not assert that the project is secure. Severity mappings and contextual weighting are heuristics, not validated ML or calibrated probabilities.

Static blast radius counts only supplied source modules importing the package. It does not include unprovided modules or transitive dependents.

## What-if simulation and feedback

The simulator queries OSV for an analyst-entered exact hypothetical version and recalculates the evidence-conditioned score. It does not edit the manifest or assert that a package upgrade is safe. A no-record result remains bounded to OSV and query time.

Existing persistent feedback changes answer length preference. A separate, explicit development-only context correction is session-only, attributed as analyst-supplied and unverified, and changes the static exposure assumption without changing scoring weights.

## Safety and evaluation

The application does not modify project files, install packages, execute project commands, commit or push code, or deploy changes. Human analysts remain responsible for conclusions and remediation.

The local Evaluation view exercises parser, policy, empty-result language, feedback mapping, and RAG retrieval with local fixtures. It does not simulate live OSV or Vocareum availability.
