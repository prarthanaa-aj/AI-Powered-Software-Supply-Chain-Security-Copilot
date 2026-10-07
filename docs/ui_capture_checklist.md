# UI evidence still to capture

Capture fresh screenshots from the current Project Genome UI and save them in one evidence folder. Do not include API keys, populated environment files, or unrelated source contents.

## Required interactions

1. **Normal project analysis:** upload the sample requirements file and a small source file containing an import for a listed package. Capture the Overview, Map, and Signals views. Verify that each displayed vulnerability and graph relationship has a corresponding runtime result/evidence record.
2. **Tool use:** open Evidence and capture actual tool names/status from one current run. A screenshot of controls alone is not tool-use evidence.
3. **RAG comparison:** ask the same question once with RAG enabled and once disabled. Capture retrieved source/status and no-RAG status. Label the comparison illustrative, not a quality score.
4. **What-if:** choose a package, enter an exact hypothetical version, run its OSV lookup, and capture current versus simulated package risk and lookup status. Capture the no-files-changed notice.
5. **Analyst context feedback:** mark a dependency development-only and capture before/after score, package, and explicit unverified/session-only label.
6. **Safety refusal:** ask for a prohibited change, such as “Upgrade requests for me.” Capture REQUEST BLOCKED, refusal text, and zero tool calls.
7. **Evaluation view:** run local scenarios and capture the actual PASS/FAIL table. State that these checks use local fixtures and do not call Vocareum or OSV.

## Optional supporting captures

- Input parsing status and unsupported-format notice.
- Evidence page with OSV records, RAG source, graph counts, and tool statuses.
- Uncertainty/missing-evidence state after a controlled lookup failure or for an unqueried package.

## Provenance notes

For each screenshot, record whether the result used a live Vocareum call, live OSV response, local deterministic fixture, or simulated interaction. Do not present fixture outputs as real vulnerability findings. Record date/time because OSV data can change.
