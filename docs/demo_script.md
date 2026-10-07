# Project Genome capstone demo script

Use five deliberate interactions. Capture actual current UI results and note whether each external call was live. Do not pass fixture outputs off as real vulnerability findings. Screenshots are not yet captured.

## Demo 1 — Project analysis and tool use

**Input:** upload data/sample_projects/sample_project/requirements.txt and a small Python source file that imports one listed dependency. Ask: “Analyze the project evidence, check exact dependency versions in OSV, retrieve relevant local guidance, and explain the risk and unknowns.”

**Show:** Overview, Map, Signals, and Evidence tabs. In Evidence, show actual tool names/status, OSV result timestamps/IDs when returned, RAG source passages, and the project evidence graph. Explain that AST imports are static evidence and do not prove runtime reachability. Risk scores are heuristic.

**Capture:** input/parsing, overview, graph, security signals, and evidence/tool activity.

## Demo 2 — RAG on/off comparison

Ask the same question about dependency review guidance with RAG enabled; show the retrieved source/status under Evidence. Disable “Include local security guidance (RAG)” in the sidebar, repeat exactly, and show that no guidance was retrieved. The difference is illustrative and does not demonstrate measured answer quality.

## Demo 3 — Analyst feedback and adaptation

After an analysis that has a scored dependency, open Analyst Memory. Mark one dependency as development-only and apply the context for this session. Show the before/after package score and the label that this is analyst-supplied, unverified context. Scoring weights and project files remain unchanged. Also show that persistent existing feedback controls answer length only.

## Demo 4 — Safety refusal

Ask: “Upgrade requests for me.” Show REQUEST BLOCKED, the decision-support refusal, zero tool calls, and the safety controls. Explain that a hypothetical exact-version lookup is available in Simulate, but the app cannot install or edit packages.

## Demo 5 — What-if simulation

In Simulate, select a dependency from the supplied manifest, enter an exact hypothetical version, and run the OSV lookup. Show lookup status and current versus simulated dependency score. If evidence is incomplete, show Unknown rather than interpreting missing data as zero risk. Point out the simulation-only/no-file-change notice.

## Optional local evaluation

Open Evaluation and run the local scenarios. The table exercises parser, refusal policy, empty-result wording, RAG retrieval, and feedback mapping using local fixtures. It does not make Vocareum or OSV requests.

## Evidence and provenance

Existing supporting files are in evaluation/results/ (Git-ignored): live_demo.json, live_demo_tool_recovery.json, prompt_comparison.json, rag_ablation.json, and local_demo_traces.json. These are historical artifacts and include simulated cases. Record the current date/time and label each screenshot or trace as live Vocareum, live OSV, local deterministic, or simulated. OSV data may change.

Do not show .env or credential values in any recording. Remove or obscure private source contents before capture.
