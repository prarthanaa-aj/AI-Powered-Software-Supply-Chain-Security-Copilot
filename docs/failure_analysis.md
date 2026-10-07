# Failure Analysis

## Valid analysis request was refused by an overbroad safety detector

- **Observed before fix:** a normal request to run risk prioritization for packages returned the fixed modification refusal, with zero LLM or tool calls. In the UI, the shared guardrail flag was also shown as if the empty-evidence response guardrail had fired.
- **Root cause:** the request detector treated generic words such as "run" near package-related words as prohibited shell execution. A single result field also conflated a blocked request with a post-tool evidence-language correction.
- **Fix:** action detection now pairs package/file changes with their targets and reserves run/execute refusals for shell commands/scripts. The result schema distinguishes request_blocked from guardrail_applied. The empty-result language guardrail still runs after lookup outputs exist.
- **Before/after evidence:** the original refusal was observed in the development UI. Regression cases now assert that normal risk-prioritization and dependency-scan questions are allowed while delete, modify, push, deploy, and arbitrary shell requests are refused before model invocation. See tests/test_agent_safety.py and tests/test_langchain_agent_adapter.py. The latest Streamlit AppTest renders the current result flow without exceptions.
- **Limit:** the action detector is lexical, not a general natural-language intent classifier. The screenshots from the original session were not saved as submission files; capture a current safety refusal and normal analysis flow for the capstone evidence.

## Unsupported RAG queries received a document

- **Observed:** unrelated queries could retrieve the only local document because generic terms such as “the” overlapped.
- **Root cause:** the initial lexical vector retrieval accepted weak shared terms as sufficient relevance.
- **Change:** added curated security-concept dimensions with cosine ranking, a query-feature overlap threshold, and an explicit unknown-query abstention test; TF-IDF remains a fallback.
- **Evidence:** run `python -m evaluation.rag_evaluation`; its report contains source hits, required-term matches, and pass/fail for 12 cases.
- **Limit:** the concept map is manually authored, not pretrained neural embeddings; the small rubric does not measure generated-answer grounding.

## Model-controlled risk values

- **Observed:** the LLM could supply CVSS, exploit, dependency, and count features to the risk tool.
- **Root cause:** tool arguments were treated as evidence.
- **Change:** the tool now accepts only a package name and obtains package/version from the parsed manifest plus advisories from a successful lookup during the same run. The unvalidated model file is no longer selected by the agent.
- **Evidence:** tests verify unavailable/mismatched evidence is rejected and model-supplied scores are ignored.
- **Limit:** exploit confirmation and transitive depth are not provided by current evidence; the result stays heuristic.

## Prohibited-operation prompt risk

- **Observed:** prompt-only policy depended on model obedience.
- **Change:** lexical action screening returns a fixed refusal before an LLM call, with no tools executed.
- **Evidence:** five tests assert the LLM is not called for delete, modify, push, deploy, and shell requests.
- **Limit:** the detector is not a general natural-language intent classifier; human review remains necessary.

## BOM dropped the first dependency and unsupported risk scores appeared low

- **Observed before fix:** the sample requirements file had a UTF-8 BOM. The file loader counted only Flask and urllib3, silently missing requests. In the same live Vocareum/OSV run, OSV returned advisories but no numeric CVSS value usable by the scorer; count/directness alone nevertheless produced low scores (0.22 and 0.25).
- **Root cause:** the requirements parser did not strip a leading BOM; the risk heuristic accepted missing CVSS as zero and still returned a severity class.
- **Change:** strip a leading BOM; parse OSV's CVSS v3.1 base vectors using FIRST's formula; return `insufficient_evidence` for unsupported vectors; and guard generated text when the risk tool withheld a score.
- **Evidence:** `live_demo_before_cvss_guardrail.json` preserves the initial run and `live_demo_after_cvss_abstention.json` preserves the interim abstention run. `live_demo.json` is the current rerun. Regression tests cover BOM loading, risk evidence binding, unsupported vectors, and FIRST's published CVSS example scores.
- **Limit:** CVSS 4.0 and malformed/unsupported vector versions are not scored. Exploit confirmation and environment-specific risk remain outside the computed base score.

## LangChain duplicate-call guard blocked distinct package lookups

- **Observed:** the first live LangChain run blocked distinct vulnerability lookups as repeated calls, so risk prioritization had insufficient evidence.
- **Root cause:** the duplicate-call signature did not include package and version arguments; parallel tool execution also allowed risk calculation to race its lookup.
- **Change:** include actual tool arguments in the signature and serialize lookup/risk work per exact package/version. Risk selection performs a bounded same-run lookup prerequisite when needed.
- **Evidence:** `live_demo_langchain_duplicate_guardrail_before_fix.json` preserves the failed run. The current `live_demo.json` records successful lookups and risk results for all three dependencies; tests cover duplicate blocking and distinct input handling.
- **Limit:** the live trace is one example. Broader tool-selection quality still needs analyst-rated cases.
