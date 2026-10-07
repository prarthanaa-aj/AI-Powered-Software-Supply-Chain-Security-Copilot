# Safety Controls

- The LLM has only allowlisted read-only analysis tools; there is no shell, file-write, package-management, GitHub, or deployment tool.
- Direct requests to modify/delete/install dependencies, run commands, push code, or deploy are refused before contacting the model. The refusal offers analyst-reviewed recommendations as the safe alternative.
- Manifest content is parsed into bounded package/version records; unsupported options are surfaced as scan issues.
- User-provided question length and tool payload size are bounded.
- Tool results are passed as structured evidence and limited before returning to the model.
- A deterministic response check prevents claims that an empty or failed OSV lookup proves safety.
- A deterministic response check prevents unsupported risk levels when the risk tool reports insufficient evidence or no advisory records.
- API keys and question/manifest content are excluded from telemetry.

The refusal detector is a narrow lexical control, not a general intent classifier. The model can still make factual mistakes in permitted analysis. Human review is required; no control establishes that OSV has complete coverage.
