# Phase 3: LLM integration and prompt comparison

## Integration

The LLM client is isolated in `app/agent/llm_client.py`. It loads `VOC_API_KEY`, `VOC_BASE_URL`, and `VOC_MODEL` from the local environment and calls Vocareum's OpenAI-compatible Chat Completions route. The key is never printed or logged. The request has a 30-second timeout and SDK retries.

A minimal Responses API request to the configured Vocareum endpoint returned HTTP 400, while the Phase 0 Chat Completions check succeeded. The prototype therefore uses Chat Completions behind the adapter. Responses API remains appropriate for a direct OpenAI provider if that provider is added and configured separately; the current Vocareum endpoint is not silently treated as compatible.

## Prompt variants

`app/agent/prompts.py` includes:

- A: short basic instruction.
- B: structured response sections.
- C: security analyst role, evidence constraints, and decision-support boundary.

The same three evidence scenarios were run against each prompt (nine requests total): a high-severity direct finding, an empty lookup, and a transitive finding. Results are saved locally in `evaluation/results/prompt_comparison.json` and are git-ignored.

## Selection

Prompt C is the default because it gave the most consistent evidence-first structure and explicitly distinguished evidence from interpretation. The comparison also exposed a failure: the model still described an empty OSV result as “no known vulnerabilities” in some wording. Prompt instructions alone were not reliable enough. A deterministic post-generation guardrail now replaces unsafe empty-result claims with a source-limited statement. The guarded comparison outputs are recorded alongside raw outputs.

This small comparison is a prompt-selection exercise, not a statistically powered evaluation. Human review is still required.
