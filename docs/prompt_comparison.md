# Prompt comparison

## Method and results

Three prompt variants were run against the same three synthetic evidence cases: a priority finding, an empty OSV lookup, and a transitive-finding scenario. The artifact contains nine responses, including raw and post-guardrail answers.

| Variant | Design | Cases | Empty-result rewrites | Selection |
|---|---|---:|---:|---|
| A — Basic | Clear, concise answer | 3 | 1/3 | Baseline |
| B — Structured | Findings, evidence, priority, follow-up, limitations | 3 | 1/3 | More organized |
| C — Security analyst | Decision support, evidence boundaries, uncertainty, safety | 3 | 1/3 | Selected default |

Prompt C was selected because it explicitly requests evidence, uncertainty, and analyst-facing structure. Deterministic empty-result handling remains necessary: prompt instructions alone did not prevent unsafe wording in the empty-lookup case.

## Limitations

This is a small qualitative comparison, not a blinded or independently rated prompt-quality study. One synthetic case per scenario cannot establish statistical consistency or answer correctness. Guardrail rewrite count is not a prompt score. Raw and guarded outputs are in evaluation/results/prompt_comparison.json. That directory is Git-ignored and must be selected explicitly for the submission archive.
