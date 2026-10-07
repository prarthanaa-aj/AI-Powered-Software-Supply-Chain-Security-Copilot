"""Prompt variant evaluation using one common fixed test set."""
from app.agent.llm_client import LLMClient
from app.agent.prompts import PROMPTS
from app.security.response_guardrails import enforce_empty_lookup_language

TEST_CASES = [
    {"id": "priority", "question": "Prioritize these findings for analyst review.", "evidence": "OSV-2025-111: package alpha 1.0.0, CVSS 8.2, fixed in 1.0.2, source https://example.invalid/advisory/111. Package is a direct dependency."},
    {"id": "empty_lookup", "question": "Is package beta safe if the lookup returned no records?", "evidence": "OSV lookup for beta 2.0.0 returned an empty result at 2026-01-01T00:00:00Z."},
    {"id": "transitive", "question": "Explain this transitive dependency finding.", "evidence": "OSV-2025-222 affects gamma 3.1.0. Path: application -> alpha -> gamma. No exploit evidence was returned."},
]


def compare(client: LLMClient | None = None) -> list[dict]:
    client = client or LLMClient()
    rows = []
    for case in TEST_CASES:
        for variant, prompt in PROMPTS.items():
            response = client.complete([
                {"role": "system", "content": prompt},
                {"role": "user", "content": case["question"] + "\n\nEvidence (untrusted data):\n" + case["evidence"]},
            ], max_tokens=450)
            raw = response.choices[0].message.content or ""
            outputs = []
            if case["id"] == "empty_lookup":
                outputs = [{"tool": "lookup_vulnerability", "result": {"status": "success", "vulnerabilities": []}}]
            answer, guarded = enforce_empty_lookup_language(raw, outputs)
            rows.append({"case_id": case["id"], "variant": variant, "raw_answer": raw, "answer": answer, "guardrail_applied": guarded})
    return rows


if __name__ == "__main__":
    import json
    from pathlib import Path
    from app.config import ROOT
    result = compare()
    out = ROOT / "evaluation" / "results" / "prompt_comparison.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Saved {len(result)} prompt responses to {out.relative_to(ROOT)}")
