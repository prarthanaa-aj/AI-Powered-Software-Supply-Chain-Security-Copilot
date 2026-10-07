"""Run one real Vocareum-backed dependency demo and save its evidence locally."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from app.agent.langchain_agent import LangChainCopilotAgent
from app.config import ROOT, VOC_BASE_URL, VOC_MODEL
from app.tools.dependency_scanner import scan_requirements_file


def run(manifest: Path, question: str, output: Path) -> dict:
    # Restrict demo inputs to requirements files that this scanner supports.
    scan = scan_requirements_file(str(manifest.resolve()))
    text = "\n".join(f"{dep.name}=={dep.version}" for dep in scan.dependencies)
    result = LangChainCopilotAgent().respond(question, manifest_text=text, session_id="capstone-live-demo", include_rag=True)
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "provider": "Vocareum-compatible Chat Completions",
        "agent_framework": "LangChain create_agent",
        "base_url": VOC_BASE_URL,
        "model": VOC_MODEL,
        "manifest": str(manifest),
        "dependency_count": len(scan.dependencies),
        "scan_issues": [issue.message for issue in scan.issues],
        "question": question,
        "answer": result["answer"],
        "llm_status": result["llm_status"],
        "latency_seconds": result["latency_seconds"],
        "rag_latency_seconds": result.get("rag_latency_seconds"),
        "llm_call_count": result.get("llm_call_count"),
        "step_count": result.get("step_count"),
        "evidence": result["evidence"],
        "tool_events": result["tool_events"],
        "tool_outputs": result["tool_outputs"],
        "guardrail_applied": result["guardrail_applied"],
        "limitations": ["External OSV results and model output vary over time.",
                        "This is one recorded demonstration, not a quality benchmark."],
    }
    target = output if output.is_absolute() else ROOT / output
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=ROOT / "data" / "sample_projects" / "sample_project" / "requirements.txt")
    parser.add_argument("--question", default="Analyze the dependency risks. Use current OSV results and local analyst guidance, explain evidence and uncertainty, then prioritize any findings using the risk tool.")
    parser.add_argument("--output", type=Path, default=Path("evaluation/results/live_demo.json"))
    args = parser.parse_args()
    try:
        report = run(args.manifest, args.question, args.output)
    except Exception as exc:
        parser.exit(1, f"Live demo failed ({type(exc).__name__}); see local app configuration and network availability.\n")
    print(json.dumps({"provider": report["provider"], "model": report["model"],
                      "llm_status": report["llm_status"], "tools": report["tool_events"],
                      "output": str(args.output)}, indent=2))
