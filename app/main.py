"""Command line entry point for baseline and copilot queries."""
import argparse
import json
from pathlib import Path
from app.agent.langchain_agent import LangChainCopilotAgent
from app.baseline import rule_based_response


def main() -> None:
    parser = argparse.ArgumentParser(description="Supply-chain security copilot")
    parser.add_argument("question", nargs="?", default="Analyze this dependency set")
    parser.add_argument("--requirements", help="Path to a supported requirements file")
    parser.add_argument("--baseline", action="store_true", help="Run Phase 2 deterministic baseline")
    parser.add_argument("--no-rag", action="store_true", help="Disable local guidance retrieval")
    args = parser.parse_args()
    if args.baseline:
        print(rule_based_response(args.question))
        return
    manifest = Path(args.requirements).read_text(encoding="utf-8") if args.requirements else ""
    result = LangChainCopilotAgent().respond(args.question, manifest_text=manifest, include_rag=not args.no_rag)
    print(result["answer"])
    print("\nRun metadata:", json.dumps({k: result[k] for k in ("tool_events", "latency_seconds", "llm_status")}, ensure_ascii=True))
    if result.get("evidence", {}).get("scan_issues"):
        print("Scan issues:", json.dumps(result["evidence"]["scan_issues"], ensure_ascii=True))


if __name__ == "__main__":
    main()
