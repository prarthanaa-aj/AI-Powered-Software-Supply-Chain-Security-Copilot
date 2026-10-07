"""Phase 2 CLI for demonstrating the rule-based baseline."""

import argparse

from app.baseline import rule_based_response


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Phase 2 rule-based baseline")
    parser.add_argument("question", nargs="?", default="Analyze my dependencies")
    args = parser.parse_args()
    print(rule_based_response(args.question))


if __name__ == "__main__":
    main()
