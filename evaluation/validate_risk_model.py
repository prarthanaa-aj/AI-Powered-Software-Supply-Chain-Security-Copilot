"""Run honest holdout validation for analyst-labeled risk CSV data."""
import argparse
import json
from pathlib import Path
from app.config import ROOT
from app.tools.risk_prediction import validate_logistic_csv


def run(dataset: Path) -> dict:
    result = validate_logistic_csv(str(dataset))
    output = ROOT / "evaluation" / "results" / "risk_model_validation.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=ROOT / "data" / "risk_labels_template.csv")
    args = parser.parse_args()
    report = run(args.dataset)
    print(json.dumps({key: report[key] for key in ("status", "row_count", "class_counts", "metrics")}, indent=2))
