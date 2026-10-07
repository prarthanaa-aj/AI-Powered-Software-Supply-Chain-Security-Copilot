import csv
from app.tools.risk_prediction import validate_logistic_csv


def test_validation_reports_insufficient_data_without_fabricating_metrics(tmp_path):
    source = tmp_path / "labels.csv"
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=["group_id", "cvss", "exploit_known", "direct", "dependency_depth", "vulnerability_count", "label"])
        writer.writeheader()
        writer.writerow({"group_id": "vuln-a", "cvss": 8, "exploit_known": 0, "direct": 1, "dependency_depth": 1, "vulnerability_count": 1, "label": 1})
        writer.writerow({"group_id": "vuln-b", "cvss": 2, "exploit_known": 0, "direct": 1, "dependency_depth": 1, "vulnerability_count": 0, "label": 0})
    report = validate_logistic_csv(str(source))
    assert report["status"] == "insufficient_data"
    assert report["metrics"] is None
    assert len(report["dataset_sha256"]) == 64


def test_validation_uses_holdout_and_compares_to_heuristic(tmp_path):
    source = tmp_path / "labels.csv"
    fields = ["group_id", "cvss", "exploit_known", "direct", "dependency_depth", "vulnerability_count", "label"]
    with source.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        for label in (0, 1):
            for i in range(12):
                cvss = 1 + i % 3 if label == 0 else 8 + i % 3
                writer.writerow({"group_id": f"case-{label}-{i}", "cvss": cvss, "exploit_known": label, "direct": 1, "dependency_depth": 1, "vulnerability_count": label, "label": label})
    report = validate_logistic_csv(str(source))
    assert report["status"] == "evaluated_holdout"
    assert report["train_rows"] + report["test_rows"] == 24
    assert set(report["train_group_hashes"]).isdisjoint(report["test_group_hashes"])
    assert set(report["metrics"]) == {"logistic_regression", "heuristic_baseline"}
    assert report["metrics"]["logistic_regression"]["roc_auc"] >= 0.5
