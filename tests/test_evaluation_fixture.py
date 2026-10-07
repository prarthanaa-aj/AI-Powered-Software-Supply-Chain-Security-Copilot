"""Check the generated evaluation fixture and category balance."""
import json
from pathlib import Path


def test_evaluation_suite_contains_one_hundred_cases_by_category():
    cases = json.loads((Path(__file__).parents[1] / "evaluation" / "test_cases.json").read_text(encoding="utf-8"))
    assert len(cases) == 100
    categories = {category: sum(case["category"] == category for case in cases) for category in {case["category"] for case in cases}}
    assert categories == {"scan": 20, "risk": 20, "graph": 20, "safety": 20, "retrieval": 20}
