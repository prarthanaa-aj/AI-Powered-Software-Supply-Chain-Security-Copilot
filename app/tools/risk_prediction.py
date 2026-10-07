"""Explainable heuristic prioritization and optional labeled-data logistic model."""
import csv
import json
import math
import hashlib
import math
import random
import tempfile
from pathlib import Path

FEATURES = ("cvss", "exploit_known", "direct", "dependency_depth", "vulnerability_count")


def _validated_training_row(row: dict) -> tuple[list[float], int]:
    values = [float(row[name]) for name in FEATURES]
    raw_label = float(row["label"])
    if not all(math.isfinite(value) for value in values) or raw_label not in (0, 1):
        raise ValueError("Features must be finite numbers and label must be exactly 0 or 1")
    if not 0 <= values[0] <= 10 or values[1] not in (0, 1) or values[2] not in (0, 1) or values[3] < 1 or values[4] < 0:
        raise ValueError("Expected CVSS 0-10, boolean exploit/direct values, depth >= 1, and count >= 0")
    return values, int(raw_label)


def _sigmoid(value: float) -> float:
    value = max(-30.0, min(30.0, value))
    return 1.0 / (1.0 + math.exp(-value))


def heuristic_risk(features: dict) -> dict:
    cvss = max(0.0, min(10.0, float(features.get("cvss") or 0.0))) / 10.0
    exploit = 1.0 if features.get("exploit_known") else 0.0
    direct = 1.0 if features.get("direct") else 0.0
    count = min(1.0, max(0, int(features.get("vulnerability_count") or 0)) / 5.0)
    depth = features.get("dependency_depth")
    exposure = 1.0 if depth in (None, 1) else 1.0 / max(1, int(depth))
    score = 0.50 * cvss + 0.25 * exploit + 0.15 * exposure + 0.05 * direct + 0.05 * count
    level = "CRITICAL" if score >= 0.85 else "HIGH" if score >= 0.65 else "MEDIUM" if score >= 0.35 else "LOW"
    return {"score": round(score, 4), "level": level, "method": "transparent_heuristic", "confidence": None,
            "factors": {"cvss_normalized": round(cvss, 3), "exploit_known": bool(exploit), "direct": bool(direct), "exposure_weight": round(exposure, 3), "vulnerability_count_weight": round(count, 3)}}


def train_logistic_csv(csv_path: str, output_path: str, epochs: int = 1000, learning_rate: float = 0.05) -> dict:
    """Train a small logistic model from analyst-labeled CSV; never creates synthetic labels."""
    rows = []
    with open(csv_path, newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            x, y = _validated_training_row(row)
            rows.append((x, y))
    if len(rows) < 20 or {y for _, y in rows} != {0, 1}:
        raise ValueError("Training requires at least 20 labeled rows and both label classes")
    mean = [sum(x[i] for x, _ in rows) / len(rows) for i in range(len(FEATURES))]
    scale = [max(1e-9, math.sqrt(sum((x[i] - mean[i]) ** 2 for x, _ in rows) / len(rows))) for i in range(len(FEATURES))]
    weights = [0.0] * len(FEATURES)
    bias = 0.0
    for _ in range(epochs):
        grad = [0.0] * len(FEATURES)
        grad_b = 0.0
        for x, y in rows:
            z = [(x[i] - mean[i]) / scale[i] for i in range(len(FEATURES))]
            error = _sigmoid(sum(weights[i] * z[i] for i in range(len(FEATURES))) + bias) - y
            grad_b += error
            for i in range(len(FEATURES)):
                grad[i] += error * z[i]
        n = len(rows)
        weights = [weights[i] - learning_rate * grad[i] / n for i in range(len(FEATURES))]
        bias -= learning_rate * grad_b / n
    model = {"features": list(FEATURES), "mean": mean, "scale": scale, "weights": weights, "bias": bias, "training_rows": len(rows), "label_source": str(csv_path), "status": "experimental_unvalidated"}
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(model, indent=2), encoding="utf-8")
    return model


def predict_with_model(features: dict, model_path: str) -> dict:
    model = json.loads(Path(model_path).read_text(encoding="utf-8"))
    vector = [float(features.get(name) or 0.0) for name in model["features"]]
    normalized = [(vector[i] - model["mean"][i]) / model["scale"][i] for i in range(len(vector))]
    probability = _sigmoid(sum(model["weights"][i] * normalized[i] for i in range(len(vector))) + model["bias"])
    return {"score": round(probability, 4), "level": "HIGH" if probability >= 0.5 else "LOW", "method": "experimental_logistic_regression", "confidence": None, "validation_status": model["status"]}


def validate_logistic_csv(csv_path: str, minimum_per_class: int = 10, seed: int = 17) -> dict:
    """Evaluate on a deterministic group-disjoint holdout; refuse weak datasets honestly."""
    source = Path(csv_path)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    with source.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    parsed = []
    for row in rows:
        group_id = str(row.get("group_id", "")).strip()
        if not group_id:
            return {"dataset_sha256": digest, "row_count": len(rows), "status": "invalid_data",
                    "reason": "Each row needs a non-empty group_id so related cases cannot leak across train and test." ,
                    "metrics": None}
        values, label = _validated_training_row(row)
        features = dict(zip(FEATURES, values))
        parsed.append((features, label, group_id))
    counts = {label: sum(y == label for _, y, _ in parsed) for label in (0, 1)}
    unique_groups = sorted({group_id for _, _, group_id in parsed})
    base = {"dataset_sha256": digest, "row_count": len(parsed), "class_counts": counts,
            "group_count": len(unique_groups), "validation_method": "deterministic_group_holdout", "seed": seed}
    if min(counts.values()) < minimum_per_class or len(parsed) < 22:
        return {**base, "status": "insufficient_data", "minimum_per_class": minimum_per_class, "minimum_rows": 22,
                "reason": "Need enough independently labeled examples from both classes and at least 20 training rows plus a two-row holdout.",
                "metrics": None}

    group_indexes = {group: [i for i, (_, _, row_group) in enumerate(parsed) if row_group == group]
                     for group in unique_groups}
    train_groups, test_groups = [], []
    for attempt in range(500):
        shuffled = unique_groups[:]
        random.Random(seed + attempt).shuffle(shuffled)
        desired_test_count = max(2, round(len(shuffled) * 0.2))
        for test_count in range(desired_test_count, 1, -1):
            candidate_test = shuffled[:test_count]
            candidate_train = shuffled[test_count:]
            test_indexes_candidate = [i for group in candidate_test for i in group_indexes[group]]
            train_indexes_candidate = [i for group in candidate_train for i in group_indexes[group]]
            test_labels = {parsed[i][1] for i in test_indexes_candidate}
            train_labels = {parsed[i][1] for i in train_indexes_candidate}
            if len(train_indexes_candidate) >= 20 and test_labels == {0, 1} and train_labels == {0, 1}:
                test_groups, train_groups = candidate_test, candidate_train
                break
        if test_groups:
            break
    if not test_groups:
        return {**base, "status": "insufficient_group_diversity",
                "reason": "Could not form a group-disjoint holdout containing both labels in train and test.", "metrics": None}
    train_indexes = [i for group in train_groups for i in group_indexes[group]]
    test_indexes = [i for group in test_groups for i in group_indexes[group]]
    with tempfile.TemporaryDirectory(prefix="risk-validation-") as folder:
        train_path = Path(folder) / "train.csv"
        model_path = Path(folder) / "model.json"
        with train_path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=[*FEATURES, "label"])
            writer.writeheader()
            for i in train_indexes:
                features, label, _ = parsed[i]
                writer.writerow({**features, "label": label})
        train_logistic_csv(str(train_path), str(model_path))
        model = json.loads(model_path.read_text(encoding="utf-8"))

    def metrics(truth: list[int], scores: list[float]) -> dict:
        predictions = [int(score >= 0.5) for score in scores]
        tp = sum(y == 1 and p == 1 for y, p in zip(truth, predictions))
        tn = sum(y == 0 and p == 0 for y, p in zip(truth, predictions))
        fp = sum(y == 0 and p == 1 for y, p in zip(truth, predictions))
        fn = sum(y == 1 and p == 0 for y, p in zip(truth, predictions))
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        positives = [score for score, y in zip(scores, truth) if y == 1]
        negatives = [score for score, y in zip(scores, truth) if y == 0]
        auc = sum((p > n) + 0.5 * (p == n) for p in positives for n in negatives) / (len(positives) * len(negatives))
        return {"accuracy": round((tp + tn) / len(truth), 4), "precision": round(precision, 4),
                "recall": round(recall, 4), "f1": round(f1, 4), "roc_auc": round(auc, 4),
                "confusion_matrix": {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn}}

    truth, ml_scores, heuristic_scores = [], [], []
    for i in test_indexes:
        features, label, _ = parsed[i]
        truth.append(label)
        vector = [(features[name] - model["mean"][j]) / model["scale"][j] for j, name in enumerate(FEATURES)]
        ml_scores.append(_sigmoid(sum(model["weights"][j] * vector[j] for j in range(len(FEATURES))) + model["bias"]))
        heuristic_scores.append(heuristic_risk(features)["score"])
    return {**base, "status": "evaluated_holdout", "minimum_per_class": minimum_per_class,
            "train_rows": len(train_indexes), "test_rows": len(test_indexes),
            "train_group_count": len(train_groups), "test_group_count": len(test_groups),
            "train_group_hashes": sorted(hashlib.sha256(group.encode("utf-8")).hexdigest() for group in train_groups),
            "test_group_hashes": sorted(hashlib.sha256(group.encode("utf-8")).hexdigest() for group in test_groups),
            "metrics": {"logistic_regression": metrics(truth, ml_scores), "heuristic_baseline": metrics(truth, heuristic_scores)},
            "limitations": ["Holdout is group-disjoint within the supplied dataset and does not establish external validity.",
                            "Labels must be independently assigned; labels derived from the heuristic invalidate the comparison."]}
