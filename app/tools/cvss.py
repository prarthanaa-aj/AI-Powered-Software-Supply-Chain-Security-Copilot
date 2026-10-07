"""Strict CVSS v3.1 base-score calculation for source-provided vectors."""
from decimal import Decimal, ROUND_HALF_UP
import math

_BASE_KEYS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
_OPTIONAL_VALUES = {
    "E": {"X", "H", "F", "P", "U"}, "RL": {"X", "U", "W", "T", "O"}, "RC": {"X", "C", "R", "U"},
    "CR": {"X", "H", "M", "L"}, "IR": {"X", "H", "M", "L"}, "AR": {"X", "H", "M", "L"},
    "MAV": {"X", "N", "A", "L", "P"}, "MAC": {"X", "L", "H"}, "MPR": {"X", "N", "L", "H"},
    "MUI": {"X", "N", "R"}, "MS": {"X", "U", "C"},
    "MC": {"X", "H", "L", "N"}, "MI": {"X", "H", "L", "N"}, "MA": {"X", "H", "L", "N"},
}
_OPTIONAL_KEYS = set(_OPTIONAL_VALUES)


def cvss_v31_base_score(vector: str) -> float | None:
    """Return CVSS 3.1 base score for a valid vector, else None.

    Temporal/environmental metrics may be present but are deliberately ignored:
    this function computes only the standardized base score.
    """
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        return None
    metrics = {}
    for part in vector[len("CVSS:3.1/"):].split("/"):
        if ":" not in part:
            return None
        key, value = part.split(":", 1)
        if key in metrics or key not in _BASE_KEYS | _OPTIONAL_KEYS:
            return None
        metrics[key] = value
    if not _BASE_KEYS.issubset(metrics):
        return None

    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac = {"L": 0.77, "H": 0.44}
    ui = {"N": 0.85, "R": 0.62}
    impact = {"H": 0.56, "L": 0.22, "N": 0.0}
    if metrics["AV"] not in av or metrics["AC"] not in ac or metrics["UI"] not in ui:
        return None
    if metrics["S"] not in {"U", "C"} or any(metrics[key] not in impact for key in ("C", "I", "A")):
        return None
    if any(metrics[key] not in allowed for key, allowed in _OPTIONAL_VALUES.items() if key in metrics):
        return None

    scope_changed = metrics["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}
    exploitability = 8.22 * av[metrics["AV"]] * ac[metrics["AC"]] * pr[metrics["PR"]] * ui[metrics["UI"]]
    iss = 1 - (1 - impact[metrics["C"]]) * (1 - impact[metrics["I"]]) * (1 - impact[metrics["A"]])
    if scope_changed:
        impact_subscore = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact_subscore = 6.42 * iss
    if impact_subscore <= 0:
        return 0.0
    raw_score = min(1.08 * (impact_subscore + exploitability) if scope_changed else impact_subscore + exploitability, 10.0)
    # FIRST's roundup rule uses integer arithmetic to avoid floating-point edge cases.
    scaled = int((Decimal(str(raw_score)) * Decimal(100000)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0
