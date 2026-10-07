"""Evidence-conditioned contextual risk index and non-mutating simulation."""
from __future__ import annotations

from app.tools.dependency_scanner import normalize_name

WEIGHTS = {"vulnerability_severity": 25, "exposure_static_usage": 20,
           "dependency_criticality": 15, "blast_radius": 10,
           "project_hygiene": 10, "supply_chain_trust": 10,
           "evidence_confidence": 10}
ALIASES = {"yaml": "pyyaml", "bs4": "beautifulsoup4", "pil": "pillow", "cv2": "opencv-python"}


def risk_category(score: int) -> str:
    """Map an index value to its policy label."""
    if not 0 <= score <= 100:
        raise ValueError("Risk index must be between 0 and 100")
    return "NO SIGNIFICANT VERIFIED RISK" if score <= 39 else "LOW" if score <= 59 else "MEDIUM" if score <= 79 else "HIGH"


def _severity_value(vuln: dict) -> float | None:
    raw = vuln.get("cvss_score")
    try:
        if raw is not None:
            return max(0.0, min(10.0, float(raw))) / 10
    except (ValueError, TypeError):
        pass
    return {"CRITICAL": .9, "HIGH": .7, "MODERATE": .5, "MEDIUM": .5, "LOW": .2}.get(str(vuln.get("severity") or "").upper())


def calculate_contextual_risk(project: dict, lookups: list[dict], analyst_context: dict | None = None) -> dict:
    """Score known evidence; unavailable dimensions remain null and reduce confidence."""
    lookup_map = {(normalize_name(str(x.get("package", ""))), str(x.get("version", ""))): x for x in lookups}
    modules_for: dict[str, list[str]] = {}
    for filename, roots in project.get("imports_by_file", {}).items():
        imports = {normalize_name(str(root)) for root in roots}
        for dep in project.get("dependencies", []):
            package = normalize_name(str(dep.get("name", "")))
            aliases = {package, *(alias for alias, dist in ALIASES.items() if dist == package)}
            if imports & aliases:
                modules_for.setdefault(package, []).append(filename)

    rows = []
    for dep in project.get("dependencies", []):
        name, version = normalize_name(str(dep.get("name", ""))), str(dep.get("version") or "")
        lookup = lookup_map.get((name, version))
        advisories = lookup.get("vulnerabilities", []) if lookup else []
        if not lookup or lookup.get("status") != "success":
            rows.append({"package": name, "version": version or None,
                         "vulnerability_status": "evidence_unavailable" if lookup else "not_queried",
                         "risk_score": None, "category": "UNKNOWN", "confidence": 0.0,
                         "components": {k: {"score": None, "weight": w, "status": "unknown"} for k, w in WEIGHTS.items()},
                         "risk_drivers": [], "risk_reducers": [],
                         "missing_evidence": ["Successful exact-version vulnerability lookup"],
                         "explanation": "Risk was not scored because exact-version vulnerability intelligence is unavailable or not queried."})
            continue
        if not advisories:
            rows.append({"package": name, "version": version or None,
                         "vulnerability_status": "no_verified_vulnerability_found",
                         "risk_score": 0, "category": "NO SIGNIFICANT VERIFIED RISK", "confidence": .5,
                         "components": {k: {"score": 0 if k == "vulnerability_severity" else None, "weight": w,
                                            "status": "observed_no_records" if k == "vulnerability_severity" else "unknown"} for k, w in WEIGHTS.items()},
                         "risk_drivers": [], "risk_reducers": [],
                         "missing_evidence": ["Exploitability", "Runtime reachability", "Transitive graph", "Supply-chain provenance"],
                         "explanation": "OSV returned no records for this exact version at lookup time. Zero denotes no verified vulnerability signal and does not mean the package is secure."})
            continue
        values = [_severity_value(v) for v in advisories]
        values = [v for v in values if v is not None]
        if not values:
            rows.append({"package": name, "version": version or None,
                         "vulnerability_status": "requires_analyst_verification",
                         "risk_score": None, "category": "UNKNOWN", "confidence": 0.0,
                         "components": {k: {"score": None, "weight": w, "status": "unknown"} for k, w in WEIGHTS.items()},
                         "risk_drivers": ["Advisory lacks parseable CVSS/severity"], "risk_reducers": [],
                         "missing_evidence": ["Numeric CVSS or mapped severity"],
                         "explanation": "An advisory exists, but available severity evidence is insufficient for a numeric score."})
            continue
        severity = max(values)
        usage_known = project.get("source_analysis_status") == "completed"
        used_modules = modules_for.get(name, [])
        analyst_context = analyst_context or {}
        development_only = analyst_context.get("package") == name and analyst_context.get("classification") == "development_only"
        component_values = {
            "vulnerability_severity": severity,
            "exposure_static_usage": 0.25 if development_only else (1.0 if used_modules else 0.0) if usage_known else None,
            "dependency_criticality": (1.0 if dep.get("direct") else .5) if dep.get("direct") is not None else None,
            "blast_radius": min(1.0, len(used_modules) / 5) if usage_known else None,
            "project_hygiene": (0.0 if dep.get("pinned") else 1.0) if dep.get("pinned") is not None else None,
            "supply_chain_trust": None,
            "evidence_confidence": 1.0,
        }
        known = {k: v for k, v in component_values.items() if v is not None}
        known_weight = sum(WEIGHTS[k] for k in known)
        score = round(100 * sum(v * WEIGHTS[k] for k, v in known.items()) / known_weight) if known_weight else None
        confidence = round(known_weight / 100 * (0.9 if development_only else 1.0 if usage_known else .85), 2)
        category = "UNKNOWN" if score is None else risk_category(score)
        components = {k: {"score": round(v * WEIGHTS[k], 2) if v is not None else None,
                          "normalized_value": v, "weight": WEIGHTS[k],
                          "status": "observed" if v is not None else "unknown"}
                      for k, v in component_values.items()}
        drivers = []
        if severity >= .7: drivers.append("High severity in retrieved vulnerability evidence")
        if used_modules: drivers.append(f"Static imports associate the package with {len(used_modules)} supplied source module(s)")
        if dep.get("direct") is True: drivers.append("Declared as a direct dependency")
        if not dep.get("pinned"): drivers.append("Version is unpinned")
        reducers = []
        if development_only:
            reducers.append("Analyst marked this dependency development-only; this context was not independently verified")
        rows.append({"package": name, "version": version or None, "vulnerability_status": "verified_vulnerability",
                     "advisory_ids": [v.get("id") for v in advisories if v.get("id")],
                     "risk_score": score, "category": category, "confidence": confidence,
                     "components": components, "risk_drivers": drivers, "risk_reducers": reducers,
                     "analyst_context": "development_only (analyst supplied; not independently verified)" if development_only else None,
                     "affected_modules": used_modules,
                     "missing_evidence": [k for k, v in component_values.items() if v is None],
                     "explanation": "Weighted mean over observed dimensions only. Unknown dimensions are excluded and listed; confidence reflects evidence coverage. Static imports do not prove runtime reachability. This is a heuristic, not validated ML."})

    scored = [r for r in rows if r["vulnerability_status"] == "verified_vulnerability" and isinstance(r["risk_score"], int)]
    successful = [x for x in lookups if x.get("status") == "success"]
    if scored:
        top = max(scored, key=lambda r: r["risk_score"])
        overall, category = top["risk_score"], top["category"]
        confidence = round(sum(r["confidence"] for r in scored) / len(scored), 2)
    elif rows and len(successful) >= len(rows) and all(r["vulnerability_status"] == "no_verified_vulnerability_found" for r in rows):
        overall, category, confidence = 0, "NO SIGNIFICANT VERIFIED RISK", .5
    else:
        overall, category, confidence = None, "INSUFFICIENT EVIDENCE", 0.0
    return {"score": overall, "category": category, "confidence": confidence,
            "components": {"weights": WEIGHTS, "method": "weighted mean over observed dimensions; unknowns excluded"},
            "risk_drivers": [d for r in scored for d in r["risk_drivers"]],
            "risk_reducers": [d for r in rows for d in r.get("risk_reducers", [])],
            "missing_evidence": sorted({e for r in rows for e in r.get("missing_evidence", [])}),
            "dependencies": rows,
            "limitations": ["Static imports do not establish runtime reachability.",
                            "Supported manifest data does not establish transitive package relationships.",
                            "Supply-chain provenance and exploitability are not assessed.",
                            "Scores are heuristic decision support, not validated ML or proof of safety."]}


def simulate_lookup_change(project: dict, lookups: list[dict], package: str, simulated_lookup: dict,
                           analyst_context: dict | None = None) -> dict:
    """Compare an explicit hypothetical version lookup without changing project files."""
    before = calculate_contextual_risk(project, lookups, analyst_context)
    target = normalize_name(package)
    dep = next((d for d in project.get("dependencies", []) if normalize_name(str(d.get("name", ""))) == target), None)
    if dep is None:
        return {"status": "invalid_input", "message": "Package is not present in the supplied manifest."}
    hypothetical_version = str(simulated_lookup.get("version", ""))
    if not hypothetical_version or simulated_lookup.get("status") != "success":
        return {"status": "insufficient_evidence", "message": "A successful lookup for an explicitly supplied hypothetical version is required."}
    scenario = {**project, "dependencies": [
        {**d, "version": hypothetical_version} if normalize_name(str(d.get("name", ""))) == target else d
        for d in project.get("dependencies", [])]}
    scenario_lookups = [x for x in lookups if normalize_name(str(x.get("package", ""))) != target]
    scenario_lookups.append({**simulated_lookup, "package": target, "version": hypothetical_version})
    after = calculate_contextual_risk(scenario, scenario_lookups, analyst_context)
    before_dependency = next((r for r in before["dependencies"] if r["package"] == target), None)
    after_dependency = next((r for r in after["dependencies"] if r["package"] == target), None)
    old_score = before_dependency.get("risk_score") if before_dependency else None
    new_score = after_dependency.get("risk_score") if after_dependency else None
    return {"status": "success", "simulation_only": True, "files_modified": False,
            "package": target, "current_version": dep.get("version"), "simulated_version": hypothetical_version,
            "before": before, "after": after,
            "before_dependency": before_dependency, "after_dependency": after_dependency,
            "score_delta": new_score - old_score if isinstance(new_score, int) and isinstance(old_score, int) else None,
            "explanation": "Counterfactual uses the hypothetical version OSV result and unchanged static project context. No files are changed; this does not prove exploitability."}
