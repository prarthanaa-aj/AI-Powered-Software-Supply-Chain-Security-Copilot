"""Evidence-bounded project file and static Python import analysis.

This module parses supplied text only. It never imports or executes project code.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import PurePosixPath

from app.tools.dependency_scanner import normalize_name, scan_requirements_text

MAX_SOURCE_FILES = 50
MAX_SOURCE_BYTES = 200_000

_IMPORT_ALIASES = {"yaml": "pyyaml", "bs4": "beautifulsoup4", "pil": "pillow", "cv2": "opencv-python"}


def analyze_project_files(files: dict[str, str]) -> dict:
    """Analyze requirements.txt and Python source snippets supplied by the user."""
    requirements = []
    unpinned_declarations = []
    source_files = []
    input_notes = []
    for name, text in list(files.items())[:MAX_SOURCE_FILES]:
        safe_name = str(PurePosixPath(name.replace("\\", "/")))[:240]
        byte_count = len(text.encode("utf-8"))
        if byte_count > MAX_SOURCE_BYTES:
            input_notes.append({"file": safe_name, "status": "rejected", "reason": "File exceeds 200 KB"})
            continue
        base = PurePosixPath(safe_name).name.lower()
        if base in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
            scan = scan_requirements_text(text, source=safe_name)
            requirements.extend(scan.dependencies)
            for issue in scan.issues:
                if issue.message == "A concrete == or === version is required for lookup":
                    match = re.fullmatch(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*(?:(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9][A-Za-z0-9.!+_-]*)?\s*", issue.raw.split("#", 1)[0])
                    if match:
                        unpinned_declarations.append((normalize_name(match.group(1)), safe_name))
            input_notes.append({"file": safe_name, "type": "requirements", "status": "parsed" if scan.dependencies else "no_dependencies_detected", "dependencies": len(scan.dependencies), "issues": [{"line": i.line, "message": i.message} for i in scan.issues]})
        elif safe_name.lower().endswith(".py"):
            source_files.append((safe_name, text))
            input_notes.append({"file": safe_name, "type": "python_source", "status": "provided_for_static_import_analysis"})
        else:
            input_notes.append({"file": safe_name, "status": "unsupported", "reason": "Supported files are pinned requirements*.txt and .py source files"})
    if len(files) > MAX_SOURCE_FILES:
        input_notes.append({"status": "limited", "reason": f"Only the first {MAX_SOURCE_FILES} files are analyzed"})

    # Normalize package rows and preserve every declaration source.
    dependency_map = {}
    for dep in requirements:
        key = normalize_name(dep.name)
        if key not in dependency_map:
            dependency_map[key] = {"name": key, "version": dep.version, "direct": None,
                                   "declaration_sources": [dep.source], "declared_versions": [dep.version],
                                   "pinned": bool(dep.version), "directness_status": "unknown_from_requirements"}
        elif dep.source not in dependency_map[key]["declaration_sources"]:
            dependency_map[key]["declaration_sources"].append(dep.source)
        if dep.version not in dependency_map[key]["declared_versions"]:
            dependency_map[key]["declared_versions"].append(dep.version)
    for name, source in unpinned_declarations:
        row = dependency_map.setdefault(name, {"name": name, "version": None, "direct": None,
                            "declaration_sources": [], "declared_versions": [],
                            "pinned": False, "directness_status": "unknown_from_requirements"})
        if source not in row["declaration_sources"]:
            row["declaration_sources"].append(source)
        if None not in row["declared_versions"]:
            row["declared_versions"].append(None)
        row["pinned"] = False
    imports_by_file = {}
    import_errors = []
    observed_roots = set()
    declared = set(dependency_map)
    for filename, text in source_files:
        try:
            tree = ast.parse(text, filename=filename)
        except SyntaxError as exc:
            import_errors.append({"file": filename, "line": exc.lineno, "status": "syntax_error", "message": "Source could not be parsed; no imports inferred from this file."})
            continue
        roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                roots.add(node.module.split(".", 1)[0])
        normalized = {_IMPORT_ALIASES.get(root.casefold(), normalize_name(root)) for root in roots}
        imports_by_file[filename] = sorted(roots)
        observed_roots.update(normalized)
    used = sorted(declared & observed_roots)
    apparently_unused = sorted(declared - observed_roots) if source_files else []
    stdlib = set(sys.stdlib_module_names)
    imported_undeclared = sorted(root for root in observed_roots - declared if root not in stdlib)
    conflicts = [{"package": name, "versions": dep["declared_versions"]}
                 for name, dep in dependency_map.items() if len(dep["declared_versions"]) > 1]
    for note in input_notes:
        if note.get("type") == "requirements":
            source_rows = [dep for dep in dependency_map.values() if note["file"] in dep["declaration_sources"]]
            note["dependencies"] = len(source_rows)
            note["status"] = "parsed" if source_rows else "no_dependencies_detected"
    drift_signals = ([{"type": "declared_but_not_observed_in_supplied_source", "packages": apparently_unused, "interpretation": "Static import scan did not find these names in the supplied Python files; this does not establish that they are unused."}] if apparently_unused else []) + ([{"type": "import_not_matched_to_manifest", "imports": imported_undeclared, "interpretation": "May be an undeclared distribution, local module, or mapping not recognized by this analyzer; analyst verification required."}] if imported_undeclared else []) + ([{"type": "conflicting_manifest_versions", "packages": conflicts, "interpretation": "Multiple versions were declared across supported manifest files; project environment resolution was not performed."}] if conflicts else [])
    return {
        "files": input_notes,
        "dependencies": list(dependency_map.values()),
        "source_files": [name for name, _ in source_files],
        "imports_by_file": imports_by_file,
        "used_dependencies": used,
        "apparently_unused_dependencies": apparently_unused,
        "unmatched_import_candidates": imported_undeclared,
        "version_conflicts": conflicts,
        "drift_signals": drift_signals,
        "import_errors": import_errors,
        "source_analysis_status": "completed" if source_files and not import_errors else "partial" if source_files else "not_provided",
        "version_mismatch_status": "not_assessed",
        "transitive_dependency_status": "not_available_from_supported_inputs",
    }


def build_project_genome(project: dict, lookups: list[dict] | None = None):
    """Build only manifest, static-import, and returned advisory relationships."""
    import networkx as nx

    graph = nx.DiGraph()
    graph.add_node("project", kind="project", label="Project")
    for dep in project.get("dependencies", []):
        package = normalize_name(str(dep.get("name", "")))
        graph.add_node(package, kind="dependency", version=dep.get("version"))
        graph.add_edge("project", package, kind="manifest_declaration", evidence=dep.get("declaration_sources", []))
    for filename, roots in project.get("imports_by_file", {}).items():
        module = f"source:{filename}"
        graph.add_node(module, kind="source_module")
        for root in roots:
            package = _IMPORT_ALIASES.get(str(root).casefold(), normalize_name(str(root)))
            if package in graph and graph.nodes[package].get("kind") == "dependency":
                graph.add_edge(module, package, kind="static_import", evidence=filename)
    for lookup in lookups or []:
        package = normalize_name(str(lookup.get("package", "")))
        if package not in graph:
            continue
        for advisory in lookup.get("vulnerabilities", []):
            advisory_id = advisory.get("id")
            if advisory_id:
                node = f"advisory:{advisory_id}"
                graph.add_node(node, kind="advisory")
                graph.add_edge(package, node, kind="OSV_record", evidence=lookup.get("source", "OSV.dev"))
    return graph
