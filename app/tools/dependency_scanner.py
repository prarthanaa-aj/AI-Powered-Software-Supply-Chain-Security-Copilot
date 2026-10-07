"""Bounded parser for pinned Python requirements files."""
import re
from app.models import Dependency, ScanIssue, ScanResult

_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]+\])?\s*===?\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*$")
_MAX_BYTES = 1_000_000
_MAX_LINES = 10_000


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def scan_requirements_text(text: str, source: str = "requirements.txt") -> ScanResult:
    result = ScanResult(source=source)
    if len(text.encode("utf-8")) > _MAX_BYTES:
        result.issues.append(ScanIssue(0, "Input exceeds the 1 MB limit", source))
        return result
    # Editors and Windows-generated manifests often include a leading UTF-8 BOM.
    lines = text.lstrip("\ufeff").splitlines()
    if len(lines) > _MAX_LINES:
        result.issues.append(ScanIssue(0, "Input exceeds the 10,000 line limit", source))
        return result
    seen: set[tuple[str, str | None]] = set()
    for number, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-", "\\")):
            result.issues.append(ScanIssue(number, "Options, includes, and editable paths are unsupported", raw[:300]))
            continue
        if ";" in line:
            line = line.split(";", 1)[0].strip()
        match = _PIN.fullmatch(line)
        if not match:
            name_match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if not name_match or not _NAME.fullmatch(name_match.group(1)):
                result.issues.append(ScanIssue(number, "Could not parse package requirement", raw[:300]))
                continue
            result.issues.append(ScanIssue(number, "A concrete == or === version is required for lookup", raw[:300]))
            continue
        name, version = match.groups()
        key = (normalize_name(name), version)
        if key in seen:
            continue
        seen.add(key)
        result.dependencies.append(Dependency(name=normalize_name(name), version=version, source=source))
    return result


def scan_requirements_file(path: str) -> ScanResult:
    from pathlib import Path
    target = Path(path)
    if target.name.lower() not in {"requirements.txt", "requirements-dev.txt", "requirements-prod.txt"}:
        raise ValueError("Only explicitly supported requirements files may be scanned")
    if not target.is_file():
        raise FileNotFoundError("Requirements file not found")
    if target.stat().st_size > _MAX_BYTES:
        return ScanResult(issues=[ScanIssue(0, "Input exceeds the 1 MB limit", target.name)], source=target.name)
    return scan_requirements_text(target.read_text(encoding="utf-8"), source=target.name)
