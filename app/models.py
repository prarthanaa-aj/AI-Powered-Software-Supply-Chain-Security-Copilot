"""Typed records shared by the copilot components."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str = "PyPI"
    direct: bool | None = True
    source: str = "requirements.txt"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanIssue:
    line: int
    message: str
    raw: str


@dataclass
class ScanResult:
    dependencies: list[Dependency] = field(default_factory=list)
    issues: list[ScanIssue] = field(default_factory=list)
    source: str = "requirements.txt"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "dependency_count": len(self.dependencies),
            "dependencies": [d.to_dict() for d in self.dependencies],
            "issues": [asdict(i) for i in self.issues],
            "complete": not self.issues,
        }


@dataclass
class LookupResult:
    package: str
    version: str
    source: str = "OSV.dev"
    status: str = "not_queried"
    retrieved_at: str | None = None
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
