from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    title: str
    evidence: str
    recommendation: str


@dataclass
class Report:
    target: str
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: int | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
