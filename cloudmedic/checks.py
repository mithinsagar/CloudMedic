"""Shared result types for the network and IAM evaluators."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

PASS, FAIL, PARTIAL, SKIP = "pass", "fail", "partial", "skip"


@dataclass
class Check:
    """One hop or policy test along the evaluation of an intent.

    `fault_class` is filled when the check does not pass and names the taxonomy class that
    explains it. `ctx` carries the facts a repair generator needs (peer IP, port range,
    which rule matched, ...).
    """

    id: str
    layer: str
    resource: str | None
    status: str
    detail: str
    fault_class: str | None = None
    ctx: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in (PASS, SKIP)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Result:
    ok: bool
    checks: list[Check]
    symptom: str = ""

    @property
    def failing(self) -> list[Check]:
        return [c for c in self.checks if not c.ok]

    def to_dict(self) -> dict:
        return {"ok": self.ok, "symptom": self.symptom, "checks": [c.to_dict() for c in self.checks]}


def finish(checks: list[Check], symptom_of) -> Result:
    bad = [c for c in checks if not c.ok]
    return Result(ok=not bad, checks=checks, symptom=symptom_of(bad[0]) if bad else "success")
