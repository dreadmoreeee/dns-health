"""Plain data types shared by the checks, the resolvers and the renderers."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("ok", "info", "warning", "error")


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass(frozen=True)
class RR:
    """One resource record; `data` is the presentation (zone file) text."""

    name: str
    rtype: str
    ttl: int
    data: str


@dataclass
class Answer:
    """Result of one query.

    status: NOERROR, NODATA, NXDOMAIN, SERVFAIL, TIMEOUT or ERROR.
    rrs: every record of the answer section (including CNAMEs and RRSIGs).
    aa: authoritative-answer flag (only meaningful for direct queries).
    """

    status: str
    rrs: list[RR] = field(default_factory=list)
    aa: bool = False

    def of(self, rtype: str) -> list[RR]:
        return [r for r in self.rrs if r.rtype == rtype]

    @property
    def ok(self) -> bool:
        return self.status in ("NOERROR", "NODATA", "NXDOMAIN")


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    title: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {"check": self.check, "severity": self.severity, "title": self.title, "detail": self.detail}


@dataclass
class Report:
    domain: str
    findings: list[Finding]

    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def worst(self) -> str:
        return max((f.severity for f in self.findings), key=severity_rank, default="ok")

    def failing(self, fail_on: str) -> bool:
        threshold = severity_rank(fail_on)
        return any(severity_rank(f.severity) >= threshold for f in self.findings)
