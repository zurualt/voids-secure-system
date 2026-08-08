from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from typing import Any
import time


class Severity(IntEnum):
    OK = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


SEVERITY_LABEL = {
    Severity.OK: "Clean",
    Severity.INFO: "Info",
    Severity.LOW: "Low",
    Severity.MEDIUM: "Medium",
    Severity.HIGH: "High",
    Severity.CRITICAL: "Critical",
}


class Verdict(IntEnum):
    CLEAN = 0
    LIKELY_CLEAN = 1
    SUSPICIOUS = 2
    DANGEROUS = 3
    UNKNOWN = 4


VERDICT_LABEL = {
    Verdict.CLEAN: "CLEAN",
    Verdict.LIKELY_CLEAN: "LIKELY CLEAN",
    Verdict.SUSPICIOUS: "SUSPICIOUS",
    Verdict.DANGEROUS: "DANGEROUS",
    Verdict.UNKNOWN: "UNKNOWN",
}

VERDICT_COLOR = {
    Verdict.CLEAN: "#2ecc71",
    Verdict.LIKELY_CLEAN: "#27ae60",
    Verdict.SUSPICIOUS: "#f39c12",
    Verdict.DANGEROUS: "#e74c3c",
    Verdict.UNKNOWN: "#7f8c8d",
}


@dataclass
class Finding:
    category: str
    title: str
    severity: Severity
    detail: str = ""
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = int(self.severity)
        d["severity_label"] = SEVERITY_LABEL[self.severity]
        return d


@dataclass
class Report:
    target: str
    kind: str = "unknown"
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    verdict: Verdict = Verdict.UNKNOWN
    score: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def note(self, text: str) -> None:
        self.steps.append(text)

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.OK
        return max(f.severity for f in self.findings)

    def compute_score(self) -> int:
        weight = {Severity.OK: 0, Severity.INFO: 0, Severity.LOW: 2,
                  Severity.MEDIUM: 10, Severity.HIGH: 26, Severity.CRITICAL: 55}
        by_cat: dict[str, list[Severity]] = {}
        for f in self.findings:
            k = f.category.split(":")[0]
            by_cat.setdefault(k, []).append(f.severity)
        total = 0.0
        for sevs in by_cat.values():
            top = max(weight[s] for s in sevs)
            rest = sum(weight[s] for s in sevs) - top
            total += top + 0.25 * rest
        self.score = int(min(100, round(total)))
        return self.score

    def compute_verdict(self) -> Verdict:
        self.compute_score()
        mx = self.max_severity
        has_av = self.meta.get("defender_ran") is True
        deep = self.meta.get("deep_inspected") is True
        if mx >= Severity.CRITICAL:
            self.verdict = Verdict.DANGEROUS
        elif mx >= Severity.HIGH:
            self.verdict = Verdict.SUSPICIOUS
        elif mx >= Severity.MEDIUM:
            self.verdict = Verdict.SUSPICIOUS
        elif has_av and deep:
            self.verdict = Verdict.CLEAN
        elif has_av:
            self.verdict = Verdict.LIKELY_CLEAN
        else:
            self.verdict = Verdict.LIKELY_CLEAN if mx <= Severity.LOW else Verdict.SUSPICIOUS
        return self.verdict

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "kind": self.kind,
            "started": self.started,
            "finished": self.finished,
            "duration_s": round((self.finished or time.time()) - self.started, 2),
            "meta": self.meta,
            "verdict": int(self.verdict),
            "verdict_label": VERDICT_LABEL[self.verdict],
            "score": self.score,
            "max_severity": int(self.max_severity),
            "steps": self.steps,
            "findings": [f.to_dict() for f in sorted(self.findings, key=lambda x: -int(x.severity))],
        }
