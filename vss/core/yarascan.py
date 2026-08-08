from __future__ import annotations
import functools
from dataclasses import dataclass, field

from .model import Severity
from . import yara_rules

_SEV = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL,
}


@dataclass
class YaraHit:
    rule: str
    category: str
    severity: Severity
    desc: str
    matched: list[str] = field(default_factory=list)


@functools.lru_cache(maxsize=1)
def _rules():
    try:
        import yara
    except ImportError:
        return None
    try:
        return yara.compile(source=yara_rules.source())
    except Exception:
        return None


def available() -> bool:
    return _rules() is not None


def scan_file(path: str, timeout: int = 60) -> list[YaraHit]:
    r = _rules()
    if r is None:
        return []
    try:
        return [_wrap(m) for m in r.match(path, timeout=timeout)]
    except Exception:
        return []


def scan_bytes(data: bytes, timeout: int = 30) -> list[YaraHit]:
    r = _rules()
    if r is None:
        return []
    try:
        return [_wrap(m) for m in r.match(data=data, timeout=timeout)]
    except Exception:
        return []


def _wrap(m) -> YaraHit:
    meta = getattr(m, "meta", {}) or {}
    sev = _SEV.get(str(meta.get("severity", "medium")).lower(), Severity.MEDIUM)
    return YaraHit(
        rule=m.rule,
        category=str(meta.get("category", "")),
        severity=sev,
        desc=str(meta.get("desc", "")),
        matched=_matched(m),
    )


def _matched(m) -> list[str]:
    out: list[str] = []
    for s in getattr(m, "strings", []) or []:
        ident = getattr(s, "identifier", None)
        if ident is None and isinstance(s, tuple) and len(s) >= 2:
            ident = s[1]
        if ident:
            out.append(str(ident))
        if len(out) >= 8:
            break
    seen = []
    for x in out:
        if x not in seen:
            seen.append(x)
    return seen
