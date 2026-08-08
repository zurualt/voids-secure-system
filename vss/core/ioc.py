from __future__ import annotations
import re
import base64
import collections
from dataclasses import dataclass

from .model import Severity


def _r(token: str, flags: int = re.I) -> re.Pattern:
    return re.compile(base64.b64decode(token), flags)


@dataclass
class IocCategory:
    key: str
    label: str
    severity: Severity
    pattern: re.Pattern
    benign_if_signed: bool = False
    stream_safe: bool = True


CATEGORIES: list[IocCategory] = [
    IocCategory("mining", "Cryptocurrency mining", Severity.CRITICAL,
                _r("c3RyYXR1bVwrdGNwfHN0cmF0dW1cK3NzbHx4bXJpZ3xyYW5kb214XGJ8Y3J5cHRvbmlnaHR8LS1kb25hdGUtbGV2ZWx8LS1jcHUtcHJpb3JpdHl8bWluZXJnYXRlfHN1cHBvcnR4bXJ8bmFub3Bvb2x8bmljZWhhc2h8bWluZXhtcnxoYXNodmF1bHR8bW9uZXJvb2NlYW58ZXRobWluZXJ8Y29pbmhpdmV8bmJtaW5lcnxsb2xtaW5lcnxwaG9lbml4bWluZXJ8LS1wb29sfC1vXHMrc3RyYXR1bQ==")),
    IocCategory("wallet", "Wallet / clipboard theft", Severity.HIGH,
                _r("d2FsbGV0XC5kYXR8ZWxlY3RydW18XGJtZXRhbWFza1xifEdldENsaXBib2FyZERhdGF8U2V0Q2xpcGJvYXJkVmlld2VyfFxiNFswLTlBQl1bMC05QS1aYS16XXs5M31cYg==")),
    IocCategory("ransom", "Ransomware behavior", Severity.CRITICAL,
                _r("dnNzYWRtaW4oXC5leGUpP1xzK2RlbGV0ZVxzK3NoYWRvd3N8d2JhZG1pblxzK2RlbGV0ZVxzK2NhdGFsb2d8Y2lwaGVyXHMrL3c6fFlPVVIgRklMRVMgKEFSRXxIQVZFIEJFRU4pIEVOQ1JZUFRFRHxhbGwgeW91ciBmaWxlcyBoYXZlIGJlZW4gZW5jcnlwdGVk")),
    IocCategory("dropper", "Remote download / execution", Severity.HIGH,
                _r("LW5vcFxifC13XHMraGlkZGVufC13aW5kb3dzdHlsZVxzK2hpZGRlbnxEb3dubG9hZFN0cmluZ3xJbnZva2UtV2ViUmVxdWVzdHxGcm9tQmFzZTY0U3RyaW5nfElFWFxzKlwofGNlcnR1dGlsXHMrLXVybGNhY2hlfGJpdHNhZG1pblxzKy90cmFuc2Zlcnxtc2h0YVxzK2h0dHA="),
                stream_safe=False),
    IocCategory("persistence", "Persistence", Severity.MEDIUM,
                _r("Q3VycmVudFZlcnNpb25cXFJ1bnxzY2h0YXNrc1xzKy9jcmVhdGV8TmV3LVNlcnZpY2V8c2NcLmV4ZVxzK2NyZWF0ZXxTdGFydCBNZW51XFxQcm9ncmFtc1xcU3RhcnR1cA=="),
                stream_safe=False),
    IocCategory("net", "Network connections", Severity.LOW,
                _r("XGIoV1NBU29ja2V0fEludGVybmV0T3BlblVybHxIdHRwU2VuZFJlcXVlc3R8V2luSHR0cENvbm5lY3R8VVJMRG93bmxvYWRUb0ZpbGUpXGI="),
                stream_safe=False),
]

BENIGN_URL = _r("c2NoZW1hc1wubWljcm9zb2Z0XC5jb218ZGlnaWNlcnRcLmNvbXx2ZXJpc2lnbnxnbG9iYWxzaWdufHNlY3RpZ298Y29tb2RvY2F8anJzb2Z0d2FyZVwub3JnfHVuaXR5M2RcLmNvbXxzdGVhbXBvd2VyZWRcLmNvbXx3M1wub3JnfG9wZW54bWxmb3JtYXRz")

URL_RE = _r("aHR0cHM/Oi8vW15cc1wiJzw+XHgwMF17NCwxNjB9", 0)


def _ascii_strings(b: bytes, minlen: int = 5):
    return re.findall(rb"[\x20-\x7e]{%d,}" % minlen, b)


def _utf16_strings(b: bytes, minlen: int = 5):
    return re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, b)


def scan_bytes(data: bytes) -> dict[str, list[str]]:
    hits: dict[str, set[str]] = collections.defaultdict(set)
    blob = data
    for cat in CATEGORIES:
        for m in cat.pattern.finditer(blob):
            s = m.group(0)
            hits[cat.key].add(_clean(s))
    urls = set()
    for m in URL_RE.finditer(blob):
        u = m.group(0)
        if not BENIGN_URL.search(u):
            urls.add(_clean(u))
    if urls:
        hits["url"] = urls
    return {k: sorted(v)[:40] for k, v in hits.items()}


def scan_file_stream(path: str, progress=None, chunk_mb: int = 16) -> dict[str, list[str]]:
    hits: dict[str, set[str]] = collections.defaultdict(set)
    ch = chunk_mb * 1024 * 1024
    overlap = 4096
    import os
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        prev = b""
        while True:
            buf = f.read(ch)
            if not buf:
                break
            window = prev + buf
            for cat in CATEGORIES:
                if not cat.stream_safe:
                    continue
                for m in cat.pattern.finditer(window):
                    hits[cat.key].add(_clean(m.group(0)))
            prev = buf[-overlap:]
            done += len(buf)
            if progress:
                progress(done, total)
    return {k: sorted(v)[:40] for k, v in hits.items()}


def _clean(b: bytes) -> str:
    return b.decode("latin1", "replace").replace("\x00", "")


def cat_by_key(key: str) -> IocCategory | None:
    for c in CATEGORIES:
        if c.key == key:
            return c
    return None
