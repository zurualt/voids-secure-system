from __future__ import annotations
import re
import ipaddress
from urllib.parse import urlparse, unquote

from .model import Report, Finding, Severity
from . import reputation

SUSPECT_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "click", "link", "country",
    "kim", "work", "party", "gdn", "review", "stream", "download", "loan", "racing", "win",
    "bid", "date", "faith", "science", "men", "cam", "rest", "quest", "sbs", "cfd",
}
SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "cutt.ly", "rebrand.ly", "shorturl.at", "t.me", "rb.gy", "shorte.st", "bc.vc",
}
BRANDS = {
    "paypal", "steam", "steamcommunity", "steampowered", "valve", "epicgames", "microsoft",
    "office365", "outlook", "google", "gmail", "apple", "icloud", "amazon", "netflix",
    "binance", "coinbase", "metamask", "trezor", "ledger", "whatsapp", "instagram",
    "facebook", "discord", "nintendo", "playstation", "xbox", "roblox", "riotgames",
    "battlenet", "blizzard", "mercadolibre", "santander", "bbva",
}
BAIT = re.compile(
    r"login|signin|verify|verification|account|update|secure|unlock|confirm|billing|"
    r"free|gratis|regalo|gift[-_]?card|giveaway|sorteo|robux|v-?bucks|nitro|recarga|"
    r"crack|keygen|activation|activador|serial|hack|cheat|premium[-_]?free", re.I)
DL_EXEC = re.compile(r"\.(exe|scr|com|pif|bat|cmd|msi|vbs|js|jar|apk|hta|ps1|iso)(\?|$)", re.I)
DL_ARCH = re.compile(r"\.(zip|rar|7z|gz|tar)(\?|$)", re.I)


def analyze_url(url: str, vt_key: str = "") -> Report:
    rep = Report(target=url, kind="url")
    raw = url.strip()
    if "://" not in raw:
        raw = "http://" + raw
    p = urlparse(raw)
    host = (p.hostname or "").lower()
    netloc = p.netloc.lower()
    path = unquote(p.path or "")
    full = unquote(raw)

    if not host:
        rep.add(Finding("url", "Could not parse the URL", Severity.MEDIUM, raw))
        rep.compute_verdict()
        return rep

    rep.meta["host"] = host
    rep.meta["scheme"] = p.scheme

    if p.scheme not in ("https",):
        rep.add(Finding("transport", "No HTTPS encryption", Severity.LOW,
                        "The link does not use HTTPS; data would travel unencrypted."))

    if "@" in netloc:
        rep.add(Finding("deception", "Credentials embedded in the URL (@)", Severity.HIGH,
                        "The text before '@' hides the link's real destination."))

    if _is_ip(host):
        rep.add(Finding("host", "The URL uses an IP address instead of a domain", Severity.HIGH,
                        "Typical of phishing pages and malware control panels."))

    if "xn--" in host:
        rep.add(Finding("deception", "Punycode domain (possible homograph)", Severity.HIGH,
                        "May visually imitate a real brand using letters from another alphabet."))

    labels = host.split(".")
    tld = labels[-1] if len(labels) > 1 else ""
    reg = ".".join(labels[-2:]) if len(labels) >= 2 else host
    if tld in SUSPECT_TLDS:
        rep.add(Finding("host", f"High-abuse top-level domain (.{tld})", Severity.MEDIUM,
                        "These TLDs concentrate a lot of phishing and malware."))

    if reg in SHORTENERS:
        rep.add(Finding("deception", "Link shortener", Severity.MEDIUM,
                        "Hides the real destination; you cannot tell where it leads without opening it."))

    if len([x for x in labels if x]) >= 5:
        rep.add(Finding("host", "Too many subdomains", Severity.MEDIUM,
                        "Long subdomains often hide the real domain.", evidence=[host]))

    if len(host) > 40:
        rep.add(Finding("host", "Unusually long host name", Severity.LOW, host))

    if p.port and p.port not in (80, 443):
        rep.add(Finding("host", f"Non-standard port ({p.port})", Severity.LOW,
                        "Uncommon on legitimate sites."))

    brand = _impersonated_brand(host, path)
    if brand:
        rep.add(Finding("deception", f"Possible brand impersonation: {brand}", Severity.HIGH,
                        f"It mentions '{brand}' but the real domain is '{reg}', which is not the official one."))

    if DL_EXEC.search(path) or DL_EXEC.search(p.query or ""):
        rep.add(Finding("payload", "Direct executable download", Severity.HIGH,
                        "The link points to an executable file; high risk.", evidence=[path[:120]]))
    elif DL_ARCH.search(path):
        rep.add(Finding("payload", "Archive download", Severity.LOW,
                        "May contain executables; scan it after downloading."))

    baits = sorted(set(m.group(0).lower() for m in BAIT.finditer(full)))
    if baits:
        sev = Severity.MEDIUM if brand or _is_ip(host) or tld in SUSPECT_TLDS else Severity.LOW
        rep.add(Finding("bait", "Typical scam bait words", sev,
                        "Terms used in phishing and scams.", evidence=baits[:8]))

    if vt_key:
        res = reputation.virustotal_url(url, vt_key)
        rep.meta["reputation"] = res
        if res.get("available") and res.get("found"):
            mal = res.get("malicious", 0)
            if mal >= 1:
                rep.add(Finding("reputation", f"VirusTotal: {mal} engine(s) flag the URL", Severity.HIGH,
                                "Reported as malicious by antivirus engines."))
            else:
                rep.add(Finding("reputation", "VirusTotal: clean URL", Severity.INFO,
                                "No engine flags it."))

    rep.compute_verdict()
    return rep


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _impersonated_brand(host: str, path: str) -> str:
    labels = host.split(".")
    reg = ".".join(labels[-2:]) if len(labels) >= 2 else host
    prefix = ".".join(labels[:-2]) if len(labels) > 2 else ""
    for b in BRANDS:
        in_sub = b in prefix or b in path.lower().split("?")[0]
        official = reg.startswith(b + ".") or reg == b + ".com" or b in reg.split(".")[0]
        if in_sub and not official:
            return b
    return ""
