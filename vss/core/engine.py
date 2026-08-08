from __future__ import annotations
import os
from dataclasses import dataclass

from .model import Report, Finding, Severity
from . import hashing, pe, ioc, winsec, iso, archive, reputation, hidden, peplus, yarascan


@dataclass
class Options:
    defender: bool = True
    reputation: bool = False
    vt_key: str = ""
    deep: bool = True
    stream_scan: bool = True


CRACK_FILES = ("steam_api", "steam_api64", "steam_emu", "steamclient", "hlm", "onlinefix", "cream_api")


def analyze(path: str, options: Options | None = None, progress=None) -> Report:
    opt = options or Options()
    rep = Report(target=path)

    def step(msg, frac=None):
        rep.note(msg)
        if progress:
            progress(msg, frac)

    if not os.path.exists(path):
        rep.add(Finding("input", "File not found", Severity.HIGH, path))
        rep.compute_verdict()
        return rep

    if os.path.isdir(path):
        rep.kind = "folder"
        _analyze_folder(path, rep, opt, step)
    elif archive.looks_like_iso(path):
        rep.kind = "iso"
        _analyze_iso(path, rep, opt, step)
    else:
        cont = archive.detect_container(path)
        peek = pe.parse_pe(path, want_imports=False)
        if peek.is_pe:
            rep.kind = "exe" if not peek.dll else "dll"
            _analyze_pe_file(path, rep, opt, step, primary=True)
        else:
            rep.kind = "archive" if cont != "unknown" else "file"
            _analyze_blob(path, rep, opt, step, container=cont)

    import time
    _reconcile(rep)
    rep.finished = time.time()
    rep.compute_verdict()
    return rep


_DOWNGRADE = {
    "mining": Severity.MEDIUM, "ransom": Severity.MEDIUM, "wallet": Severity.LOW,
    "dropper": Severity.LOW, "persistence": Severity.INFO, "net": Severity.INFO, "url": Severity.INFO,
}


def _reconcile(rep):
    defender_ran = rep.meta.get("defender_ran") is True
    defender_bad = any(f.category == "defender" and f.severity >= Severity.CRITICAL for f in rep.findings)
    defender_clean = defender_ran and not defender_bad
    vt = rep.meta.get("reputation", {}) or {}
    vt_bad = bool(vt.get("found")) and vt.get("malicious", 0) >= 1
    signed_valid = (rep.meta.get("signature", {}) or {}).get("status") == "Valid"
    if defender_bad or vt_bad:
        return
    if not (defender_clean or signed_valid):
        return
    note = "  ⚠ Text match only, not corroborated by antivirus/signature (possible false positive)."
    for f in rep.findings:
        target = _DOWNGRADE.get(f.category)
        if target is not None and f.severity > target:
            f.severity = target
            f.detail = (f.detail + note).strip()


def _hash_and_meta(path, rep, step):
    step("Computing hash and file info…", 0.02)
    size = hashing.file_size(path)
    hashes = hashing.file_hashes(path)
    rep.meta["size"] = size
    rep.meta["size_human"] = hashing.human_size(size)
    rep.meta["sha256"] = hashes["sha256"]
    rep.meta["md5"] = hashes["md5"]
    return hashes


def _sig_finding(path, rep, step, is_crack_name=False):
    step("Checking digital signature…", 0.1)
    sig = winsec.authenticode(path)
    rep.meta["signature"] = sig
    st = sig.get("status", "Unknown")
    signer = sig.get("signer", "")
    if st == "Valid":
        rep.add(Finding("signature", f"Valid digital signature ({_cn(signer)})", Severity.INFO,
                        "The file is signed and has not been modified."))
    elif st == "HashMismatch":
        sev = Severity.INFO if is_crack_name else Severity.MEDIUM
        note = ("Typical of a crack: a DLL signed by the original publisher but modified."
                if is_crack_name else
                "The file was modified AFTER being signed. Suspicious unless it is a known crack.")
        rep.add(Finding("signature", f"Signature mismatch (HashMismatch) — {_cn(signer)}", sev, note))
    elif st == "NotSigned":
        rep.add(Finding("signature", "No digital signature", Severity.LOW,
                        "Normal for games and repacks; on its own it does not indicate malware."))
    else:
        rep.add(Finding("signature", f"Signature: {st}", Severity.LOW, sig.get("error", "")))


def _pe_findings(path, rep, step, label=""):
    step(f"Analyzing PE structure {label}…".strip(), 0.2)
    info = pe.parse_pe(path, want_imports=True)
    if not info.is_pe:
        return info
    rep.meta.setdefault("pe", {})[os.path.basename(path)] = {
        "is64": info.is_64,
        "dll": info.dll,
        "packed": info.packed,
        "sections": [(s.name, s.entropy) for s in info.sections],
        "imports": {k: v[:20] for k, v in info.imports.items()},
    }
    net_imports = [f for f in info.import_names if _is_net_import(f)]
    if net_imports:
        rep.meta.setdefault("net_imports", {})[os.path.basename(path)] = sorted(set(net_imports))[:10]
    return info


_NOISY_CAPS = {"dynamic-loading", "anti-debug"}


def _advanced(path, rep, step, label="", quiet=False, do_yara=True):
    if not quiet:
        step(f"Deep analysis {label}".strip(), 0.45)
    pr = peplus.analyze(path)
    if pr.ok:
        if not quiet:
            rep.meta.setdefault("peplus", {})[os.path.basename(path)] = {
                "imphash": pr.imphash, "packer": pr.packer, "tls": pr.tls_callbacks,
                "overlay": pr.overlay, "capabilities": list(pr.capabilities),
            }
        if pr.packer:
            sev = Severity.LOW if pr.packer in ("UPX", "PyInstaller") else Severity.MEDIUM
            rep.add(Finding("packer", f"Protector/packer: {pr.packer} {label}".strip(), sev,
                            "Protected or compressed code; common in cracks and also in malware."))
        elif pr.high_entropy_sections and not quiet:
            rep.add(Finding("packer", f"Packed executable (high entropy) {label}".strip(), Severity.LOW,
                            "Compressed/encrypted sections.", evidence=pr.high_entropy_sections[:4]))
        if pr.wx_sections:
            rep.add(Finding("pe-anomaly", f"Writable+executable sections {label}".strip(), Severity.MEDIUM,
                            "Allow self-modifying code; a sign of a packer or shellcode.",
                            evidence=pr.wx_sections[:6]))
        if pr.tls_callbacks and not quiet:
            rep.add(Finding("pe-anomaly", f"TLS callbacks {label}".strip(), Severity.LOW,
                            "Runs code before the entry point (early start / anti-analysis)."))
        inj = pr.capabilities.get("injection")
        if inj and len(inj) >= 3:
            rep.add(Finding("capability", f"Process injection capability {label}".strip(), Severity.MEDIUM,
                            "Uses several code-injection APIs targeting other processes.", evidence=inj))
        if not quiet:
            caps = sorted(c for c in pr.capabilities if c not in _NOISY_CAPS and c != "injection")
            if caps:
                rep.add(Finding("capability", f"Binary capabilities {label}".strip(), Severity.INFO,
                                "What the binary is able to do (informational).", evidence=caps))
    if do_yara:
        for h in yarascan.scan_file(path):
            rep.add(Finding(f"yara:{h.category}", f"[YARA] {h.desc} {label}".strip(), h.severity,
                            f"Rule: {h.rule}", evidence=h.matched[:8]))


def _bulk_yara(files, rep, step, cap=300):
    if not yarascan.available():
        return
    step("Applying YARA rules to files…", 0.55)
    groups: dict[str, dict] = {}
    for f in files[:cap]:
        for h in yarascan.scan_file(f):
            g = groups.setdefault(h.rule, {"hit": h, "files": []})
            g["files"].append(os.path.basename(f))
    for rule, g in groups.items():
        h = g["hit"]
        rep.add(Finding(f"yara:{h.category}", f"[YARA] {h.desc}", h.severity,
                        f"Rule: {h.rule} — {len(g['files'])} file(s)", evidence=g["files"][:15]))


def _ioc_findings(path, rep, step, stream=False, label=""):
    step(f"Indicator sweep {label}…".strip(), 0.35)
    if stream:
        hits = ioc.scan_file_stream(path, progress=lambda d, t: progress_frac(step, d, t))
    else:
        try:
            with open(path, "rb") as f:
                data = f.read(64 * 1024 * 1024)
            hits = ioc.scan_bytes(data)
        except OSError:
            hits = {}
    _emit_ioc(hits, rep, label)
    return hits


def _emit_ioc(hits, rep, label=""):
    for key, samples in hits.items():
        if key == "url":
            rep.add(Finding("url", f"Unrecognized embedded URLs {label}".strip(), Severity.INFO,
                            "Check the destination.", evidence=samples[:10]))
            continue
        cat = ioc.cat_by_key(key)
        if not cat:
            continue
        rep.add(Finding(cat.key, f"{cat.label} {label}".strip(), cat.severity,
                        "High-risk pattern matches." if cat.severity >= Severity.HIGH
                        else "Matches detected.", evidence=samples[:12]))


def _defender(path, rep, step, label=""):
    if not step_defender_available(rep):
        return
    step(f"Scanning with Windows Defender {label}… (may take a while)".strip(), 0.6)
    res = winsec.defender_scan(path)
    if res.get("ran"):
        rep.meta["defender_ran"] = True
        threats = res.get("threats") or []
        if threats:
            rep.add(Finding("defender", "Windows Defender detected threats", Severity.CRITICAL,
                            "The system antivirus flagged this content.", evidence=threats[:10]))
        else:
            rep.add(Finding("defender", f"Windows Defender: no threats {label}".strip(), Severity.INFO,
                            "The system antivirus did not detect anything."))
    else:
        rep.add(Finding("defender", "Could not run Windows Defender", Severity.INFO,
                        res.get("error", "")))


def step_defender_available(rep) -> bool:
    if "defender_available" not in rep.meta:
        st = winsec.defender_status()
        rep.meta["defender_available"] = bool(st.get("engine"))
        rep.meta["defender_info"] = st
    return rep.meta["defender_available"]


def _reputation(rep, step, sha256):
    if not sha256:
        return
    step("Checking online reputation (VirusTotal)…", 0.75)
    res = reputation.virustotal_lookup(sha256, rep.meta.get("_vtkey", ""))
    rep.meta["reputation"] = res
    if res.get("available") and res.get("found"):
        mal = res.get("malicious", 0)
        if mal >= 3:
            rep.add(Finding("reputation", f"VirusTotal: {mal} engines flag it as malicious", Severity.HIGH,
                            "Detected by several antivirus engines."))
        elif mal >= 1:
            rep.add(Finding("reputation", f"VirusTotal: {mal} engine(s) flag it", Severity.MEDIUM,
                            "Could be a false positive from the crack; review it."))
        else:
            rep.add(Finding("reputation", "VirusTotal: clean", Severity.INFO,
                            "No engine flags it as malicious."))


def _analyze_pe_file(path, rep, opt, step, primary=False):
    _hash_and_meta(path, rep, step)
    is_crack = any(k in os.path.basename(path).lower() for k in CRACK_FILES)
    _sig_finding(path, rep, step, is_crack_name=is_crack)
    _pe_findings(path, rep, step)
    _advanced(path, rep, step)
    _ioc_findings(path, rep, step, stream=False)
    if opt.defender:
        _defender(path, rep, step)
    if opt.reputation:
        rep.meta["_vtkey"] = opt.vt_key
        _reputation(rep, step, rep.meta.get("sha256", ""))
    rep.meta["deep_inspected"] = True


def _analyze_blob(path, rep, opt, step, container="unknown"):
    hashes = _hash_and_meta(path, rep, step)
    rep.meta["container"] = container
    if container != "unknown":
        rep.add(Finding("container", f"Container detected: {container}", Severity.INFO,
                        "The inner files are compressed; only what is accessible is checked."))
    if hashing.file_size(path) <= 400 * 1024 * 1024:
        for h in yarascan.scan_file(path):
            rep.add(Finding(f"yara:{h.category}", f"[YARA] {h.desc}", h.severity,
                            f"Rule: {h.rule}", evidence=h.matched[:8]))
    _ioc_findings(path, rep, step, stream=opt.stream_scan)
    if opt.defender:
        _defender(path, rep, step)
    if opt.reputation:
        rep.meta["_vtkey"] = opt.vt_key
        _reputation(rep, step, hashes["sha256"])


_HIDDEN_SEV = {
    "double_ext": Severity.HIGH,
    "hidden_exec": Severity.HIGH,
    "masquerade": Severity.HIGH,
    "hidden_lib": Severity.MEDIUM,
}
_HIDDEN_TITLE = {
    "double_ext": "Files with deceptive double extension",
    "hidden_exec": "Hidden executables",
    "masquerade": "Executables disguised as data",
    "hidden_lib": "Hidden libraries in unusual locations",
}


def _hidden_findings(files, rep, step):
    step("Looking for hidden or disguised executables…", 0.5)
    hits = hidden.scan(files)
    rep.meta["hidden_exes"] = len(hits)
    if not hits:
        rep.add(Finding("hidden", "No hidden or disguised executables", Severity.INFO,
                        "No hidden .exe, double-extension or data-disguised executables found."))
        return
    groups: dict[str, list] = {}
    for h in hits:
        groups.setdefault(h.kind, []).append(h)
    for kind, items in groups.items():
        ev = [f"{h.path}  ·  {h.reason}" for h in items[:20]]
        rep.add(Finding("hidden", f"{_HIDDEN_TITLE.get(kind, 'Hidden executable')} ({len(items)})",
                        _HIDDEN_SEV.get(kind, Severity.HIGH),
                        "A legitimate game does not hide executables like this; review carefully.",
                        evidence=ev))
    for h in hits:
        if h.kind in ("hidden_exec", "masquerade", "double_ext"):
            try:
                with open(h.path, "rb") as f:
                    _emit_ioc(ioc.scan_bytes(f.read(16 * 1024 * 1024)), rep,
                              label=f"(hidden: {os.path.basename(h.path)})")
            except OSError:
                pass


def _analyze_iso(path, rep, opt, step):
    _hash_and_meta(path, rep, step)
    rep.meta["mark_of_web"] = iso.is_mark_of_web(path)
    if not opt.deep:
        rep.add(Finding("iso", "ISO detected (shallow mode)", Severity.INFO,
                        "Enable deep analysis to inspect the contents."))
        return
    step("Mounting ISO read-only…", 0.15)
    drive = iso.mount(path)
    if not drive:
        rep.add(Finding("iso", "Could not mount the ISO", Severity.MEDIUM,
                        "Analyzed as a compressed file instead."))
        _ioc_findings(path, rep, step, stream=opt.stream_scan)
        return
    rep.meta["mounted"] = drive
    try:
        files = iso.walk(drive)
        rep.meta["iso_files"] = len(files)
        exes = [f for f in files if f.lower().endswith((".exe", ".dll"))]
        bins = [f for f in files if f.lower().endswith(".bin")]
        step(f"Contents: {len(files)} files, {len(exes)} executables.", 0.2)
        _hidden_findings(files, rep, step)
        for ex in exes[:12]:
            is_crack = any(k in os.path.basename(ex).lower() for k in CRACK_FILES)
            _sig_finding(ex, rep, step, is_crack_name=is_crack)
            _pe_findings(ex, rep, step, label=f"({os.path.basename(ex)})")
            _advanced(ex, rep, step, label=f"({os.path.basename(ex)})", quiet=True, do_yara=False)
        _bulk_yara(exes, rep, step)
        for b in bins:
            if opt.stream_scan:
                _ioc_findings(b, rep, step, stream=True, label=f"({os.path.basename(b)})")
        if opt.defender:
            _defender(drive, rep, step, label="(ISO)")
        if opt.reputation:
            rep.meta["_vtkey"] = opt.vt_key
            _reputation(rep, step, rep.meta.get("sha256", ""))
    finally:
        step("Unmounting ISO…", 0.95)
        iso.dismount(path)


def _analyze_folder(path, rep, opt, step):
    files = iso.walk(path)
    rep.meta["folder_files"] = len(files)
    exes = [f for f in files if f.lower().endswith((".exe", ".dll"))]
    step(f"Folder: {len(files)} files, {len(exes)} executables.", 0.1)
    packed = 0
    for ex in exes:
        info = pe.parse_pe(ex, want_imports=False)
        if info.is_pe and info.packed:
            packed += 1
    rep.meta["packed_count"] = packed
    _hidden_findings(files, rep, step)
    for ex in exes[:120]:
        _advanced(ex, rep, step, label=f"({os.path.basename(ex)})", quiet=True, do_yara=False)
    _bulk_yara(exes, rep, step)
    for ex in exes:
        if any(k in os.path.basename(ex.lower()) for k in CRACK_FILES):
            _sig_finding(ex, rep, step, is_crack_name=True)
    if opt.defender:
        _defender(path, rep, step, label="(folder)")
    rep.meta["deep_inspected"] = True


def progress_frac(step, done, total):
    if total:
        step(f"Sweeping… {done/1e9:.2f} GB", min(0.9, 0.35 + 0.5 * done / total))


def _is_net_import(name: str) -> bool:
    n = name.lower()
    return any(x in n for x in ("socket", "wsastartup", "internetopen", "winhttp", "httpsend",
                                "urldownload", "connect", "getaddrinfo", "wsaconnect"))


def _cn(subject: str) -> str:
    for part in subject.split(","):
        part = part.strip()
        if part.upper().startswith("CN="):
            return part[3:]
    return subject[:40]
