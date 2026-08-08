from __future__ import annotations
import os
import re
import sys
import json
import hashlib
import tempfile
import subprocess
import urllib.request
import urllib.error

from ..version import __version__, UPDATE_URL

_NO_WINDOW = 0x08000000


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _ver(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "0")) or (0,)


def _cmp(a: str, b: str) -> int:
    va, vb = _ver(a), _ver(b)
    return (va > vb) - (va < vb)


def check(url: str = UPDATE_URL, timeout: int = 10) -> dict:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VSS-Updater"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as e:
        return {"ok": False, "reason": str(e)}
    latest = str(data.get("version", ""))
    return {
        "ok": True,
        "current": __version__,
        "latest": latest,
        "update": _cmp(latest, __version__) > 0,
        "url": data.get("url", ""),
        "sha256": str(data.get("sha256", "")).lower(),
        "notes": data.get("notes", ""),
        "mandatory": bool(data.get("mandatory", False)),
    }


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _download(url: str, dest: str, progress=None):
    req = urllib.request.Request(url, headers={"User-Agent": "VSS-Updater"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if progress and total:
                    progress(done / total)


def download_and_apply(info: dict, progress=None) -> dict:
    if not is_frozen():
        return {"ok": False, "reason": "Auto-update only works in the compiled app (.exe)."}
    url = info.get("url")
    if not url:
        return {"ok": False, "reason": "The manifest has no download URL."}
    new = os.path.join(tempfile.gettempdir(), "VSS_update_new.exe")
    try:
        _download(url, new, progress)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "reason": f"Download failed: {e}"}
    want = info.get("sha256", "")
    if want:
        got = _sha256(new).lower()
        if got != want:
            try:
                os.remove(new)
            except OSError:
                pass
            return {"ok": False, "reason": "Hash mismatch; corrupt or tampered download."}
    return _swap(sys.executable, new)


def _swap(exe: str, new: str) -> dict:
    bak = exe + ".bak"
    bat = os.path.join(tempfile.gettempdir(), "VSS_update.bat")
    lines = [
        "@echo off",
        "ping 127.0.0.1 -n 3 >nul",
        f'del /f /q "{bak}" >nul 2>&1',
        ":ren",
        f'move /y "{exe}" "{bak}" >nul 2>&1',
        "if errorlevel 1 ( ping 127.0.0.1 -n 2 >nul & goto ren )",
        f'move /y "{new}" "{exe}" >nul 2>&1',
        f'start "" "{exe}"',
        "ping 127.0.0.1 -n 3 >nul",
        f'del /f /q "{bak}" >nul 2>&1',
        'del /f /q "%~f0" >nul 2>&1',
    ]
    try:
        with open(bat, "w", encoding="ascii") as f:
            f.write("\r\n".join(lines))
        subprocess.Popen(["cmd", "/c", bat], creationflags=_NO_WINDOW,
                         close_fds=True)
    except OSError as e:
        return {"ok": False, "reason": f"Could not launch the replacement: {e}"}
    return {"ok": True, "restart": True}
