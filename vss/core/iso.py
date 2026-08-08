from __future__ import annotations
import os
from .winsec import _ps, _q


def mount(path: str) -> str | None:
    script = (
        "$img = Mount-DiskImage -ImagePath %s -Access ReadOnly -PassThru -ErrorAction Stop; "
        "Start-Sleep -Milliseconds 800; "
        "(Get-Volume -DiskImage $img).DriveLetter"
    ) % _q(path)
    rc, out, err = _ps(script, timeout=120)
    letter = (out or "").strip().splitlines()[-1].strip() if out else ""
    if rc == 0 and len(letter) == 1 and letter.isalpha():
        return f"{letter}:\\"
    return None


def dismount(path: str) -> bool:
    rc, out, err = _ps("Dismount-DiskImage -ImagePath %s | Out-Null; 'ok'" % _q(path), timeout=120)
    return rc == 0


def walk(root: str, max_files: int = 20000) -> list[str]:
    found: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            found.append(os.path.join(dirpath, name))
            if len(found) >= max_files:
                return found
    return found


def is_mark_of_web(path: str) -> bool:
    try:
        with open(path + ":Zone.Identifier", "r", errors="ignore") as f:
            return "ZoneId=3" in f.read()
    except OSError:
        return False
