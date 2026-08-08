from __future__ import annotations
import os
import struct
from dataclasses import dataclass

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4

EXEC_LAUNCHABLE = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".msi", ".cpl", ".jar",
}
BINARY_LEGIT = {
    ".exe", ".dll", ".scr", ".cpl", ".sys", ".ocx", ".ax", ".drv", ".efi",
    ".node", ".pyd", ".mun", ".tsp", ".acm", ".msstyles", ".mui", ".winmd",
}
DATA_MASK = {
    ".txt", ".log", ".dat", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf",
    ".doc", ".docx", ".xls", ".xlsx", ".mp3", ".mp4", ".avi", ".ini", ".json",
    ".xml", ".cfg", ".sav", ".tmp", ".db", ".ico",
}
DOUBLE_LURE = {".txt", ".pdf", ".jpg", ".jpeg", ".png", ".doc", ".docx",
               ".xls", ".xlsx", ".mp4", ".mp3", ".gif", ".avi", ".zip"}


@dataclass
class HiddenHit:
    path: str
    kind: str
    reason: str


def _attributes(path: str) -> int:
    try:
        return os.stat(path).st_file_attributes
    except (OSError, AttributeError):
        return 0


def is_pe(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            if f.read(2) != b"MZ":
                return False
            f.seek(0x3C)
            raw = f.read(4)
            if len(raw) < 4:
                return False
            f.seek(struct.unpack("<I", raw)[0])
            return f.read(4) == b"PE\x00\x00"
    except (OSError, struct.error):
        return False


def scan(files: list[str]) -> list[HiddenHit]:
    hits: list[HiddenHit] = []
    for path in files:
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        attrs = _attributes(path)
        concealed = bool(attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))

        segs = name.split(".")
        if len(segs) >= 3 and "." + segs[-1] in EXEC_LAUNCHABLE and "." + segs[-2] in DOUBLE_LURE:
            hits.append(HiddenHit(path, "double_ext", f"Deceptive double extension (.{segs[-2]}.{segs[-1]})"))
            continue

        if concealed and ext in EXEC_LAUNCHABLE:
            hits.append(HiddenHit(path, "hidden_exec", "Executable with hidden/system attribute"))
            continue

        if ext in DATA_MASK and is_pe(path):
            hits.append(HiddenHit(path, "masquerade", f"Executable disguised as a data file ({ext})"))
            continue

        if ext == "" and is_pe(path):
            hits.append(HiddenHit(path, "masquerade", "Executable with no extension"))
            continue

        if concealed and ext in (".dll", ".sys") and _in_odd_location(path):
            hits.append(HiddenHit(path, "hidden_lib", "Hidden library in an unusual location"))

    return hits


def _in_odd_location(path: str) -> bool:
    low = path.lower()
    return any(seg in low for seg in ("\\temp\\", "\\appdata\\", "\\public\\", "\\programdata\\", "\\recycle"))
