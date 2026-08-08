from __future__ import annotations

MAGICS = {
    b"ArC\x01": "FreeArc (repack)",
    b"Rar!\x1a\x07": "RAR",
    b"PK\x03\x04": "ZIP",
    b"7z\xbc\xaf\x27\x1c": "7-Zip",
    b"MSCF": "CAB",
    b"\x1f\x8b": "GZIP",
    b"ISc(": "InstallShield",
}


def detect_container(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(16)
    except OSError:
        return "unknown"
    for magic, name in MAGICS.items():
        if head.startswith(magic):
            return name
    return "unknown"


def looks_like_iso(path: str) -> bool:
    if path.lower().endswith(".iso"):
        return True
    try:
        with open(path, "rb") as f:
            f.seek(0x8001)
            return f.read(5) == b"CD001"
    except OSError:
        return False
