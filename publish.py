from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
VERSION_PY = os.path.join(ROOT, "vss", "version.py")
UPDATE_JSON = os.path.join(ROOT, "update.json")
DIST_EXE = os.path.join(ROOT, "dist", "VoidsSecureSystem.exe")


def read_version() -> str:
    with open(VERSION_PY, encoding="utf-8") as f:
        m = re.search(r'__version__\s*=\s*"([^"]+)"', f.read())
    return m.group(1) if m else "0.0.0"


def set_version(v: str):
    with open(VERSION_PY, encoding="utf-8") as f:
        text = f.read()
    text = re.sub(r'__version__\s*=\s*"[^"]+"', f'__version__ = "{v}"', text)
    with open(VERSION_PY, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Builds and prepares the update manifest.")
    ap.add_argument("--version", help="New version, e.g. 2.2.0")
    ap.add_argument("--notes", default="", help="Release notes for this version")
    ap.add_argument("--url", default="", help="Download URL of the .exe")
    ap.add_argument("--no-build", action="store_true")
    args = ap.parse_args()

    if args.version:
        set_version(args.version)
        print(f"version -> {args.version}")

    if not args.no_build:
        subprocess.check_call([sys.executable, "build.py"], cwd=ROOT)

    if not os.path.exists(DIST_EXE):
        print("dist/VoidsSecureSystem.exe not found; build it first")
        return 1

    manifest = {}
    if os.path.exists(UPDATE_JSON):
        with open(UPDATE_JSON, encoding="utf-8") as f:
            manifest = json.load(f)

    manifest["version"] = read_version()
    manifest["sha256"] = sha256(DIST_EXE)
    if args.url:
        manifest["url"] = args.url
    if args.notes:
        manifest["notes"] = args.notes
    manifest.setdefault("url", "https://github.com/zurualt/voids-secure-system/releases/latest/download/VoidsSecureSystem.exe")
    manifest.setdefault("mandatory", False)

    with open(UPDATE_JSON, "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
        f.write("\n")

    print(f"\nmanifest updated -> {UPDATE_JSON}")
    print(f"  version : {manifest['version']}")
    print(f"  sha256  : {manifest['sha256']}")
    print("\nnext steps:")
    print("  1) upload dist/VoidsSecureSystem.exe as a release asset (exact name VoidsSecureSystem.exe)")
    print("  2) push update.json to the repo at the path UPDATE_URL points to (vss/version.py)")
    print("  open apps will detect it and offer to update.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
