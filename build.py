from __future__ import annotations
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
SEP = ";" if os.name == "nt" else ":"


def main():
    monitor = os.path.join("vss", "dynamic", "monitor.ps1")
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "VoidsSecureSystem",
        "--onefile", "--windowed",
        "--add-data", f"{monitor}{SEP}vss/dynamic",
        "--collect-all", "tkinterdnd2",
        "--collect-all", "yara",
        "--hidden-import", "pefile",
        "run.py",
    ]
    icon = os.path.join(ROOT, "assets", "icon.ico")
    if os.path.exists(icon):
        args[args.index("--onefile"):args.index("--onefile")] = ["--icon", icon]
    print(">", " ".join(args))
    subprocess.check_call(args, cwd=ROOT)
    print("\nDone -> dist/VoidsSecureSystem.exe")


if __name__ == "__main__":
    main()
