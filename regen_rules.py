from __future__ import annotations
import base64
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(ROOT, "vss", "core", "rules.yar")
OUT = os.path.join(ROOT, "vss", "core", "yara_rules.py")


def main():
    with open(SRC, "rb") as f:
        raw = f.read()
    try:
        import yara
        yara.compile(source=raw.decode("utf-8"))
    except ImportError:
        print("note: yara not installed, skipping validation")
    blob = base64.b64encode(raw).decode()
    parts = [blob[i:i + 120] for i in range(0, len(blob), 120)]
    body = "from __future__ import annotations\nimport base64\n\n_B = (\n"
    for p in parts:
        body += f'    "{p}"\n'
    body += ")\n\n\ndef source() -> str:\n    return base64.b64decode(_B).decode(\"utf-8\")\n"
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    print(f"generated {OUT} ({len(blob)} b64 chars)")


if __name__ == "__main__":
    main()
