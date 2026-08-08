from __future__ import annotations
import argparse
import sys
import json

from .core.engine import analyze, Options
from .core.model import SEVERITY_LABEL, VERDICT_LABEL, Severity


def _c(text, code):
    return f"\x1b[{code}m{text}\x1b[0m"


SEV_COLOR = {
    Severity.OK: 32, Severity.INFO: 36, Severity.LOW: 36,
    Severity.MEDIUM: 33, Severity.HIGH: 31, Severity.CRITICAL: 91,
}


def main(argv=None):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    ap = argparse.ArgumentParser(prog="vss", description="Analyzes a file/ISO/folder and tells you if it is safe.")
    ap.add_argument("path")
    ap.add_argument("--no-defender", action="store_true")
    ap.add_argument("--vt", metavar="APIKEY", default="", help="Query VirusTotal with this API key")
    ap.add_argument("--shallow", action="store_true", help="Do not mount or inspect inside the ISO")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    opt = Options(
        defender=not args.no_defender,
        reputation=bool(args.vt),
        vt_key=args.vt,
        deep=not args.shallow,
    )

    def progress(msg, frac):
        if not args.json:
            bar = "" if frac is None else f"[{int(frac*100):3d}%] "
            print(_c(f"  {bar}{msg}", 90), file=sys.stderr)

    rep = analyze(args.path, opt, progress)
    d = rep.to_dict()

    if args.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
        return 0

    print()
    print("=" * 64)
    print(f"  VERDICT: {_c(d['verdict_label'], 1)}   ({d['kind']}, {d['duration_s']}s, risk {d['score']}/100)")
    print("=" * 64)
    m = d["meta"]
    if m.get("sha256"):
        print(f"  File : {rep.target}")
        print(f"  Size : {m.get('size_human','?')}   SHA256: {m['sha256'][:32]}…")
    print()
    print(f"  Findings ({len(d['findings'])}):")
    for f in d["findings"]:
        sev = Severity(f["severity"])
        tag = _c(f"[{SEVERITY_LABEL[sev]:>7}]", SEV_COLOR[sev])
        print(f"   {tag} {f['title']}")
        if f["detail"]:
            print(_c(f"            {f['detail']}", 90))
        for ev in f["evidence"][:6]:
            print(_c(f"              · {ev[:100]}", 90))
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
