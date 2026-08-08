from __future__ import annotations
import subprocess
import json


def _ps(script: str, timeout: int = 900) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except FileNotFoundError:
        return 127, "", "powershell not found"


def authenticode(path: str) -> dict:
    script = (
        "$s = Get-AuthenticodeSignature -LiteralPath %s; "
        "$o = [ordered]@{ status = $s.Status.ToString(); "
        "signer = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { '' }; "
        "issuer = if ($s.SignerCertificate) { $s.SignerCertificate.Issuer } else { '' } }; "
        "$o | ConvertTo-Json -Compress"
    ) % _q(path)
    rc, out, err = _ps(script, timeout=60)
    if rc == 0 and out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {"status": "Unknown", "signer": "", "issuer": "", "error": err}


def defender_status() -> dict:
    script = (
        "$s = Get-MpComputerStatus; [ordered]@{ engine = $s.AMEngineVersion; "
        "sig = $s.AntivirusSignatureVersion; realtime = $s.RealTimeProtectionEnabled; "
        "enabled = $s.AntivirusEnabled } | ConvertTo-Json -Compress"
    )
    rc, out, err = _ps(script, timeout=60)
    if rc == 0 and out:
        try:
            return json.loads(out)
        except json.JSONDecodeError:
            pass
    return {"available": False, "error": err}


def defender_scan(path: str, timeout: int = 1200) -> dict:
    script = (
        "$before = (Get-MpThreatDetection -ErrorAction SilentlyContinue).Count; "
        "Start-MpScan -ScanType CustomScan -ScanPath %s; "
        "$t = Get-MpThreatDetection -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Resources -match [regex]::Escape(%s) }; "
        "$names = @(); if ($t) { $names = $t | ForEach-Object { $_.ThreatID.ToString() } }; "
        "[ordered]@{ ran = $true; threats = @($names) } | ConvertTo-Json -Compress"
    ) % (_q(path), _q(path))
    rc, out, err = _ps(script, timeout=timeout)
    if rc == 0 and out:
        try:
            data = json.loads(out)
            th = data.get("threats") or []
            if isinstance(th, str):
                th = [th]
            return {"ran": True, "threats": th}
        except json.JSONDecodeError:
            pass
    return {"ran": False, "error": err or f"rc={rc}"}


def _q(path: str) -> str:
    return "'" + path.replace("'", "''") + "'"
