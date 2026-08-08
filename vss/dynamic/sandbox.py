from __future__ import annotations
import os
import shutil
import subprocess
import tempfile
import time
import json

HERE = os.path.dirname(os.path.abspath(__file__))
MONITOR = os.path.join(HERE, "monitor.ps1")


def is_available() -> bool:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsSandbox.exe")
    return os.path.exists(exe)


def _wsb(shared_host: str, seconds: int) -> str:
    cmd = (
        "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\shared\\monitor.ps1 "
        f"-Target C:\\shared\\target -OutFile C:\\shared\\result.json -Seconds {seconds}"
    )
    return f"""<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Default</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{shared_host}</HostFolder>
      <SandboxFolder>C:\\shared</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>{cmd}</Command>
  </LogonCommand>
</Configuration>"""


def run(target_path: str, seconds: int = 75, timeout: int = 1200, progress=None) -> dict:
    if not is_available():
        return {"available": False, "reason": "Windows Sandbox is not installed/enabled."}

    work = tempfile.mkdtemp(prefix="rgsandbox_")
    shared = os.path.join(work, "shared")
    os.makedirs(shared, exist_ok=True)
    shutil.copy2(MONITOR, os.path.join(shared, "monitor.ps1"))

    target_dst = os.path.join(shared, "target")
    if os.path.isdir(target_path):
        shutil.copytree(target_path, target_dst)
    else:
        os.makedirs(target_dst, exist_ok=True)
        shutil.copy2(target_path, os.path.join(target_dst, os.path.basename(target_path)))

    wsb_path = os.path.join(work, "run.wsb")
    with open(wsb_path, "w", encoding="utf-8") as f:
        f.write(_wsb(shared, seconds))

    result_file = os.path.join(shared, "result.json")
    if progress:
        progress("Starting Windows Sandbox (isolated environment)…", 0.1)
    try:
        subprocess.Popen(["WindowsSandbox.exe", wsb_path])
    except FileNotFoundError:
        return {"available": False, "reason": "Could not launch WindowsSandbox.exe"}

    start = time.time()
    while time.time() - start < timeout:
        if os.path.exists(result_file):
            time.sleep(1)
            try:
                with open(result_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                data["available"] = True
                return data
            except (json.JSONDecodeError, OSError):
                pass
        if progress:
            progress("Behavior test running inside the sandbox…", None)
        time.sleep(4)
    return {"available": True, "timeout": True, "reason": "The sandbox did not return a result in time."}


def summarize(data: dict) -> tuple[str, str]:
    if not data.get("available"):
        return "unavailable", data.get("reason", "")
    if data.get("timeout"):
        return "no_result", data.get("reason", "")
    if not data.get("launched"):
        return "not_run", "; ".join(data.get("notes", []))
    pool = data.get("pool_hits") or []
    children = data.get("child_processes") or []
    ext = data.get("external_connections") or []
    game_ext = [c for c in ext if c.get("game")]
    if pool:
        return "malicious", f"Connections to mining pools: {pool}"
    suspicious_children = [c for c in children if str(c).lower() not in ("unitycrashhandler64.exe", "unitycrashhandler32.exe")]
    parts = [f"{len(game_ext)} game connections (HTTPS)", f"{len(children)} child processes", f"max CPU {data.get('max_cpu_seconds')}s"]
    if suspicious_children:
        return "review", "Unexpected child processes: " + ", ".join(map(str, suspicious_children))
    return "clean", "; ".join(parts)
