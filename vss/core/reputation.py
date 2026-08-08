from __future__ import annotations
import json
import base64
import urllib.request
import urllib.error


def virustotal_lookup(sha256: str, api_key: str, timeout: int = 20) -> dict:
    if not api_key:
        return {"available": False, "reason": "sin API key"}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {
            "available": True,
            "found": True,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"available": True, "found": False}
        return {"available": False, "reason": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as e:
        return {"available": False, "reason": str(e)}


def virustotal_url(url: str, api_key: str, timeout: int = 20) -> dict:
    if not api_key:
        return {"available": False, "reason": "sin API key"}
    uid = base64.urlsafe_b64encode(url.encode("utf-8")).decode().strip("=")
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/urls/{uid}",
                                 headers={"x-apikey": api_key})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return {"available": True, "found": True, "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0)}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"available": True, "found": False}
        return {"available": False, "reason": f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as e:
        return {"available": False, "reason": str(e)}
