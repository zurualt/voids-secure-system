# 🛡 Voids Secure System

**Is this pirated game / repack safe?** Pick a file and Voids Secure System checks whether it
carries a crypto miner, a hidden virus, or hidden executables — automating the work a malware
analyst would do.

It is not just another antivirus: it **leans on the antivirus you already have (Windows Defender)**
and adds static analysis, signature verification, an indicator sweep, hidden-executable hunting,
and a behavior test in an isolated environment.

---

## ⬇️ Download & install (Windows)

**➡️ [Download the installer](https://github.com/zurualt/voids-secure-system/releases/latest/download/VoidsSecureSystem_Setup.exe)**

1. Run **`VoidsSecureSystem_Setup.exe`**.
2. If Windows shows *"Windows protected your PC"*, click **More info → Run anyway** (the app is unsigned).
3. Click through the wizard — **no administrator rights needed**. A shortcut is added to the Start menu.
4. It **updates itself automatically** when a new version is released.

Prefer not to install? Grab the **[portable version](https://github.com/zurualt/voids-secure-system/releases/latest/download/VoidsSecureSystem.exe)** and just run it.

All releases: <https://github.com/zurualt/voids-secure-system/releases/latest>

---

## What it checks

### Core mode (safe — never runs the file)
- **YARA engine** with custom rules: miners (XMRig, pool protocols, domains), infostealers
  (browser credentials, wallets, Telegram exfiltration), injection / process hollowing,
  packers/protectors (UPX, Themida, VMProtect, Enigma), obfuscated PowerShell, LOLBins, anti-VM,
  ransomware and Steam emulators.
- **Deep PE analysis** (`pefile`): imphash, TLS callbacks, writable+executable sections, overlay,
  packer identification and a **capability profile** (network, injection, keylogging, crypto,
  screen capture, persistence…).
- **Hidden and disguised executables**: `.exe` with hidden/system attribute, PE files disguised as
  `.jpg`/`.txt`/`.dat`, double extensions (`photo.jpg.exe`) and libraries in unusual locations.
- **Hash and identity** (SHA-256 / MD5) and **digital signature** (Authenticode): valid, unsigned,
  or `HashMismatch` (modified after signing — the typical fingerprint of a crack).
- **Indicator sweep** with encoded signatures: mining, ransomware, droppers, persistence,
  clipboard theft.
- **Windows Defender**: on-demand scan of the file/folder with the system engine.
- **ISO**: mounted **read-only**, contents inspected, executables scanned, and compressed data
  (`.bin` FreeArc, etc.) swept in streaming.
- **Online reputation** (optional): looks the hash up on VirusTotal (free API key).
- **Risk score 0–100** and **false-positive reconciliation**: if the antivirus and signature are
  clean, a mere text match does not trigger a "dangerous" verdict.
- **Link checker**: paste a URL and check whether it is phishing/malicious without visiting it —
  IP instead of a domain, Punycode/homographs, high-abuse TLDs, shorteners, brand impersonation
  (PayPal, Steam…), executable downloads, bait words, and optionally VirusTotal.
- **Interface**: drag and drop the file, a risk ring, and findings grouped by severity.

### Advanced mode (live behavior test)
Runs the game inside **Windows Sandbox** (a disposable, isolated environment) and watches for
connections to mining pools, unexpected child processes, outbound traffic and CPU usage.

> ⚠️ The live test **runs the file**; that is why it only runs inside Windows Sandbox, never on
> your system. Requires Windows 10/11 **Pro** with the *Windows Sandbox* feature enabled.

---

## Usage

### From source (Python 3.11+)
```bash
python run.py                                 # graphical interface
python -m vss.cli "D:\game.iso"               # command line
python -m vss.cli "C:\Games\X" --vt YOUR_API_KEY
```
The core needs no external dependencies (standard library + system PowerShell).

### Build the .exe and the installer
```bash
pip install -r requirements.txt
python build.py                               # -> dist/VoidsSecureSystem.exe
ISCC installer.iss                            # -> installer/VoidsSecureSystem_Setup.exe
```

## Auto-update
The compiled app checks an `update.json` manifest on start (and every hour); if a new version is
available it shows a notice and updates itself (downloads, **verifies the SHA-256**, replaces the
`.exe` and restarts). Any open copy on another machine updates when a new version is published.

Publish a new version with:
```bash
python publish.py --version 2.3.0 --notes "what's new"
```
Then upload `dist/VoidsSecureSystem.exe` as the release asset (exact name `VoidsSecureSystem.exe`)
and push `update.json`.

---

## Verdicts
| Verdict | Meaning |
|---|---|
| **CLEAN** | No indicators + Defender clean + deep inspection done |
| **LIKELY CLEAN** | No relevant indicators, but a layer was skipped |
| **SUSPICIOUS** | Signals worth a manual review |
| **DANGEROUS** | Threat confirmed by antivirus/reputation or critical indicators |

---

## Notice
A **defensive** tool for checking files you already have on your machine. No automatic analysis is
an absolute guarantee; a packed crack is only fully cleared by the behavior test. Use it as one
more layer of security.
