from __future__ import annotations
from dataclasses import dataclass, field

CAP_APIS = {
    "network": ("wsastartup", "wsasocket", "socket", "connect", "send", "recv", "internetopen",
                "internetconnect", "httpsendrequest", "winhttpconnect", "winhttpopen",
                "urldownloadtofile", "getaddrinfo", "wsaconnect", "internetreadfile"),
    "injection": ("virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
                  "zwunmapviewofsection", "setthreadcontext", "queueuserapc", "ntmapviewofsection",
                  "rtlcreateuserthread", "ntwritevirtualmemory"),
    "keylogging": ("setwindowshookex", "getasynckeystate", "getkeystate", "getkeyboardstate",
                   "registerrawinputdevices"),
    "anti-debug": ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess",
                   "outputdebugstring", "ntsetinformationthread"),
    "screen-capture": ("bitblt", "getdc", "createcompatiblebitmap", "gdipcreatebitmapfromhbitmap",
                       "gdiplusstartup"),
    "process-enum": ("createtoolhelp32snapshot", "process32first", "process32next", "enumprocesses",
                     "enumprocessmodules"),
    "crypto": ("cryptencrypt", "cryptgenkey", "cryptacquirecontext", "bcryptencrypt", "cryptdecrypt"),
    "privileges": ("adjusttokenprivileges", "lookupprivilegevalue", "openprocesstoken"),
    "services": ("createservice", "openscmanager", "startservicectrldispatcher"),
    "dynamic-loading": ("loadlibrary", "getprocaddress", "ldrloaddll"),
    "clipboard": ("getclipboarddata", "setclipboardviewer", "openclipboard"),
}

PACKER_SECTIONS = {
    "UPX": ("upx0", "upx1", "upx!"),
    "Themida/WinLicense": (".themida", ".winlice"),
    "VMProtect": (".vmp0", ".vmp1", ".vmp2"),
    "Enigma": (".enigma1", ".enigma2"),
    "MPRESS": (".mpress1", ".mpress2"),
    "ASPack": (".aspack", ".adata"),
    "PECompact": ("pec1", "pec2"),
    "Obsidium": (".obsidiu",),
    "PyInstaller": (),
}


@dataclass
class PeReport:
    ok: bool = False
    imphash: str = ""
    is_dll: bool = False
    is_64: bool = False
    tls_callbacks: int = 0
    overlay: int = 0
    overlay_ratio: float = 0.0
    wx_sections: list[str] = field(default_factory=list)
    high_entropy_sections: list[str] = field(default_factory=list)
    ep_section: str = ""
    ep_in_last: bool = False
    packer: str = ""
    signed_dir: bool = False
    capabilities: dict = field(default_factory=dict)
    n_imports: int = 0
    error: str = ""


def analyze(path: str) -> PeReport:
    r = PeReport()
    try:
        import pefile
    except ImportError:
        r.error = "pefile no disponible"
        return r
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception as e:
        r.error = str(e)
        return r
    try:
        r.ok = True
        r.is_dll = pe.is_dll()
        r.is_64 = pe.FILE_HEADER.Machine == 0x8664
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_TLS"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
        try:
            r.imphash = pe.get_imphash()
        except Exception:
            r.imphash = ""
        _sections(pe, r)
        _tls(pe, r)
        _overlay(pe, path, r)
        _security(pe, r)
        _imports(pe, r)
        _packer(pe, r)
    except Exception as e:
        r.error = str(e)
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return r


def _sections(pe, r):
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    last = None
    total = len(pe.sections)
    for i, s in enumerate(pe.sections):
        name = s.Name.rstrip(b"\x00").decode("latin1", "replace")
        try:
            ent = s.get_entropy()
        except Exception:
            ent = 0.0
        exec_flag = bool(s.Characteristics & 0x20000000)
        write_flag = bool(s.Characteristics & 0x80000000)
        if exec_flag and write_flag:
            r.wx_sections.append(name)
        if ent >= 7.2 and s.SizeOfRawData > 0:
            r.high_entropy_sections.append(f"{name} ({ent:.2f})")
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            r.ep_section = name
            last = i
    if last is not None and total:
        r.ep_in_last = last >= total - 1 and total > 1


def _tls(pe, r):
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if tls and getattr(tls, "struct", None):
        cb = tls.struct.AddressOfCallBacks
        if cb:
            r.tls_callbacks = 1


def _overlay(pe, path, r):
    try:
        end = pe.get_overlay_data_start_offset()
    except Exception:
        end = None
    import os
    size = os.path.getsize(path)
    if end is not None:
        r.overlay = max(0, size - end)
        r.overlay_ratio = round(r.overlay / size, 3) if size else 0.0


def _security(pe, r):
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        r.signed_dir = d.Size > 0 and d.VirtualAddress > 0
    except Exception:
        r.signed_dir = False


def _imports(pe, r):
    caps: dict[str, list[str]] = {}
    total = 0
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if not imp.name:
                continue
            total += 1
            fn = imp.name.decode("latin1", "replace").lower()
            for cap, apis in CAP_APIS.items():
                if any(a in fn for a in apis):
                    caps.setdefault(cap, [])
                    if imp.name.decode("latin1", "replace") not in caps[cap]:
                        caps[cap].append(imp.name.decode("latin1", "replace"))
    r.n_imports = total
    r.capabilities = {k: v[:6] for k, v in caps.items()}


def _packer(pe, r):
    names = [s.Name.rstrip(b"\x00").decode("latin1", "replace").lower() for s in pe.sections]
    for packer, sigs in PACKER_SECTIONS.items():
        if sigs and any(any(sig in n for n in names) for sig in sigs):
            r.packer = packer
            return
