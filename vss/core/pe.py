from __future__ import annotations
import struct
import math
import collections
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    vsize: int
    rawsize: int
    rawptr: int
    entropy: float


@dataclass
class PEInfo:
    is_pe: bool = False
    is_64: bool = False
    machine: int = 0
    subsystem: int = 0
    dll: bool = False
    sections: list[Section] = field(default_factory=list)
    imports: dict[str, list[str]] = field(default_factory=dict)
    overlay_size: int = 0
    error: str = ""

    @property
    def packed(self) -> bool:
        code = [s for s in self.sections if s.rawsize > 0]
        if not code:
            return False
        hi = [s for s in code if s.entropy >= 7.2]
        weird_names = any(
            not s.name.lower().lstrip(".").isalnum() or s.name not in _COMMON_SECTIONS
            for s in code
        )
        return bool(hi) and (weird_names or len(code) <= 3)

    @property
    def import_names(self) -> list[str]:
        out = []
        for funcs in self.imports.values():
            out.extend(funcs)
        return out


_COMMON_SECTIONS = {
    ".text", ".data", ".rdata", ".idata", ".edata", ".pdata", ".rsrc",
    ".reloc", ".bss", ".tls", ".itext", "_RDATA", ".didat", ".gfids",
}


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    freq = collections.Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def parse_pe(path: str, want_imports: bool = True) -> PEInfo:
    info = PEInfo()
    try:
        with open(path, "rb") as f:
            data = f.read(16 * 1024 * 1024)
        full_size = _tail_size(path)
    except OSError as e:
        info.error = str(e)
        return info

    if data[:2] != b"MZ":
        return info

    def u16(o):
        return struct.unpack_from("<H", data, o)[0]

    def u32(o):
        return struct.unpack_from("<I", data, o)[0]

    try:
        e = u32(0x3C)
        if data[e:e + 4] != b"PE\x00\x00":
            return info
        info.is_pe = True
        coff = e + 4
        info.machine = u16(coff)
        nsec = u16(coff + 2)
        opt = coff + 20
        magic = u16(opt)
        info.is_64 = magic == 0x20B
        chars = u16(coff + 18)
        info.dll = bool(chars & 0x2000)
        info.subsystem = u16(opt + 0x44)
        size_opt = u16(coff + 16)
        sec_off = opt + size_opt
        end_of_raw = 0
        for i in range(nsec):
            so = sec_off + i * 40
            name = data[so:so + 8].rstrip(b"\x00").decode("latin1", "replace")
            vsize = u32(so + 8)
            rawsize = u32(so + 16)
            rawptr = u32(so + 20)
            chunk = data[rawptr:rawptr + rawsize] if rawptr < len(data) else b""
            info.sections.append(Section(name, vsize, rawsize, rawptr, round(_entropy(chunk), 2)))
            end_of_raw = max(end_of_raw, rawptr + rawsize)
        info.overlay_size = max(0, full_size - end_of_raw)
        if want_imports:
            info.imports = _parse_imports(data, u16, u32, opt, coff, info.is_64)
    except (struct.error, IndexError, ValueError) as ex:
        info.error = f"parse: {ex}"
    return info


def _tail_size(path: str) -> int:
    import os
    return os.path.getsize(path)


def _parse_imports(data, u16, u32, opt, coff, is64) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    dd = opt + (0x70 if is64 else 0x60)
    imp_rva = u32(dd + 8)
    if not imp_rva:
        return out
    nsec = u16(coff + 2)
    sh = opt + u16(coff + 16)
    secs = []
    for i in range(nsec):
        so = sh + i * 40
        vad = u32(so + 12)
        vsz = u32(so + 8)
        rsz = u32(so + 16)
        rpt = u32(so + 20)
        secs.append((vad, max(vsz, rsz), rpt))

    def rva2off(rva):
        for vad, span, rpt in secs:
            if vad <= rva < vad + span:
                return rpt + (rva - vad)
        return None

    o = rva2off(imp_rva)
    if o is None:
        return out
    ptr_fmt = "<Q" if is64 else "<I"
    ptr_sz = 8 if is64 else 4
    high = 1 << (63 if is64 else 31)
    guard = 0
    while guard < 512:
        guard += 1
        try:
            oft = u32(o)
            name_rva = u32(o + 12)
            ft = u32(o + 16)
        except struct.error:
            break
        if oft == 0 and name_rva == 0 and ft == 0:
            break
        no = rva2off(name_rva)
        if no is None:
            o += 20
            continue
        end = data.find(b"\x00", no)
        dll = data[no:end].decode("latin1", "replace") if end > no else "?"
        funcs: list[str] = []
        thunk = rva2off(oft or ft)
        if thunk is not None:
            fguard = 0
            while fguard < 4096:
                fguard += 1
                try:
                    val = struct.unpack_from(ptr_fmt, data, thunk)[0]
                except struct.error:
                    break
                if val == 0:
                    break
                if not (val & high):
                    fo = rva2off(val & (high - 1))
                    if fo is not None and fo + 2 < len(data):
                        fe = data.find(b"\x00", fo + 2)
                        if fe > fo + 2:
                            funcs.append(data[fo + 2:fe].decode("latin1", "replace"))
                else:
                    funcs.append(f"ord#{val & 0xffff}")
                thunk += ptr_sz
        out[dll] = funcs
        o += 20
    return out
