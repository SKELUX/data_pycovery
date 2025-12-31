#todo: esp, nsp, knp, safetensors, dir

#!/usr/bin/env python3
from __future__ import annotations

import argparse, os, struct, sys, time, zlib, re, atexit
from pathlib import Path
from dataclasses import dataclass
from typing import Iterator

# ---- signatures / limits ----

PNG_SIG, PNG_IEND = b"\x89PNG\r\n\x1a\n", b"\x00\x00\x00\x00IEND\xaeB`\x82"
JPG_SOI, MIN_JPG_BYTES = b"\xFF\xD8", 1024
ZIP_LFH, ZIP_CDH, ZIP_EOCD = b"PK\x03\x04", b"PK\x01\x02", b"PK\x05\x06"
ZIP64_LOC, ZIP64_EOCD = b"PK\x06\x07", b"PK\x06\x06"
SEVENZ_SIG = b"7z\xBC\xAF\x27\x1C"
EXE_MZ = b"MZ"
PDF_SIG, PDF_EOF, PDF_STARTXREF = b"%PDF-", b"%%EOF", b"startxref"
MP3_ID3, MP3_TAG = b"ID3", b"TAG"
NES_SIG = b"NES\x1A"
PFS0_SIG = b"PFS0"
MP4_FTYP = b"ftyp"
GIF_SIG = b"GIF"
GIF87A, GIF89A = b"GIF87a", b"GIF89a"
WEBP_RIFF, WEBP_WEBP = b"RIFF", b"WEBP"

TXT_MIN_BYTES = 0x1000

CHUNK_LIMIT_DEFAULT = 2 * 1024**3
READ_BLOCK_DEFAULT  = 64 * 1024**2
SECTOR_ALIGN        = 512

LIMITS = {
    "png": dict(sig=PNG_SIG,    maxb=25 * 1024**2,    maxn=200,  minb=len(PNG_SIG)),
    "jpg": dict(sig=JPG_SOI,    maxb=50 * 1024**2,    maxn=200,  minb=MIN_JPG_BYTES),
    "zip": dict(sig=ZIP_LFH,    maxb=512 * 1024**2,   maxn=100,  minb=22),
    "7z":  dict(sig=SEVENZ_SIG, maxb=1024 * 1024**2,  maxn=50,   minb=32),
    "exe": dict(sig=EXE_MZ,     maxb=8 * 1024**2,     maxn=200,  minb=1024),
    "pdf": dict(sig=PDF_SIG,    maxb=256 * 1024**2,   maxn=200,  minb=512),
    "mp3": dict(sig=MP3_ID3,    maxb=256 * 1024**2,   maxn=200,  minb=2048),
    "txt": dict(sig=b"",        maxb=64 * 1024**2,    maxn=2000, minb=TXT_MIN_BYTES),
    "nes": dict(sig=NES_SIG,    maxb=8 * 1024**2,     maxn=500,  minb=16 + 16 * 1024),
    "nsp": dict(sig=PFS0_SIG,  maxb=4 * 1024**3,     maxn=50,   minb=0x4000),
    "mp4": dict(sig=MP4_FTYP,  maxb=32 * 1024**3,    maxn=50,   minb=4096),
    "gif": dict(sig=GIF_SIG,    maxb=256 * 1024**2,   maxn=200,  minb=32),
    "webp": dict(sig=WEBP_RIFF, maxb=256 * 1024**2,   maxn=200,  minb=32),
}

# ---- Raw device I/O ----

if os.name != "nt":
    raise SystemExit("This script is Windows-only (raw volume access).")

import ctypes
from ctypes import wintypes

k32 = ctypes.WinDLL("kernel32", use_last_error=True)

GENERIC_READ, GENERIC_WRITE = 0x80000000, 0x40000000
SHARE = 0x1 | 0x2 | 0x4
OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL = 3, 0x80
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000

FSCTL_LOCK_VOLUME, FSCTL_UNLOCK_VOLUME, FSCTL_DISMOUNT_VOLUME = 0x00090018, 0x0009001C, 0x00090020

ULONG_PTR = ctypes.c_uint64 if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_uint32

class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ULONG_PTR), ("InternalHigh", ULONG_PTR),
        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    ]

def _sig(fn, restype, *argtypes):
    f = getattr(k32, fn)
    f.restype = restype
    f.argtypes = list(argtypes)
    return f

CreateFileW = _sig("CreateFileW", wintypes.HANDLE,
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE
)
ReadFile = _sig("ReadFile", wintypes.BOOL,
    wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED)
)
WriteFile = _sig("WriteFile", wintypes.BOOL,
    wintypes.HANDLE, wintypes.LPCVOID, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(OVERLAPPED)
)
DeviceIoControl = _sig("DeviceIoControl", wintypes.BOOL,
    wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
    wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID
)
CloseHandle = _sig("CloseHandle", wintypes.BOOL, wintypes.HANDLE)
GetVolumeInformationW = _sig("GetVolumeInformationW", wintypes.BOOL,
    wintypes.LPCWSTR,
    wintypes.LPWSTR, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR, wintypes.DWORD
)
GetDiskFreeSpaceW = _sig("GetDiskFreeSpaceW", wintypes.BOOL,
    wintypes.LPCWSTR,
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD)
)

def _raise_last(msg: str) -> None:
    e = ctypes.get_last_error()
    raise OSError(e, f"{msg} (WinError {e})")

class WinRawDevice:
    def __init__(self, path: str, write: bool = False):
        access = GENERIC_READ | (GENERIC_WRITE if write else 0)
        h = CreateFileW(path, access, SHARE, None, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, None)
        if h == wintypes.HANDLE(-1).value:
            _raise_last(f"CreateFileW failed for {path}")
        self.h = h

    def close(self):
        if self.h:
            CloseHandle(self.h)
            self.h = 0

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def _ctl(self, code: int) -> None:
        br = wintypes.DWORD(0)
        DeviceIoControl(self.h, code, None, 0, None, 0, ctypes.byref(br), None)

    def try_lock_dismount(self):
        try:
            self._ctl(FSCTL_LOCK_VOLUME)
            self._ctl(FSCTL_DISMOUNT_VOLUME)
        except Exception:
            pass

    def try_unlock(self):
        try:
            self._ctl(FSCTL_UNLOCK_VOLUME)
        except Exception:
            pass

    @staticmethod
    def _ptr(b: bytearray):
        c = ctypes.c_char.from_buffer(b)
        return ctypes.c_void_p(ctypes.addressof(c))

    def read_into(self, off: int, out: bytearray, n: int, align: int = SECTOR_ALIGN) -> None:
        if off % align or n % align:
            raise ValueError("read_into requires aligned off/n")
        if n > len(out):
            raise ValueError("read_into: n > out size")
        got = wintypes.DWORD(0)
        ov = OVERLAPPED()
        ov.Offset, ov.OffsetHigh = off & 0xFFFFFFFF, (off >> 32) & 0xFFFFFFFF
        ok = ReadFile(self.h, self._ptr(out), n, ctypes.byref(got), ctypes.byref(ov))
        if not ok:
            _raise_last(f"ReadFile failed off={off} n={n}")
        if got.value != n:
            raise OSError(f"Short read at {off} (wanted {n}, got {got.value})")

    def read_exact(self, off: int, n: int) -> bytes:
        nn = n + ((SECTOR_ALIGN - (n % SECTOR_ALIGN)) % SECTOR_ALIGN)
        tmp = bytearray(nn)
        self.read_into(off, tmp, nn)
        return bytes(tmp[:n])

    def write_exact(self, off: int, data: bytes | memoryview) -> None:
        mv = memoryview(data)
        n = len(mv)
        if off % SECTOR_ALIGN or n % SECTOR_ALIGN:
            raise ValueError("write_exact requires aligned off/n")
        if n <= 0:
            return

        max_chunk = 8 * 1024**2
        cur, i = off, 0
        while i < n:
            take = min(max_chunk, n - i)
            take = (take // SECTOR_ALIGN) * SECTOR_ALIGN or SECTOR_ALIGN
            buf = (ctypes.c_char * take).from_buffer_copy(mv[i:i + take])
            put = wintypes.DWORD(0)
            ov = OVERLAPPED()
            ov.Offset, ov.OffsetHigh = cur & 0xFFFFFFFF, (cur >> 32) & 0xFFFFFFFF
            ok = WriteFile(self.h, buf, take, ctypes.byref(put), ctypes.byref(ov))
            if not ok:
                _raise_last(f"WriteFile failed off={cur} n={take}")
            if put.value != take:
                raise OSError(f"Short write at {cur} (wanted {take}, got {put.value})")
            cur += take
            i += take

def open_device(path: str, write: bool = False) -> WinRawDevice:
    return WinRawDevice(path, write=write)

# ---- Misc ----

U16 = struct.Struct("<H").unpack_from
U32 = struct.Struct("<I").unpack_from
U64 = struct.Struct("<Q").unpack_from
BE32 = struct.Struct(">I").unpack_from
BE64 = struct.Struct(">Q").unpack_from

def fmt_bytes(n: int) -> str:
    x = float(n)
    for u in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if x < 1024 or u == "PiB":
            return f"{int(x)} B" if u == "B" else f"{x:.2f} {u}"
        x /= 1024.0
    return f"{x:.2f} PiB"

def volume_serial(volume_device: str) -> str:
    s = (volume_device or "").strip()
    if not (s.startswith("\\\\.\\") and len(s) >= 6 and s[4].isalpha() and s[5] == ":"):
        return "UNKNOWN"
    drive = s[4].upper()
    root = f"{drive}:\\"
    vol = ctypes.create_unicode_buffer(261)
    fs  = ctypes.create_unicode_buffer(261)
    serial = wintypes.DWORD(0)
    maxc = wintypes.DWORD(0)
    flags = wintypes.DWORD(0)
    ok = GetVolumeInformationW(root, vol, len(vol), ctypes.byref(serial), ctypes.byref(maxc), ctypes.byref(flags), fs, len(fs))
    return f"{serial.value:08X}" if ok else "UNKNOWN"

def win_bps_bpc(volume_device: str):
    s = (volume_device or "").strip()
    if not (s.startswith("\\\\.\\") and len(s) >= 6 and s[4].isalpha() and s[5] == ":"):
        return None
    drive = s[4].upper()
    root = f"{drive}:\\"

    spc = wintypes.DWORD(0)
    bps = wintypes.DWORD(0)
    nfc = wintypes.DWORD(0)
    tnc = wintypes.DWORD(0)
    ok = GetDiskFreeSpaceW(root, ctypes.byref(spc), ctypes.byref(bps), ctypes.byref(nfc), ctypes.byref(tnc))
    if not ok or spc.value == 0 or bps.value == 0:
        return None
    return int(bps.value), int(spc.value) * int(bps.value)

INDEX_LINE_RE = re.compile(r"^([0-9A-Fa-f]{16}) ([0-9A-Fa-f]{8}) ([A-Za-z0-9]+)$")

def load_index(out_root: Path):
    idx = out_root / "index.txt"
    if not idx.exists():
        return [], 0
    entries = []
    scan_off = 0
    for raw in idx.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#SCAN"):
            parts = s.split()
            if len(parts) >= 2:
                try: scan_off = int(parts[1], 16)
                except Exception: pass
            continue
        m = INDEX_LINE_RE.match(s)
        if not m:
            continue
        off = int(m.group(1), 16)
        h   = int(m.group(2), 16)
        t   = m.group(3).lower()
        entries.append((off, t, h))
    entries.sort(key=lambda x: (x[0], x[1], x[2]))
    return entries, scan_off

def emit_found(out_dir: Path, index_entries: list[tuple[int, str, int]], ext: str, off: int, data: bytes) -> None:
    h = zlib.crc32(data) & 0xFFFFFFFF
    name = f"{off:016X}_{h:08X}.{ext}"
    (out_dir / name).write_bytes(data)
    index_entries.append((off, ext, h))

def emit_found_file(out_dir: Path, index_entries: list[tuple[int, str, int]], ext: str, off: int, tmp_path: Path, final_len: int) -> None:
    with tmp_path.open("r+b") as f:
        f.truncate(final_len)

    h = 0
    with tmp_path.open("rb") as f:
        while True:
            b = f.read(8 * 1024**2)
            if not b:
                break
            h = zlib.crc32(b, h)
    h &= 0xFFFFFFFF

    final_name = f"{off:016X}_{h:08X}.{ext}"
    final_path = out_dir / final_name
    tmp_path.replace(final_path)

    index_entries.append((off, ext, h))

POPCNT = [bin(i).count("1") for i in range(256)]
WS = b" \t\r\n\f\0"

# ---- NTFS boot + MFT ----

@dataclass
class NTFSInfo:
    bps: int
    bpc: int
    total_sectors: int
    mft_lcn: int
    frs: int

    def cl_to_off(self, cl: int) -> int:
        return cl * self.bpc

def s8(x: int) -> int:
    return struct.unpack("b", bytes([x & 0xFF]))[0]

def parse_ntfs_boot(bs: bytes) -> NTFSInfo:
    if bs[3:11] != b"NTFS    ":
        raise ValueError("Not NTFS.")
    bps = U16(bs, 11)[0]
    spc_raw = s8(bs[13])
    bpc = (bps * spc_raw) if spc_raw > 0 else (1 << (-spc_raw))
    total_sectors = U64(bs, 40)[0]
    mft_lcn = U64(bs, 48)[0]
    cpr = s8(bs[64])
    frs = (cpr * bpc) if cpr > 0 else (1 << (-cpr))
    return NTFSInfo(bps=bps, bpc=bpc, total_sectors=total_sectors, mft_lcn=mft_lcn, frs=frs)

def apply_fixup(rec: bytes, sector_size: int) -> bytes:
    if rec[:4] != b"FILE":
        raise ValueError("Bad MFT record.")
    usa_off, usa_cnt = U16(rec, 4)[0], U16(rec, 6)[0]
    usa = rec[usa_off:usa_off + 2 * usa_cnt]
    usn = usa[:2]
    fixed = bytearray(rec)
    sectors = len(rec) // sector_size
    if usa_cnt != sectors + 1:
        raise ValueError("Bad USA.")
    for i in range(sectors):
        end = (i + 1) * sector_size
        if fixed[end - 2:end] != usn:
            raise ValueError("USN mismatch.")
        fixed[end - 2:end] = usa[2 + i * 2: 2 + (i + 1) * 2]
    return bytes(fixed)

ATTR_END, ATTR_DATA = 0xFFFFFFFF, 0x80

def iter_attrs(mft: bytes):
    p = U16(mft, 0x14)[0]
    n = len(mft)
    while p + 8 <= n:
        at = U32(mft, p)[0]
        if at == ATTR_END:
            return
        ln = U32(mft, p + 4)[0]
        if ln <= 0 or p + ln > n:
            return
        nonres = mft[p + 8]
        if nonres == 0:
            vlen = U32(mft, p + 16)[0]
            voff = U16(mft, p + 20)[0]
            yield at, 0, vlen, mft[p + voff:p + voff + vlen]
        else:
            roff = U16(mft, p + 32)[0]
            real = U64(mft, p + 48)[0]
            yield at, 1, real, mft[p + roff:p + ln]
        p += ln

def le_i(b: bytes) -> int:
    v = int.from_bytes(b, "little", signed=False)
    if b and (b[-1] & 0x80):
        v -= 1 << (8 * len(b))
    return v

def parse_runlist(rl: bytes):
    runs = []
    i, cur = 0, 0
    while i < len(rl):
        head = rl[i]; i += 1
        if head == 0:
            break
        len_sz, off_sz = head & 0x0F, (head >> 4) & 0x0F
        run_len = int.from_bytes(rl[i:i + len_sz], "little"); i += len_sz
        off = le_i(rl[i:i + off_sz]) if off_sz else 0; i += off_sz
        cur += off
        runs.append((cur, run_len))
    return runs

def read_at(dev: WinRawDevice, off: int, n: int) -> bytes:
    return dev.read_exact(off, n)

def read_runs(dev: WinRawDevice, nt: NTFSInfo, runs, byte_len: int) -> bytearray:
    out = bytearray(byte_len)
    pos, rem = 0, byte_len
    block = 8 * 1024**2
    for lcn, clen in runs:
        if rem <= 0:
            break
        start = lcn * nt.bpc
        to_copy = min(clen * nt.bpc, rem)
        copied = 0
        while copied < to_copy:
            take = min(block, to_copy - copied)
            chunk = read_at(dev, start + copied, take)
            out[pos + copied:pos + copied + take] = chunk
            copied += take
        pos += to_copy
        rem -= to_copy
    if rem:
        raise OSError("Short read assembling runs.")
    return out

def load_mft_runs(dev: WinRawDevice, nt: NTFSInfo):
    mft0 = nt.mft_lcn * nt.bpc
    rec0 = apply_fixup(read_at(dev, mft0, nt.frs), nt.bps)
    for at, nonres, _real, payload in iter_attrs(rec0):
        if at == ATTR_DATA and nonres == 1:
            runs = parse_runlist(payload)
            if not runs:
                raise ValueError("$MFT runlist empty.")
            return runs
    raise ValueError("No nonresident $DATA in $MFT record 0.")

def mft_rec_off(nt: NTFSInfo, mft_runs, recno: int) -> int:
    idx = recno * nt.frs
    for lcn, clen in mft_runs:
        rb = clen * nt.bpc
        if idx < rb:
            return lcn * nt.bpc + idx
        idx -= rb
    raise ValueError("MFT record beyond runlist.")

def read_mft_rec(dev: WinRawDevice, nt: NTFSInfo, mft_runs, recno: int) -> bytes:
    off = mft_rec_off(nt, mft_runs, recno)
    return apply_fixup(read_at(dev, off, nt.frs), nt.bps)

def load_bitmap(dev: WinRawDevice, nt: NTFSInfo) -> bytes:
    mft_runs = load_mft_runs(dev, nt)
    rec6 = read_mft_rec(dev, nt, mft_runs, 6)
    for at, nonres, real_size, payload in iter_attrs(rec6):
        if at == ATTR_DATA and nonres == 1:
            runs = parse_runlist(payload)
            return bytes(read_runs(dev, nt, runs, byte_len=real_size))
    raise ValueError("No nonresident $DATA in $Bitmap record 6.")

def iter_free_cluster_runs_ntfs(bitmap: bytes):
    in_run = False
    run_start = run_len = 0
    cl = 0
    for byte in bitmap:
        if byte == 0x00:
            if not in_run:
                in_run, run_start, run_len = True, cl, 8
            else:
                run_len += 8
            cl += 8
            continue
        if byte == 0xFF:
            if in_run:
                yield run_start, run_len
                in_run, run_len = False, 0
            cl += 8
            continue
        for bit in range(8):
            used = (byte >> bit) & 1
            if used == 0:
                if not in_run:
                    in_run, run_start, run_len = True, cl, 1
                else:
                    run_len += 1
            else:
                if in_run:
                    yield run_start, run_len
                    in_run, run_len = False, 0
            cl += 1
    if in_run:
        yield run_start, run_len

def unalloc_bytes_ntfs(nt: NTFSInfo, bitmap: bytes, volume_bytes: int) -> int:
    total_clusters = volume_bytes // nt.bpc
    if total_clusters <= 0:
        return 0
    full_bytes, rem_bits = divmod(total_clusters, 8)
    if full_bytes > len(bitmap):
        total_clusters = len(bitmap) * 8
        full_bytes, rem_bits = divmod(total_clusters, 8)

    free = 0
    for b in bitmap[:full_bytes]:
        free += 8 - POPCNT[b]
    if rem_bits and full_bytes < len(bitmap):
        mask = (1 << rem_bits) - 1
        last = bitmap[full_bytes] & mask
        free += rem_bits - POPCNT[last]
    return free * nt.bpc

# ---- FAT32 ----

@dataclass
class FAT32Info:
    bps: int
    spc: int
    bpc: int
    total_sectors: int
    reserved: int
    nfats: int
    fatsz: int
    root_cluster: int
    first_data_sector: int
    total_clusters: int
    fat0_off: int

    def cl_to_off(self, cl: int) -> int:
        return (self.first_data_sector * self.bps) + (cl - 2) * self.bpc

def parse_fat32_boot(bs: bytes) -> FAT32Info:
    bps = U16(bs, 11)[0]
    spc = bs[13]
    reserved = U16(bs, 14)[0]
    nfats = bs[16]
    root_ent_cnt = U16(bs, 17)[0]
    tot16 = U16(bs, 19)[0]
    fatsz16 = U16(bs, 22)[0]
    tot32 = U32(bs, 32)[0]
    fatsz32 = U32(bs, 36)[0]
    root_cluster = U32(bs, 44)[0]

    total_sectors = tot16 if tot16 else tot32
    fatsz = fatsz32 if fatsz32 else fatsz16

    if bps == 0 or spc == 0 or reserved == 0 or nfats == 0 or fatsz == 0 or total_sectors == 0:
        raise ValueError("Bad FAT BPB.")
    if root_ent_cnt != 0:
        raise ValueError("Not FAT32 (looks like FAT12/16).")
    if bs[0x52:0x5A].rstrip(b"\x00 ").startswith(b"FAT32") is False:
        raise ValueError("Not FAT32.")

    bpc = bps * spc
    first_data_sector = reserved + nfats * fatsz
    data_sectors = total_sectors - first_data_sector
    total_clusters = data_sectors // spc

    fat0_off = reserved * bps
    return FAT32Info(
        bps=bps, spc=spc, bpc=bpc, total_sectors=total_sectors,
        reserved=reserved, nfats=nfats, fatsz=fatsz, root_cluster=root_cluster,
        first_data_sector=first_data_sector, total_clusters=total_clusters,
        fat0_off=fat0_off,
    )

def fat32_count_free_clusters(dev: WinRawDevice, fat: FAT32Info) -> int:
    fat_bytes = fat.fatsz * fat.bps
    max_cluster = fat.total_clusters + 1
    want_entries = max_cluster + 1
    want_bytes = want_entries * 4
    if want_bytes > fat_bytes:
        want_bytes = fat_bytes

    block = 8 * 1024**2
    block -= (block % SECTOR_ALIGN)
    block = max(block, SECTOR_ALIGN)
    buf = bytearray(block)

    free = 0
    pos = 0
    while pos < want_bytes:
        take = min(block, want_bytes - pos)
        take -= (take % SECTOR_ALIGN)
        if take <= 0:
            break
        dev.read_into(fat.fat0_off + pos, buf, take)
        base_entry = pos // 4
        n_entries = take // 4
        for i in range(n_entries):
            cl = base_entry + i
            if cl < 2:
                continue
            v = U32(buf, i * 4)[0] & 0x0FFFFFFF
            if v == 0:
                free += 1
        pos += take
    return free

def iter_free_cluster_runs_fat32(dev: WinRawDevice, fat: FAT32Info):
    fat_bytes = fat.fatsz * fat.bps
    max_cluster = fat.total_clusters + 1
    want_entries = max_cluster + 1
    want_bytes = want_entries * 4
    if want_bytes > fat_bytes:
        want_bytes = fat_bytes

    block = 8 * 1024**2
    block -= (block % SECTOR_ALIGN)
    block = max(block, SECTOR_ALIGN)
    buf = bytearray(block)

    in_run = False
    run_start = 0
    run_len = 0

    pos = 0
    while pos < want_bytes:
        take = min(block, want_bytes - pos)
        take -= (take % SECTOR_ALIGN)
        if take <= 0:
            break
        dev.read_into(fat.fat0_off + pos, buf, take)
        base_entry = pos // 4
        n_entries = take // 4
        for i in range(n_entries):
            cl = base_entry + i
            if cl < 2:
                continue
            v = U32(buf, i * 4)[0] & 0x0FFFFFFF
            is_free = (v == 0)
            if is_free:
                if not in_run:
                    in_run = True
                    run_start = cl
                    run_len = 1
                else:
                    run_len += 1
            else:
                if in_run:
                    yield run_start, run_len
                    in_run = False
                    run_len = 0
        pos += take

    if in_run:
        yield run_start, run_len

# ---- sliding buffer ----

class SLB:
    __slots__ = ("buf", "start", "abs_start")
    def __init__(self):
        self.buf = bytearray()
        self.start = 0
        self.abs_start = 0

    def clear(self):
        self.buf.clear()
        self.start = 0
        self.abs_start = 0

    def reset_with(self, data: bytes, abs_start: int):
        self.buf = bytearray(data)
        self.start = 0
        self.abs_start = abs_start

    def append(self, data: memoryview):
        self.buf.extend(data)

    def n(self) -> int:
        return len(self.buf) - self.start

    def discard(self, k: int):
        if k <= 0:
            return
        a = self.n()
        if k >= a:
            self.clear()
            self.abs_start += k
            return
        self.start += k
        self.abs_start += k
        if self.start >= (1 << 20) or self.start >= (len(self.buf) // 2):
            del self.buf[:self.start]
            self.start = 0

    def take(self, k: int) -> bytes:
        return bytes(self.buf[self.start:self.start + k])

    def find(self, needle: bytes, rel: int = 0) -> int:
        p = self.buf.find(needle, self.start + rel)
        return -1 if p < 0 else p - self.start

    def tail(self, k: int) -> bytes:
        a = self.n()
        if a <= 0 or k <= 0:
            return b""
        take = min(k, a)
        return bytes(self.buf[len(self.buf) - take:])

# ---- validators ----

def jpeg_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 2:
        return None
    if b[base] != 0xFF or b[base + 1] != 0xD8:
        return -1

    i = 2
    saw_sof = saw_sos = False
    def need(k): return i + k <= n

    while True:
        if i > maxb: return -1
        if not need(2): return None
        if b[base + i] != 0xFF: return -1
        while need(1) and b[base + i] == 0xFF:
            i += 1
            if not need(1): return None
        m = b[base + i]; i += 1
        if m == 0xD9: return -1
        if m in (0xD8, 0x01) or (0xD0 <= m <= 0xD7):
            continue
        if m == 0xDA:
            if not need(2): return None
            seg = (b[base + i] << 8) | b[base + i + 1]
            if seg < 2: return -1
            if not need(seg): return None
            i += seg
            saw_sos = True
            break
        if not need(2): return None
        seg = (b[base + i] << 8) | b[base + i + 1]
        if seg < 2: return -1
        if not need(seg): return None
        if 0xC0 <= m <= 0xCF and m not in (0xC4, 0xC8, 0xCC):
            saw_sof = True
        i += seg

    if not (saw_sof and saw_sos):
        return -1

    while True:
        if i > maxb: return -1
        if not need(1): return None
        x = b[base + i]; i += 1
        if x != 0xFF:
            continue
        if not need(1): return None
        m = b[base + i]; i += 1
        if m == 0x00 or (0xD0 <= m <= 0xD7):
            continue
        return i if m == 0xD9 else -1

def zip_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 4: return None
    if b[base:base + 4] != ZIP_LFH or n > maxb:
        return -1
    scan = base + 4
    while True:
        p = b.find(ZIP_EOCD, scan)
        if p < 0:
            return None
        rel = p - base
        if rel > maxb:
            return -1
        if rel + 22 > n:
            return None
        cd_size = U32(b, p + 12)[0]
        cd_off  = U32(b, p + 16)[0]
        cmt_len = U16(b, p + 20)[0]
        end_rel = rel + 22 + cmt_len
        if end_rel > n:
            return None
        file_len = end_rel
        if not (0 < file_len <= maxb):
            return -1

        if cd_size == 0xFFFFFFFF or cd_off == 0xFFFFFFFF:
            loc = p - 20
            if loc < base or b[loc:loc + 4] != ZIP64_LOC:
                scan = p + 1
                continue
            eocd64_off = U64(b, loc + 8)[0]
            eocd64 = base + eocd64_off
            if eocd64 + 64 > base + n:
                return None
            if b[eocd64:eocd64 + 4] != ZIP64_EOCD:
                scan = p + 1
                continue
            cd_size = U64(b, eocd64 + 48)[0]
            cd_off  = U64(b, eocd64 + 56)[0]

        if cd_off + cd_size > file_len:
            scan = p + 1
            continue

        cd_abs = base + cd_off
        if cd_abs + 4 > base + n:
            return None
        if b[cd_abs:cd_abs + 4] != ZIP_CDH:
            scan = p + 1
            continue
        return end_rel

def sevenz_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 32: return None
    if b[base:base + 6] != SEVENZ_SIG:
        return -1
    sh_crc = U32(b, base + 8)[0]
    if (zlib.crc32(bytes(b[base + 12:base + 32])) & 0xFFFFFFFF) != sh_crc:
        return -1
    next_off  = U64(b, base + 12)[0]
    next_size = U64(b, base + 20)[0]
    next_crc  = U32(b, base + 28)[0]
    file_len = 32 + next_off + next_size
    if not (32 < file_len <= maxb):
        return -1
    if file_len > n:
        return None
    nh0 = base + 32 + next_off
    nh1 = nh0 + next_size
    if next_size:
        if (zlib.crc32(bytes(b[nh0:nh1])) & 0xFFFFFFFF) != next_crc:
            return -1
    return file_len

def pe_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 0x40: return None
    if b[base:base + 2] != EXE_MZ:
        return -1
    e_lfanew = U32(b, base + 0x3C)[0]
    if e_lfanew < 0x40 or e_lfanew > maxb - 0x100:
        return -1
    pe_min = e_lfanew + 4 + 20
    if pe_min > n:
        return None
    pe = base + e_lfanew
    if b[pe:pe + 4] != b"PE\0\0":
        return -1
    filehdr = pe + 4
    nsec = U16(b, filehdr + 2)[0]
    optsz = U16(b, filehdr + 16)[0]
    if not (1 <= nsec <= 96) or not (0x60 <= optsz <= 0x1000):
        return -1
    opt = filehdr + 20
    sect = opt + optsz
    if opt + 2 > base + n:
        return None
    magic = U16(b, opt)[0]
    if magic not in (0x10B, 0x20B):
        return -1
    need = (sect - base) + (nsec * 40)
    if need > n:
        return None
    end_raw = 0
    for i in range(nsec):
        sh = sect + i * 40
        size_raw = U32(b, sh + 16)[0]
        ptr_raw  = U32(b, sh + 20)[0]
        if ptr_raw and ptr_raw <= maxb:
            end_raw = max(end_raw, ptr_raw + size_raw)
        elif ptr_raw > maxb:
            return -1
    size_hdr = U32(b, opt + 60)[0] if (opt + 64) <= (base + n) else 0
    end = max(end_raw, size_hdr)
    dd_off = 0x60 if magic == 0x10B else 0x70
    if optsz >= dd_off + 5 * 8:
        secdir = opt + dd_off + 4 * 8
        sec_off = U32(b, secdir + 0)[0]
        sec_sz  = U32(b, secdir + 4)[0]
        if sec_sz:
            end = max(end, sec_off + sec_sz)
    if not (0 < end <= maxb):
        return -1
    if end > n:
        return None
    if end < (e_lfanew + 4 + 20 + optsz + nsec * 40):
        return -1
    return end

def pdf_linearized_len(buf: bytearray, base: int, n: int):
    win = min(n, 4096)
    if win < 64:
        return None
    s = buf[base:base + win]
    if s.find(b"/Linearized") < 0:
        return None
    j = 0
    while True:
        p = s.find(b"/L", j)
        if p < 0:
            return None
        k = p + 2
        while k < len(s) and s[k] in WS:
            k += 1
        if k >= len(s) or not (48 <= s[k] <= 57):
            j = p + 2
            continue
        val = 0
        while k < len(s) and (48 <= s[k] <= 57):
            val = val * 10 + (s[k] - 48)
            k += 1
        return None if k == len(s) else val

def pdf_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < len(PDF_SIG):
        return None
    if b[base:base + len(PDF_SIG)] != PDF_SIG or n > maxb:
        return -1

    L = pdf_linearized_len(b, base, n)
    if L is not None:
        if not (0 < L <= maxb):
            return -1
        return None if L > n else L

    p = b.rfind(PDF_EOF, base, base + n)
    while p >= 0:
        rel = p - base
        if rel > maxb:
            return -1
        lo = max(base, p - 2048)
        if b.find(PDF_STARTXREF, lo, p + len(PDF_EOF)) >= 0:
            end = rel + len(PDF_EOF)
            while end < n and b[base + end] in WS:
                end += 1
            return -1 if not (0 < end <= maxb) else end
        p = b.rfind(PDF_EOF, base, p)
    return None

def gif_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 13: return None
    if n > maxb: return -1
    if b[base:base+6] not in (GIF87A, GIF89A): return -1
    packed = b[base+10]
    p = base + 13
    if packed & 0x80:
        p += 3 * (1 << ((packed & 7) + 1))
        if p > base + n: return None
    end = base + n
    while True:
        if p >= end: return None
        t = b[p]; p += 1
        if t == 0x3B: return p - base
        if t == 0x21:
            if p >= end: return None
            p += 1
        elif t == 0x2C:
            if p + 9 > end: return None
            ip = b[p+8]; p += 9
            if ip & 0x80:
                p += 3 * (1 << ((ip & 7) + 1))
                if p > end: return None
            if p >= end: return None
            p += 1
        else:
            return -1
        while True:
            if p >= end: return None
            sz = b[p]; p += 1
            if sz == 0: break
            p += sz
            if p > end: return None

# ---- MP3 ----

BR_MPEG1_L3 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0]
BR_MPEG2_L3 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0]
SR_MPEG1, SR_MPEG2, SR_MPEG25 = [44100, 48000, 32000, 0], [22050, 24000, 16000, 0], [11025, 12000, 8000, 0]

def syncsafe_u28(b: bytearray, off: int) -> int:
    x0, x1, x2, x3 = b[off], b[off + 1], b[off + 2], b[off + 3]
    if (x0 | x1 | x2 | x3) & 0x80:
        return -1
    return (x0 << 21) | (x1 << 14) | (x2 << 7) | x3

def is_frame_header(buf, off: int, end: int) -> bool:
    if off + 4 > end:
        return False
    b0, b1, b2, b3 = buf[off], buf[off + 1], buf[off + 2], buf[off + 3]
    if b0 != 0xFF or (b1 & 0xE0) != 0xE0:
        return False
    ver = (b1 >> 3) & 0x03
    layer = (b1 >> 1) & 0x03
    if ver == 0x01 or layer != 0x01:
        return False
    br = (b2 >> 4) & 0x0F
    sr = (b2 >> 2) & 0x03
    emph = b3 & 0x03
    return (br not in (0, 0x0F)) and (sr != 0x03) and (emph != 0x02)

def frame_params(buf: bytearray, off: int):
    b1, b2, b3 = buf[off + 1], buf[off + 2], buf[off + 3]
    ver = (b1 >> 3) & 0x03
    br_idx, sr_idx = (b2 >> 4) & 0x0F, (b2 >> 2) & 0x03
    pad = (b2 >> 1) & 0x01
    ch = (b3 >> 6) & 0x03
    if ver == 0x03:
        sr, br = SR_MPEG1[sr_idx], BR_MPEG1_L3[br_idx]
    elif ver == 0x02:
        sr, br = SR_MPEG2[sr_idx], BR_MPEG2_L3[br_idx]
    elif ver == 0x00:
        sr, br = SR_MPEG25[sr_idx], BR_MPEG2_L3[br_idx]
    else:
        return None
    if sr == 0 or br == 0:
        return None
    return ver, sr, br, pad, ch

def frame_len(ver: int, sr: int, br: int, pad: int) -> int:
    return ((144000 if ver == 0x03 else 72000) * br // sr) + pad

def xing_vbri_stream_bytes(buf: bytearray, frame_off: int, end: int):
    protection = buf[frame_off + 1] & 0x01
    crc_len = 0 if protection else 2
    params = frame_params(buf, frame_off)
    if params is None:
        return None
    ver, _sr, _br, _pad, ch = params
    mono = (ch == 0x03)
    side = (17 if mono else 32) if ver == 0x03 else (9 if mono else 17)
    xoff = frame_off + 4 + crc_len + side
    if xoff + 8 > end:
        return None
    tag = bytes(buf[xoff:xoff + 4])
    if tag in (b"Xing", b"Info"):
        flags = U32(buf, xoff + 4)[0]
        p = xoff + 8
        stream = None
        if flags & 0x1:
            if p + 4 > end: return None
            p += 4
        if flags & 0x2:
            if p + 4 > end: return None
            stream = U32(buf, p)[0]
        if stream and stream > 0:
            return int(stream)
    lo, hi = frame_off + 4, min(end, frame_off + 200)
    p = buf.find(b"VBRI", lo, hi)
    if p >= 0 and p + 18 <= end:
        stream = U32(buf, p + 10)[0]
        if stream and stream > 0:
            return int(stream)
    return None

def mp3_end(slb: SLB, maxb: int):
    b, base, n = slb.buf, slb.start, slb.n()
    if n < 4:
        return None
    if n > maxb:
        return -1

    p = base
    if n >= 10 and b[p:p + 3] == MP3_ID3:
        sz = syncsafe_u28(b, p + 6)
        if sz < 0:
            return -1
        total = 10 + sz + (10 if (b[p + 5] & 0x10) else 0)
        if not (10 < total <= maxb):
            return -1
        if total > n:
            return None
        p += total

    end_abs = base + n
    if not is_frame_header(b, p, end_abs):
        return -1

    stream = xing_vbri_stream_bytes(b, p, end_abs)
    if stream is not None:
        total_len = (p - base) + stream
        if not (0 < total_len <= maxb):
            return -1
        if total_len > n:
            return None
        if total_len + 128 <= n and b[base + total_len:base + total_len + 3] == MP3_TAG:
            total_len += 128
        return total_len

    pos = p
    while True:
        rel = pos - base
        if rel > maxb:
            return -1
        if pos + 4 > base + n:
            return None
        if not is_frame_header(b, pos, base + n):
            if pos + 128 <= base + n and b[pos:pos + 3] == MP3_TAG:
                return rel + 128
            return rel
        params = frame_params(b, pos)
        if params is None:
            return -1
        ver, sr, br, pad, _ch = params
        fl = frame_len(ver, sr, br, pad)
        if fl < 4 or fl > maxb:
            return -1
        if pos + fl > base + n:
            return None
        pos += fl

# ---- TXT ----

TXT_VALID_RE = re.compile(rb"[\x09\x0A\x0D\x20-\x7E]{%d,}" % TXT_MIN_BYTES)
TXT_INVALID_RE = re.compile(rb"[^\x09\x0A\x0D\x20-\x7E]")

def txt_valid_suffix_len(b: bytes) -> int:
    i = len(b)
    while i > 0:
        x = b[i - 1]
        if x in (0x09, 0x0A, 0x0D) or (0x20 <= x <= 0x7E):
            i -= 1
        else:
            break
    return len(b) - i

def txt_valid_prefix_len(buf: bytearray, got: int) -> int:
    i = 0
    while i < got:
        x = buf[i]
        if x in (0x09, 0x0A, 0x0D) or (0x20 <= x <= 0x7E):
            i += 1
        else:
            break
    return i

# ---- carvers ----

class BaseCarver:
    __slots__ = ("sig", "tail_max", "tail", "slb", "maxb", "maxn", "minb", "ext", "out_dir", "count", "index_entries")

    def __init__(self, ext: str, out_dir: Path, index_entries: list, sig: bytes, maxb: int, maxn: int, minb: int):
        self.sig = sig
        self.tail_max = max(0, len(sig) - 1)
        self.tail = b""
        self.slb = SLB()
        self.maxb, self.maxn, self.minb = maxb, maxn, minb
        self.ext = ext
        self.out_dir = out_dir
        self.count = 0
        self.index_entries = index_entries

    def reset_stream(self):
        self.tail = b""
        self.slb.clear()

    def _update_tail(self, chunk: bytearray, got: int):
        if self.tail_max <= 0:
            self.tail = b""
            return
        take = min(self.tail_max, got)
        self.tail = bytes(chunk[got - take:got]) if take > 0 else b""

    def _find_sig(self, chunk: bytearray, got: int):
        p = chunk.find(self.sig, 0, got)
        if p >= 0:
            return p, False, 0
        if self.tail and got and self.tail_max:
            maxk = min(len(self.sig) - 1, len(self.tail), got)
            for k in range(maxk, 0, -1):
                if self.tail[-k:] == self.sig[:k]:
                    need = len(self.sig) - k
                    if need <= got and bytes(chunk[:need]) == self.sig[k:]:
                        return 0, True, k
        return -1, False, 0

    def process(self, chunk: bytearray, got: int, abs_off: int):
        if self.slb.n() == 0:
            pos, boundary, k = self._find_sig(chunk, got)
            if pos < 0:
                self._update_tail(chunk, got)
                return
            if boundary:
                self.slb.reset_with(self.tail[-k:] + bytes(chunk[:got]), abs_off - k)
            else:
                self.slb.reset_with(bytes(chunk[pos:got]), abs_off + pos)
            self.tail = b""
        else:
            self.slb.append(memoryview(chunk)[:got])

        while self.count < self.maxn:
            end = self.try_end()
            if end == 0:
                return
            if end < 0:
                self.slb.discard(1)
                if self.slb.n() == 0:
                    return
                rel = self.slb.find(self.sig, 0)
                if rel < 0:
                    self.tail = self.slb.tail(self.tail_max)
                    self.slb.clear()
                    return
                self.slb.discard(rel)
                continue

            if end < self.minb:
                self.slb.discard(1)
                continue

            data = self.slb.take(end)
            off = self.slb.abs_start
            emit_found(self.out_dir, self.index_entries, self.ext, off, data)
            self.count += 1

            self.slb.discard(end)
            if self.slb.n() == 0:
                return
            rel = self.slb.find(self.sig, 0)
            if rel < 0:
                self.tail = self.slb.tail(self.tail_max)
                self.slb.clear()
                return
            self.slb.discard(rel)

    def try_end(self) -> int:
        raise NotImplementedError

class PngCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < len(PNG_SIG): return 0
        base = self.slb.start
        if self.slb.buf[base:base + len(PNG_SIG)] != PNG_SIG: return -1
        p = self.slb.find(PNG_IEND, 0)
        return 0 if p < 0 else p + len(PNG_IEND)

class JpgCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < 2: return 0
        base = self.slb.start
        if self.slb.buf[base:base + 2] != JPG_SOI: return -1
        r = jpeg_end(self.slb, self.maxb)
        return 0 if r is None else r

class ZipCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < 4: return 0
        base = self.slb.start
        if self.slb.buf[base:base + 4] != ZIP_LFH: return -1
        r = zip_end(self.slb, self.maxb)
        return 0 if r is None else r

class SevenZCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < 32: return 0
        base = self.slb.start
        if self.slb.buf[base:base + 6] != SEVENZ_SIG: return -1
        r = sevenz_end(self.slb, self.maxb)
        return 0 if r is None else r

class ExeCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < 2: return 0
        base = self.slb.start
        if self.slb.buf[base:base + 2] != EXE_MZ: return -1
        r = pe_end(self.slb, self.maxb)
        if r is None:
            return self.maxb if self.slb.n() >= self.maxb else 0
        return r

class PdfCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < len(PDF_SIG): return 0
        base = self.slb.start
        if self.slb.buf[base:base + len(PDF_SIG)] != PDF_SIG: return -1
        r = pdf_end(self.slb, self.maxb)
        return 0 if r is None else r

class Mp3Carver(BaseCarver):
    def __init__(self, out_dir: Path, index_entries: list):
        L = LIMITS["mp3"]
        super().__init__("mp3", out_dir, index_entries, MP3_ID3, L["maxb"], L["maxn"], L["minb"])
        self.tail_max = max(self.tail_max, 3)

    def process(self, chunk: bytearray, got: int, abs_off: int):
        if self.slb.n() == 0:
            if chunk.find(MP3_ID3, 0, got) < 0 and chunk.find(0xFF, 0, got) < 0:
                self._update_tail(chunk, got)
                return
        super().process(chunk, got, abs_off)

    def _find_sig(self, chunk: bytearray, got: int):
        best = (-1, False, 0)
        p = chunk.find(MP3_ID3, 0, got)
        if p >= 0:
            best = (p, False, 0)

        i = 0
        while True:
            q = chunk.find(0xFF, i, got)
            if q < 0:
                break
            if q + 4 <= got and is_frame_header(chunk, q, got):
                if best[0] < 0 or q < best[0]:
                    best = (q, False, 0)
            i = q + 1

        if self.tail and got:
            maxk = min(2, len(self.tail), got)
            for k in range(maxk, 0, -1):
                if self.tail[-k:] == MP3_ID3[:k]:
                    need = 3 - k
                    if need <= got and bytes(chunk[:need]) == MP3_ID3[k:]:
                        return (0, True, k)
            t = self.tail[-min(3, len(self.tail)):]
            for k in (3, 2, 1):
                if len(t) < k or got < (4 - k):
                    continue
                cand = t[-k:] + bytes(chunk[:4 - k])
                if is_frame_header(cand, 0, 4):
                    return (0, True, k)
        return best

    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        r = mp3_end(self.slb, self.maxb)
        return 0 if r is None else r

class Mp4Carver:
    __slots__ = (
        "tail_max", "tail",
        "out_dir", "index_entries",
        "maxb", "maxn", "minb",
        "count",
        "active", "tmp_path", "start_off", "written",
        "pos_valid", "hdr",
        "box_rem",
        "saw_ftyp", "saw_moov", "saw_mdat", "boxes",
        "MP4_TOPLEVEL",
    )

    def __init__(self, out_dir: Path, index_entries: list):
        L = LIMITS["mp4"]
        self.tail_max = 7
        self.tail = b""

        self.out_dir = out_dir
        self.index_entries = index_entries
        self.maxb, self.maxn, self.minb = L["maxb"], L["maxn"], L["minb"]
        self.count = 0

        self.active = False
        self.tmp_path = None
        self.start_off = 0
        self.written = 0

        self.pos_valid = 0
        self.hdr = bytearray()
        self.box_rem = 0
        self.saw_ftyp = self.saw_moov = self.saw_mdat = False
        self.boxes = 0

        self.MP4_TOPLEVEL = {
            b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid",
            b"mfra", b"moof", b"styp", b"sidx", b"emsg", b"pdin",
        }

    def reset_stream(self):
        self.tail = b""
        if self.active:
            try:
                if self.tmp_path and self.tmp_path.exists():
                    self.tmp_path.unlink(missing_ok=True)
            except Exception:
                pass
        self.active = False
        self.tmp_path = None
        self.start_off = 0
        self.written = 0

        self.pos_valid = 0
        self.hdr.clear()
        self.box_rem = 0
        self.saw_ftyp = self.saw_moov = self.saw_mdat = False
        self.boxes = 0
        
    def _mp4_type_ok(self, t: bytes) -> bool:
        return len(t) == 4 and all(0x20 <= c <= 0x7E for c in t)

    def _update_tail(self, chunk: bytearray, got: int):
        take = min(self.tail_max, got)
        self.tail = bytes(chunk[got - take:got]) if take > 0 else b""

    def _try_start(self, chunk: bytearray, got: int, abs_off: int):
        head_take = min(got, 256)
        cand = self.tail + bytes(chunk[:head_take])
        p = cand.find(MP4_FTYP)
        if p < 0:
            return None

        start = p - 4
        if start < 0:
            return None

        sz = BE32(cand, start)[0]
        if sz < 8 or sz > 256 * 1024:
            return None

        if p + 8 <= len(cand):
            brand = cand[p + 4:p + 8]
            if not all(0x20 <= c <= 0x7E for c in brand):
                return None

        abs_start = abs_off - len(self.tail) + start

        if start < len(self.tail):
            init = self.tail[start:] + bytes(chunk[:got])
        else:
            k = start - len(self.tail)
            if k >= got:
                return None
            init = bytes(chunk[k:got])

        return abs_start, init

    def _feed_parser(self, data: bytes):
        i = 0
        n = len(data)

        while i < n:
            if self.pos_valid > self.maxb:
                return -1

            if self.box_rem:
                take = min(self.box_rem, n - i)
                self.box_rem -= take
                self.pos_valid += take
                i += take
                continue

            need8 = 8 - len(self.hdr)
            if need8 > 0:
                take = min(need8, n - i)
                self.hdr.extend(data[i:i + take])
                i += take
                if len(self.hdr) < 8:
                    return None

            sz32 = BE32(self.hdr, 0)[0]
            typ = bytes(self.hdr[4:8])

            def finish_or_fail():
                if self.saw_ftyp and (self.saw_moov or self.saw_mdat) and self.boxes >= 2 and self.pos_valid >= self.minb:
                    return int(self.pos_valid)
                return -1

            if not self._mp4_type_ok(typ):
                return finish_or_fail()

            if self.boxes == 0:
                if typ != b"ftyp":
                    return -1
            else:
                if typ not in self.MP4_TOPLEVEL:
                    return finish_or_fail()

            if sz32 == 0:
                return finish_or_fail()

            header_len = 8
            size = sz32

            if sz32 == 1:
                if len(self.hdr) < 16:
                    take = min(16 - len(self.hdr), n - i)
                    self.hdr.extend(data[i:i + take])
                    i += take
                    if len(self.hdr) < 16:
                        return None
                size = BE64(self.hdr, 8)[0]
                header_len = 16

            if size < header_len:
                return -1
            if self.pos_valid + size > self.maxb:
                return -1

            self.pos_valid += header_len
            self.boxes += 1
            if typ == b"ftyp": self.saw_ftyp = True
            elif typ == b"moov": self.saw_moov = True
            elif typ == b"mdat": self.saw_mdat = True

            self.box_rem = int(size - header_len)
            self.hdr.clear()

        return None

    def process(self, chunk: bytearray, got: int, abs_off: int):
        if self.count >= self.maxn:
            self._update_tail(chunk, got)
            return

        if not self.active:
            st = self._try_start(chunk, got, abs_off)
            if st is None:
                self._update_tail(chunk, got)
                return

            off, init = st
            self.start_off = off
            self.tmp_path = self.out_dir / f"{off:016X}.mp4.part"
            try:
                with self.tmp_path.open("wb") as f:
                    f.write(init)
            except Exception:
                self.reset_stream()
                self._update_tail(chunk, got)
                return

            self.active = True
            self.written = len(init)

            self.pos_valid = 0
            self.hdr.clear()
            self.box_rem = 0
            self.saw_ftyp = self.saw_moov = self.saw_mdat = False
            self.boxes = 0

            r = self._feed_parser(init)
            if r == -1:
                self.reset_stream()
                self._update_tail(chunk, got)
                return
            if isinstance(r, int):
                emit_found_file(self.out_dir, self.index_entries, "mp4", self.start_off, self.tmp_path, r)
                self.count += 1
                self.reset_stream()
                self._update_tail(chunk, got)
                return

            self._update_tail(chunk, got)
            return

        try:
            with self.tmp_path.open("ab") as f:
                f.write(chunk[:got])
        except Exception:
            self.reset_stream()
            self._update_tail(chunk, got)
            return

        self.written += got
        if self.written > self.maxb:
            self.reset_stream()
            self._update_tail(chunk, got)
            return

        r = self._feed_parser(bytes(chunk[:got]))
        if r == -1:
            self.reset_stream()
            self._update_tail(chunk, got)
            return
        if isinstance(r, int):
            emit_found_file(self.out_dir, self.index_entries, "mp4", self.start_off, self.tmp_path, r)
            self.count += 1
            self.reset_stream()

        self._update_tail(chunk, got)

class TxtCarver:
    __slots__ = ("tail_max", "tail", "slb", "maxb", "maxn", "minb", "out_dir", "count", "checked", "index_entries")

    def __init__(self, out_dir: Path, index_entries: list):
        L = LIMITS["txt"]
        self.tail_max = TXT_MIN_BYTES - 1
        self.tail = b""
        self.slb = SLB()
        self.maxb, self.maxn, self.minb = L["maxb"], L["maxn"], L["minb"]
        self.out_dir = out_dir
        self.count = 0
        self.checked = 0
        self.index_entries = index_entries

    def reset_stream(self):
        self.tail = b""
        self.slb.clear()
        self.checked = 0

    def _update_tail(self, chunk: bytearray, got: int):
        take = min(self.tail_max, got)
        self.tail = bytes(chunk[got - take:got]) if take > 0 else b""

    def _start_boundary(self, chunk: bytearray, got: int, abs_off: int) -> bool:
        if not self.tail:
            return False
        suf = txt_valid_suffix_len(self.tail)
        if suf <= 0:
            return False
        pre = txt_valid_prefix_len(chunk, got)
        if suf + pre < self.minb:
            return False
        self.slb.reset_with(self.tail[-suf:] + bytes(chunk[:got]), abs_off - suf)
        self.tail = b""
        self.checked = 0
        return True

    def _start_chunk(self, chunk: bytearray, got: int, abs_off: int) -> bool:
        m = TXT_VALID_RE.search(chunk, 0, got)
        if not m:
            return False
        pos = m.start()
        self.slb.reset_with(bytes(chunk[pos:got]), abs_off + pos)
        self.checked = 0
        return True

    def _reseek(self) -> bool:
        n = self.slb.n()
        if n <= 0:
            return False
        base = self.slb.start
        m = TXT_VALID_RE.search(self.slb.buf, base, base + n)
        if not m:
            self.tail = self.slb.tail(self.tail_max)
            self.slb.clear()
            self.checked = 0
            return False
        drop = m.start() - base
        if drop:
            self.slb.discard(drop)
        self.checked = 0
        return True

    def _try_end(self):
        n = self.slb.n()
        if n <= 0:
            return 0
        if n > self.maxb:
            return -1
        base = self.slb.start
        frm = base + self.checked
        to = base + n
        if frm < base: frm = base
        if frm > to: frm = to
        m = TXT_INVALID_RE.search(self.slb.buf, frm, to)
        if m:
            return m.start() - base
        self.checked = n
        return 0

    def process(self, chunk: bytearray, got: int, abs_off: int):
        if self.slb.n() == 0:
            if not self._start_boundary(chunk, got, abs_off):
                if not self._start_chunk(chunk, got, abs_off):
                    self._update_tail(chunk, got)
                    return
        else:
            self.slb.append(memoryview(chunk)[:got])

        while self.count < self.maxn:
            r = self._try_end()
            if r == 0:
                return
            if r < 0:
                self.slb.discard(1)
                if self.slb.n() == 0:
                    return
                if not self._reseek():
                    return
                continue
            if r < self.minb:
                self.slb.discard(1)
                if self.slb.n() == 0:
                    return
                if not self._reseek():
                    return
                continue

            data = self.slb.take(r)
            off = self.slb.abs_start
            emit_found(self.out_dir, self.index_entries, "txt", off, data)
            self.count += 1

            self.slb.discard(r)
            self.checked = 0
            if self.slb.n() == 0:
                return
            if not self._reseek():
                return

class NesCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb:
            return -1
        if self.slb.n() < 16:
            return 0

        b, base, n = self.slb.buf, self.slb.start, self.slb.n()
        if b[base:base + 4] != NES_SIG:
            return -1

        prg_lo = b[base + 4]
        chr_lo = b[base + 5]
        flags6 = b[base + 6]
        flags7 = b[base + 7]

        hdr_variant = flags7 & 0x0C
        if hdr_variant in (0x04, 0x0C):
            return -1

        trainer = 512 if (flags6 & 0x04) else 0
        nes2 = (hdr_variant == 0x08)

        if nes2:
            byte8 = b[base + 8]
            msb   = b[base + 9]
            submapper = (byte8 >> 4) & 0x0F
            mapper_hi = byte8 & 0x0F

            prg_m = msb & 0x0F
            chr_m = (msb >> 4) & 0x0F

            if prg_m == 0x0F or chr_m == 0x0F:
                return -1

            prg_units = prg_lo | (prg_m << 8)
            chr_units = chr_lo | (chr_m << 8)
        else:
            prg_units = prg_lo
            chr_units = chr_lo

        if prg_units == 0:
            return -1

        prg_bytes = prg_units * 16384
        chr_bytes = chr_units * 8192
        total = 16 + trainer + prg_bytes + chr_bytes

        if not (self.minb <= total <= self.maxb):
            return -1
        if total > n:
            return 0

        mapper = ((flags6 >> 4) & 0x0F) | (flags7 & 0xF0)
        if nes2:
            if mapper_hi != 0 or submapper != 0:
                return -1
        else:
            if any(b[base + i] != 0 for i in range(9, 16)):
                return -1

        prg_base = base + 16 + trainer
        prg_end  = prg_base + prg_bytes
        if prg_end - 6 < prg_base:
            return -1

        def u16le(off: int) -> int:
            return b[off] | (b[off + 1] << 8)

        reset = u16le(prg_end - 4)
        if not (0x8000 <= reset <= 0xFFFF):
            return -1

        return total

class NspCarver(BaseCarver):
    def try_end(self) -> int:
        if self.slb.n() > self.maxb:
            return -1
        if self.slb.n() < 0x10:
            return 0

        b, base, n = self.slb.buf, self.slb.start, self.slb.n()

        if b[base:base + 4] != PFS0_SIG:
            return -1

        entry_count = U32(b, base + 4)[0]
        str_sz      = U32(b, base + 8)[0]
        reserved    = U32(b, base + 0xC)[0]

        if reserved != 0:
            return -1
        if entry_count == 0 or entry_count > 0x2000:
            return -1
        if str_sz > 4 * 1024 * 1024:
            return -1

        ent_table = 0x10
        ent_size  = 0x18
        ent_bytes = entry_count * ent_size
        hdr_bytes = ent_table + ent_bytes

        if hdr_bytes > self.maxb:
            return -1
        if n < hdr_bytes:
            return 0

        str_base = base + hdr_bytes
        if hdr_bytes + str_sz > self.maxb:
            return -1
        if n < hdr_bytes + str_sz:
            return 0

        data_off = hdr_bytes + str_sz

        max_end = 0
        p = base + ent_table
        str_end = str_base + str_sz

        for _ in range(entry_count):
            off = U64(b, p + 0x00)[0]
            sz  = U64(b, p + 0x08)[0]
            no  = U32(b, p + 0x10)[0]
            rsv = U32(b, p + 0x14)[0]
            p += ent_size

            if rsv != 0:
                return -1
            if no >= str_sz:
                return -1

            name_abs = str_base + no
            nul = b.find(0, name_abs, str_end)
            if nul < 0:
                return -1

            name = bytes(b[name_abs:nul])
            if not name or any(c < 0x20 or c > 0x7E for c in name):
                return -1

            if off > self.maxb or sz > self.maxb:
                return -1
            end = off + sz
            if end < off:
                return -1
            if end > max_end:
                max_end = end

        total = data_off + max_end
        if not (self.minb <= total <= self.maxb):
            return -1
        return 0 if total > n else total

class GifCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        r = gif_end(self.slb, self.maxb)
        return 0 if r is None else r

class WebpCarver(BaseCarver):
    def try_end(self):
        if self.slb.n() > self.maxb: return -1
        if self.slb.n() < 12: return 0

        b, base, n = self.slb.buf, self.slb.start, self.slb.n()
        if b[base:base + 4] != WEBP_RIFF: return -1
        if b[base + 8:base + 12] != WEBP_WEBP: return -1

        total = U32(b, base + 4)[0] + 8
        if total < 12 or total > self.maxb: return -1
        if total > n: return 0

        if total >= 20:
            tag = bytes(b[base + 12:base + 16])
            if tag not in (b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ANIM", b"ANMF", b"ICCP", b"EXIF", b"XMP "):
                return -1
            csz = U32(b, base + 16)[0]
            if 20 + csz > total + 1:
                return -1

        return total

CARVERS = {
    "png": PngCarver,
    "jpg": JpgCarver,
    "zip": ZipCarver,
    "7z":  SevenZCarver,
    "exe": ExeCarver,
    "pdf": PdfCarver,
    "nes": NesCarver,
    "nsp": NspCarver,
    "gif": GifCarver,
    "webp": WebpCarver,
}

# ---- index writer ----

def rewrite_index(out_root: Path, entries: list[tuple[int, str, int]], scan_off: int):
    entries.sort(key=lambda x: (x[0], x[1], x[2]))
    p = out_root / "index.txt"
    with p.open("w", encoding="utf-8", newline="\n") as f:
        for off, t, h in entries:
            f.write(f"{off:016X} {h:08X} {t}\n")
        f.write(f"#SCAN {scan_off:016X}\n")

# ---- carve stream ----

def stream_carve(dev: WinRawDevice, fs, free_runs: Iterator[tuple[int, int]], out_root: Path, types: set[str],
                 read_block: int, max_scan_bytes: int, start_abs_off: int, existing_entries):
    out_root.mkdir(parents=True, exist_ok=True)
    index_entries: list[tuple[int, str, int]] = list(existing_entries)

    carvers = {}
    for t in sorted(types):
        d = out_root / t
        d.mkdir(parents=True, exist_ok=True)
        L = LIMITS[t]
        if t == "mp3":
            carvers[t] = Mp3Carver(d, index_entries)
        elif t == "mp4":
            carvers[t] = Mp4Carver(d, index_entries)
        elif t == "txt":
            carvers[t] = TxtCarver(d, index_entries)
        else:
            carvers[t] = CARVERS[t](t, d, index_entries, L["sig"], L["maxb"], L["maxn"], L["minb"])

    read_block -= (read_block % SECTOR_ALIGN)
    read_block = max(read_block, SECTOR_ALIGN)
    buf = bytearray(read_block)

    start_time = time.time()
    last_t = start_time
    last_scanned = 0
    scanned = 0
    scan_off = start_abs_off or 0

    rewrite_index(out_root, index_entries, scan_off)
    written_upto = len(index_entries)

    for start_cl, run_len in free_runs:
        if scanned >= max_scan_bytes:
            break

        run_off = fs.cl_to_off(start_cl)
        run_bytes = run_len * fs.bpc
        to_process = min(run_bytes, max_scan_bytes - scanned)
        if to_process <= 0:
            break

        run_end = run_off + to_process
        if start_abs_off and run_end <= start_abs_off:
            scanned += to_process
            continue

        for c in carvers.values():
            c.reset_stream()

        cur = run_off
        rem = to_process

        if start_abs_off and (run_off < start_abs_off < run_off + to_process):
            skip = start_abs_off - run_off
            skip -= (skip % SECTOR_ALIGN)
            cur += skip
            rem -= skip
            scanned += skip

        while rem > 0 and scanned < max_scan_bytes:
            r = min(read_block, rem)
            r -= (r % SECTOR_ALIGN)
            if r <= 0:
                break

            dev.read_into(cur, buf, r)
            for c in carvers.values():
                if c.count < c.maxn:
                    c.process(buf, r, cur)

            scan_off = cur + r
            if len(index_entries) > written_upto:
                rewrite_index(out_root, index_entries, scan_off)
                written_upto = len(index_entries)
            else:
                p = out_root / "index.txt"
                with p.open("r+b") as f:
                    f.seek(-len(f"#SCAN {0:016X}\n"), os.SEEK_END)
                    f.write(f"#SCAN {scan_off:016X}\n".encode("ascii"))

            scanned += r
            cur += r
            rem -= r

            now = time.time()
            if now - last_t >= 5.0:
                dt = now - last_t
                delta = scanned - last_scanned
                speed = (delta / dt) if dt > 0 else 0.0
                pct = (scanned / max_scan_bytes * 100.0) if max_scan_bytes else 0.0
                eta = (max_scan_bytes - scanned) / speed if speed > 0 else float("inf")
                eta_str = "?" if eta == float("inf") else time.strftime("%H:%M:%S", time.gmtime(int(eta)))
                el = time.strftime("%H:%M:%S", time.gmtime(int(now - start_time)))
                counts = " ".join(f"{k}={carvers[k].count}" for k in sorted(carvers))
                print(f"[SCAN] {fmt_bytes(scanned)} / {fmt_bytes(max_scan_bytes)} ({pct:.2f}%) speed={fmt_bytes(int(speed))}/s elapsed={el} eta={eta_str} {counts}", flush=True)
                last_t = now
                last_scanned = scanned

    rewrite_index(out_root, index_entries, scan_off)
    return scanned, {k: c.count for k, c in carvers.items()}

# ---- wipe ----

def wipe_unallocated(dev: WinRawDevice, fs, free_runs: Iterator[tuple[int, int]], write_block: int, max_scan_bytes: int) -> int:
    write_block -= (write_block % SECTOR_ALIGN)
    write_block = max(write_block, SECTOR_ALIGN)
    max_scan_bytes -= (max_scan_bytes % SECTOR_ALIGN)

    zero = bytes(write_block)
    wiped = 0
    start_time = time.time()
    last_t = start_time
    last_wiped = 0

    dev.try_lock_dismount()
    try:
        for start_cl, run_len in free_runs:
            if wiped >= max_scan_bytes:
                break
            run_off = fs.cl_to_off(start_cl)
            run_bytes = run_len * fs.bpc
            to_process = min(run_bytes, max_scan_bytes - wiped)
            to_process -= (to_process % SECTOR_ALIGN)
            if to_process <= 0:
                break
            cur, rem = run_off, to_process
            while rem > 0 and wiped < max_scan_bytes:
                take = min(write_block, rem)
                dev.write_exact(cur, zero if take == write_block else bytes(take))
                wiped += take
                cur += take
                rem -= take

                now = time.time()
                if now - last_t >= 5.0:
                    dt = now - last_t
                    delta = wiped - last_wiped
                    speed = (delta / dt) if dt > 0 else 0.0
                    pct = (wiped / max_scan_bytes * 100.0) if max_scan_bytes else 0.0
                    eta = (max_scan_bytes - wiped) / speed if speed > 0 else float("inf")
                    eta_str = "?" if eta == float("inf") else time.strftime("%H:%M:%S", time.gmtime(int(eta)))
                    el = time.strftime("%H:%M:%S", time.gmtime(int(now - start_time)))
                    print(f"[WIPE] {fmt_bytes(wiped)} / {fmt_bytes(max_scan_bytes)} ({pct:.2f}%) speed={fmt_bytes(int(speed))}/s elapsed={el} eta={eta_str}", flush=True)
                    last_t = now
                    last_wiped = wiped
    finally:
        dev.try_unlock()
    return wiped

# ---- CLI ----

def parse_types(s: str) -> set[str]:
    s = (s or "").strip().lower()
    if s in ("*", "all", ""):
        return set(LIMITS.keys())
    if s in ("none",):
        return set()
    out = set()
    for tok in (t.strip() for t in s.split(",")):
        if not tok:
            continue
        if tok not in LIMITS:
            raise argparse.ArgumentTypeError(f"Unknown type '{tok}'. Use {','.join(LIMITS)} or all.")
        out.add(tok)
    return out

def norm_vol(s: str) -> str:
    s = (s or "").strip().strip('"').strip()
    if not s:
        return ""
    if s.lower().startswith("\\\\.\\"):
        s = s[4:]
    if len(s) == 1:
        s += ":"
    if len(s) >= 2 and s[1] == ":":
        s = s[0].upper() + s[1:]
    return r"\\.\%s" % s

def _pause_on_exit():
    try:
        input()
    except Exception:
        pass

atexit.register(_pause_on_exit)

def main() -> int:
    ap = argparse.ArgumentParser(description="NTFS/FAT32 unallocated-space carver (or wipe unallocated space). Run as Administrator.")
    ap.add_argument("volume", nargs="?", default=None, help=r"e.g. \\.\F: (or just F)")
    ap.add_argument("--types", type=parse_types, default=None, help="png,jpg,zip,7z,exe,pdf,mp3,txt or all/* (default: prompt)")
    ap.add_argument("--chunk-limit", type=lambda x: int(x, 0), default=CHUNK_LIMIT_DEFAULT, help="kept for compatibility (unused)")
    ap.add_argument("--wipe", action="store_true", help="zero-fill unallocated clusters (DANGEROUS)")
    args = ap.parse_args()

    if not args.volume:
        dl = input("Enter drive letter to scan (e.g. C): ").strip()
        if not dl:
            print("No drive letter entered.", file=sys.stderr)
            return 1
        args.volume = dl

    if not args.wipe:
        w = input("Do you want to format unallocated clusters? Leave blank for 'no': ").strip().lower()
        if w in ("y", "yes"):
            args.wipe = True

    args.volume = norm_vol(args.volume)
    if not args.volume:
        print("Invalid volume.", file=sys.stderr)
        return 1

    if (not args.wipe) and (args.types is None):
        s = input("Enter filetypes separated by commas (example: png,jpg,zip)\nLeave empty to scan for ALL filetypes.\nTypes: ").strip()
        args.types = set(LIMITS.keys()) if s == "" else parse_types(s)
    if args.types is None:
        args.types = set()

    serial = volume_serial(args.volume)
    script_dir = Path(__file__).resolve().parent
    out_root = None
    resume_off = 0
    existing_entries = []

    if not args.wipe:
        base = script_dir / "drives"
        base.mkdir(parents=True, exist_ok=True)
        out_root = base / serial
        out_root.mkdir(parents=True, exist_ok=True)
        idx = out_root / "index.txt"
        if idx.exists():
            ans = input("Found existing index.txt. Continue from previous scan? Leave blank for 'yes': ").strip().lower()
            if ans not in ("n", "no"):
                existing_entries, resume_off = load_index(out_root)
                print(f"Resuming from offset: 0x{resume_off:016X}")

    for retry in range(2):
        try:
            with open_device(args.volume, write=args.wipe) as dev:
                boot = dev.read_exact(0, 512)

                fs_type = None
                nt = None
                fat = None

                if boot[3:11] == b"NTFS    ":
                    fs_type = "ntfs"
                    nt = parse_ntfs_boot(boot)

                    fix = win_bps_bpc(args.volume)
                    if fix:
                        bps_api, bpc_api = fix
                        if (bps_api, bpc_api) != (nt.bps, nt.bpc):
                            print(f"NOTE: overriding NTFS geometry from WinAPI: bps={bps_api} bpc={bpc_api} (boot said bps={nt.bps} bpc={nt.bpc})")
                        nt = NTFSInfo(bps=bps_api, bpc=bpc_api, total_sectors=nt.total_sectors, mft_lcn=nt.mft_lcn, frs=nt.frs)

                    fs = nt
                    vol_bytes = nt.total_sectors * nt.bps
                    mft0_off = nt.mft_lcn * nt.bpc

                    print(f"NTFS: serial={serial} bps={nt.bps} bytes_per_cluster={nt.bpc} file_record_size={nt.frs} mft_lcn={nt.mft_lcn}")
                    print(f"Volume size: {fmt_bytes(vol_bytes)} ({vol_bytes} bytes)")
                    print(f"MFT[0] byte offset: {mft0_off}")
                    print(f"Carve types: {', '.join(sorted(args.types)) if args.types else '(none)'}")

                    bitmap = load_bitmap(dev, nt)
                    print(f"Loaded $Bitmap: {len(bitmap)} bytes -> {len(bitmap) * 8} cluster bits")

                    total_unalloc = unalloc_bytes_ntfs(nt, bitmap, vol_bytes)
                    max_scan = total_unalloc - (total_unalloc % SECTOR_ALIGN)
                    print(f"Auto scan/wipe target (all unallocated clusters): {fmt_bytes(max_scan)} ({max_scan} bytes)")

                    free_runs = iter_free_cluster_runs_ntfs(bitmap)

                else:
                    if boot[0x52:0x5A].rstrip(b"\x00 ").startswith(b"FAT32"):
                        fs_type = "fat32"
                        fat = parse_fat32_boot(boot)
                        fs = fat
                        vol_bytes = fat.total_sectors * fat.bps

                        print(f"FAT32: serial={serial} bps={fat.bps} spc={fat.spc} bytes_per_cluster={fat.bpc}")
                        print(f"      reserved={fat.reserved} nfats={fat.nfats} fatsz(sectors)={fat.fatsz} root_cluster={fat.root_cluster}")
                        print(f"      first_data_sector={fat.first_data_sector} total_clusters={fat.total_clusters}")
                        print(f"Volume size: {fmt_bytes(vol_bytes)} ({vol_bytes} bytes)")
                        print(f"Carve types: {', '.join(sorted(args.types)) if args.types else '(none)'}")

                        free_clusters = fat32_count_free_clusters(dev, fat)
                        total_unalloc = free_clusters * fat.bpc
                        max_scan = total_unalloc - (total_unalloc % SECTOR_ALIGN)
                        print(f"Auto scan/wipe target (all unallocated clusters): {fmt_bytes(max_scan)} ({max_scan} bytes)")
                        print(f"Free clusters (counted from FAT): {free_clusters}")

                        free_runs = iter_free_cluster_runs_fat32(dev, fat)
                    else:
                        raise ValueError("Unsupported filesystem (expected NTFS or FAT32).")

                if args.wipe:
                    ans = input(
                        f"\n*** WIPE MODE ENABLED ***\n"
                        f"This will ZERO-FILL ALL UNALLOCATED SPACE on {args.volume} ({fmt_bytes(max_scan)}).\n"
                        f"Type WIPE to proceed: "
                    ).strip()
                    if ans != "WIPE":
                        print("Wipe cancelled.")
                        return 1
                    wiped = wipe_unallocated(dev, fs, free_runs=free_runs, write_block=READ_BLOCK_DEFAULT, max_scan_bytes=max_scan)
                    print("\nDone.")
                    print(f"Unallocated bytes wiped (zero-filled): {wiped}")
                    return 0

                scanned, counts = stream_carve(
                    dev=dev, fs=fs, free_runs=free_runs,
                    out_root=out_root, types=args.types,
                    read_block=READ_BLOCK_DEFAULT, max_scan_bytes=max_scan,
                    start_abs_off=resume_off, existing_entries=existing_entries,
                )

                print("\nDone.")
                print(f"Unallocated bytes processed: {scanned}")
                for t in sorted(args.types):
                    print(f"Carved {t.upper()}: {counts.get(t, 0)} -> {out_root / t}")

            return 0

        except PermissionError:
            print("Permission denied. Run as Administrator.", file=sys.stderr)
            return 2

        except Exception as e:
            if retry == 0 and "Bad MFT record" in str(e):
                if input("Bad MFT record, run chkdsk then scrape? Leave blank for 'yes': ").strip().lower() not in ("n", "no"):
                    os.system(f"chkdsk {args.volume[4]}: /f /r /x")
                    continue
                print("Aborting (chkdsk declined).", file=sys.stderr)
                return 4

            print(f"Error: {e}", file=sys.stderr)
            return 4

if __name__ == "__main__":
    raise SystemExit(main())
