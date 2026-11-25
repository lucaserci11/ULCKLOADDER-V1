# -*- coding: utf-8 -*-
"""
ULCKLOADDER - auditoria forense SOMENTE LEITURA para Windows 10/11.

- Nao altera, apaga, executa nem envia nada para fora do computador.
- Navegadores: o banco de historico e copiado para uma pasta temporaria,
  lido e a copia e removida em seguida (o original nunca e tocado).
- So usa a biblioteca padrao do Python (tkinter, sqlite3, winreg, ctypes).
"""

import csv
import ctypes
import hashlib
import hmac
import json
import math
import ntpath
import os
import queue
import random
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import uuid
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import winreg
except ImportError:  # fora do Windows (apenas para desenvolvimento)
    winreg = None

APP_NAME = "ULCKLOADDER V1"
VERSAO = "1.0"
IS_WIN = sys.platform.startswith("win")

# ----------------------------------------------------------------- tema ----
BG = "#0a0a0b"
SIDEBAR = "#0d0d0e"
PANEL = "#131314"
PANEL2 = "#19191b"
ROW_ALT = "#161617"
BORDER = "#2a2a2d"
FG = "#e8e8ea"
MUTED = "#8b8b92"
DIM = "#5c5c63"
RED = "#d4343b"
RED_D = "#7d1a1f"
RED_BG = "#2b0f12"
AMBER = "#d9a441"
GREEN = "#58b27f"
ERR = "#e0605f"
FONT = "Segoe UI"
MONO = "Consolas"

F_TITLE = (FONT, 16, "bold")
F_BRAND = (FONT, 15, "bold")
F_NAV = (FONT, 10)
F_BTN = (FONT, 9, "bold")
F_SMALL = (FONT, 8)
F_CAP = (FONT, 8, "bold")
F_BIG = (MONO, 20, "bold")


def blend(c1, c2, t):
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


# ------------------------------------------------------------- utilidades ---
def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ft_to_dt(ft):
    """FILETIME (100 ns desde 1601) -> datetime local."""
    try:
        if not ft:
            return None
        secs = ft / 1e7 - 11644473600
        if secs <= 0:
            return None
        return datetime.fromtimestamp(secs)
    except (OverflowError, OSError, ValueError):
        return None


def chrome_to_dt(us):
    """Microssegundos desde 1601 (formato do Chromium) -> datetime local."""
    return ft_to_dt(us * 10) if us else None


def fmt_dt(dt):
    return dt.strftime("%d/%m/%Y %H:%M:%S") if dt else "—"


def fmt_ts(ts):
    try:
        return fmt_dt(datetime.fromtimestamp(ts))
    except (OSError, ValueError, OverflowError):
        return "—"


def fmt_size(n):
    try:
        if n is None or int(n) < 0:
            return "—"
        return f"{int(n):,}".replace(",", ".")
    except (TypeError, ValueError):
        return "—"


def fmt_n(n):
    return f"{n:,}".replace(",", ".")


def existe(p):
    """True/False/None (None = nao verificado, ex.: caminho de rede)."""
    if not p or p.startswith("\\\\"):
        return None
    try:
        return os.path.exists(p)
    except OSError:
        return None


def estado_disco(p):
    e = existe(p)
    return "No disco" if e else ("Ausente do disco" if e is False else "Não verificado")


def nome_de(p):
    return ntpath.basename(p.rstrip("\\/")) or p


def join_win(prefix, label):
    if not prefix:
        return label
    return prefix + label if prefix.endswith("\\") else prefix + "\\" + label


def fixed_drives():
    out = []
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if mask & (1 << i):
                root = f"{chr(65 + i)}:\\"
                if ctypes.windll.kernel32.GetDriveTypeW(root) == 3:
                    out.append(root)
    except Exception:
        pass
    return out


def is_junction(entry):
    try:
        return bool(entry.is_junction())
    except Exception:
        return False


def sort_key(s):
    s = str(s)
    m = re.match(r"^(\d\d)/(\d\d)/(\d{4}) (\d\d):(\d\d):(\d\d)$", s)
    if m:
        d, mo, y, h, mi, se = map(int, m.groups())
        return (0, ((((y * 13 + mo) * 32 + d) * 24 + h) * 60 + mi) * 60 + se)
    if re.match(r"^[\d\.]+$", s):
        try:
            return (0, int(s.replace(".", "")))
        except ValueError:
            pass
    return (1, s.lower())


# ============================================================ PARSERS ========
# ---- LNK (atalhos de Arquivos Recentes / Jump Lists) ----
LNK_SIG = b"\x4C\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xC0\x00\x00\x00\x00\x00\x00\x46"


def _cstr(data, off, wide=False):
    if wide:
        end = off
        while end + 1 < len(data) and data[end:end + 2] != b"\x00\x00":
            end += 2
        return data[off:end].decode("utf-16le", "replace")
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("mbcs" if IS_WIN else "cp1252", "replace")


def parse_lnk(data):
    """Le um arquivo .lnk (somente leitura de bytes). Retorna dict ou None."""
    try:
        if len(data) < 0x4C or struct.unpack_from("<I", data, 0)[0] != 0x4C:
            return None
        flags = struct.unpack_from("<I", data, 0x14)[0]
        attrs = struct.unpack_from("<I", data, 0x18)[0]
        ctime, atime, mtime = struct.unpack_from("<3Q", data, 0x1C)
        fsize = struct.unpack_from("<I", data, 0x34)[0]
        off = 0x4C
        if flags & 0x01:  # HasLinkTargetIDList
            off += 2 + struct.unpack_from("<H", data, off)[0]
        target = ""
        if flags & 0x02:  # HasLinkInfo
            li = off
            li_size, hdr, lf = struct.unpack_from("<3I", data, li)
            lbp, cnr, suf = struct.unpack_from("<3I", data, li + 16)
            if lf & 1 and lbp:
                if hdr >= 0x24:
                    ulbp, usuf = struct.unpack_from("<2I", data, li + 28)
                    base = _cstr(data, li + ulbp, True) if ulbp else _cstr(data, li + lbp)
                    sfx = _cstr(data, li + usuf, True) if usuf else (_cstr(data, li + suf) if suf else "")
                else:
                    base = _cstr(data, li + lbp)
                    sfx = _cstr(data, li + suf) if suf else ""
                target = base + sfx
            elif lf & 2 and cnr:
                nn = struct.unpack_from("<I", data, li + cnr + 8)[0]
                target = _cstr(data, li + cnr + nn)
                if suf:
                    target += "\\" + _cstr(data, li + suf)
            off = li + li_size
        uni = bool(flags & 0x80)
        strs = {}
        for bit, nm in ((0x04, "name"), (0x08, "rel"), (0x10, "wd"), (0x20, "args"), (0x40, "icon")):
            if flags & bit:
                n = struct.unpack_from("<H", data, off)[0]
                off += 2
                ln = n * 2 if uni else n
                raw = data[off:off + ln]
                off += ln
                strs[nm] = raw.decode("utf-16le", "replace") if uni else raw.decode("cp1252", "replace")
        if not target:
            rel, wd = strs.get("rel", ""), strs.get("wd", "")
            if rel and wd and not ntpath.isabs(rel):
                target = ntpath.normpath(ntpath.join(wd, rel))
            else:
                target = rel
        return {
            "target": target, "args": strs.get("args", ""), "dir": bool(attrs & 0x10),
            "atime": ft_to_dt(atime), "mtime": ft_to_dt(mtime), "ctime": ft_to_dt(ctime), "size": fsize,
        }
    except (struct.error, ValueError, IndexError):
        return None


def split_lnks(data):
    idx = [m.start() for m in re.finditer(re.escape(LNK_SIG), data)]
    return [data[a:(idx[i + 1] if i + 1 < len(idx) else len(data))] for i, a in enumerate(idx)]


# ---- Compound File Binary (formato das AutomaticDestinations) ----
class CFB:
    FREE = 0xFFFFFFFA

    def __init__(self, data):
        if data[:8] != b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1":
            raise ValueError("não é um arquivo CFB")
        self.d = data
        self.ss = 1 << struct.unpack_from("<H", data, 0x1E)[0]
        self.mss = 1 << struct.unpack_from("<H", data, 0x20)[0]
        nfat, first_dir, _t, self.cutoff, first_mini, nmini, first_difat, ndifat = struct.unpack_from("<8I", data, 0x2C)
        difat = list(struct.unpack_from("<109I", data, 0x4C))
        s, per = first_difat, self.ss // 4 - 1
        for _ in range(ndifat):
            if s >= self.FREE:
                break
            blk = struct.unpack_from(f"<{per + 1}I", data, self._off(s))
            difat += blk[:per]
            s = blk[per]
        self.fat = []
        for sec in [x for x in difat if x < self.FREE][:nfat]:
            self.fat += struct.unpack_from(f"<{self.ss // 4}I", data, self._off(sec))
        dd = self._read_chain(first_dir)
        self.entries = []
        for i in range(len(dd) // 128):
            e = dd[i * 128:(i + 1) * 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            name = e[:max(0, nlen - 2)].decode("utf-16le", "replace")
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<Q", e, 120)[0] & 0xFFFFFFFF
            self.entries.append((name, e[66], start, size))
        root = self.entries[0]
        self.ministream = self._read_chain(root[2])[:root[3]] if root[2] < self.FREE else b""
        mf = self._read_chain(first_mini) if first_mini < self.FREE else b""
        self.minifat = list(struct.unpack_from(f"<{len(mf) // 4}I", mf, 0)) if mf else []

    def _off(self, s):
        return (s + 1) * self.ss

    def _chain(self, start, fat):
        out, s, guard = [], start, 0
        while s < self.FREE and guard < 1_000_000:
            out.append(s)
            if s >= len(fat):
                break
            s = fat[s]
            guard += 1
        return out

    def _read_chain(self, start):
        return b"".join(self.d[self._off(s):self._off(s) + self.ss] for s in self._chain(start, self.fat))

    def streams(self):
        for name, typ, start, size in self.entries:
            if typ != 2:
                continue
            if size < self.cutoff:
                buf = b"".join(self.ministream[s * self.mss:(s + 1) * self.mss] for s in self._chain(start, self.minifat))
            else:
                buf = self._read_chain(start)
            yield name, buf[:size]


# ---- ShimCache (AppCompatCache) ----
def parse_shimcache(data):
    """Formato Windows 10/11 (assinatura '10ts'). Retorna lista de (caminho, FILETIME)."""
    if len(data) < 52:
        raise ValueError("dados do ShimCache muito curtos")
    off = struct.unpack_from("<I", data, 0)[0]
    if data[off:off + 4] != b"10ts":
        raise ValueError("formato de ShimCache não suportado (esperado Windows 10/11)")
    out = []
    while off + 14 <= len(data) and data[off:off + 4] == b"10ts":
        entry_len = struct.unpack_from("<I", data, off + 8)[0]
        plen = struct.unpack_from("<H", data, off + 12)[0]
        path = data[off + 14:off + 14 + plen].decode("utf-16le", "replace")
        ft = struct.unpack_from("<Q", data, off + 14 + plen)[0] if off + 22 + plen <= len(data) else 0
        out.append((path, ft))
        off += 12 + entry_len
    return out


# ---- ShellBags ----
KNOWN_GUIDS = {
    "20D04FE0-3AEA-1069-A2D8-08002B30309D": "Este Computador",
    "F02C1A0D-BE21-4350-88B0-7367FC96EF3C": "Rede",
    "645FF040-5081-101B-9F08-00AA002F954E": "Lixeira",
    "59031A47-3F72-44A7-89C5-5595FE6B30EE": "Pasta do usuário",
    "450D8FBA-AD25-11D0-98A8-0800361B1103": "Documentos",
    "031E4825-7B94-4DC3-B131-E946B44C8DD5": "Bibliotecas",
    "374DE290-123F-4565-9164-39C4925E467B": "Downloads",
    "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Área de Trabalho",
    "24AD3AD4-A569-4530-98E1-AB02F9417AA8": "Imagens",
    "3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE": "Músicas",
    "F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A": "Vídeos",
}


def _ext_longname(raw):
    i = raw.find(b"\x04\x00\xef\xbe")  # assinatura 0xBEEF0004
    if i < 4:
        return ""
    start = i - 4
    ver = struct.unpack_from("<H", raw, start + 2)[0]
    j = start + (18 if ver < 7 else 38)
    while j + 4 <= len(raw):
        k, run = j, []
        while k + 2 <= len(raw):
            cu = raw[k] | (raw[k + 1] << 8)
            if cu < 0x20:
                break
            run.append(chr(cu))
            k += 2
        if len(run) >= 2 and k + 2 <= len(raw) and raw[k] == 0 and raw[k + 1] == 0:
            return "".join(run)
        j += 2
    return ""


def shell_item_info(raw):
    """Interpreta o primeiro item de shell de um valor do BagMRU -> (nome, tipo) ou None."""
    if len(raw) < 4:
        return None
    t = raw[2]
    if t == 0x1F and len(raw) >= 20:
        g = str(uuid.UUID(bytes_le=bytes(raw[4:20]))).upper()
        return KNOWN_GUIDS.get(g, "{" + g + "}"), "Raiz"
    if (t & 0x70) == 0x20:
        return raw[3:].split(b"\x00")[0].decode("ascii", "replace").rstrip("\\"), "Unidade"
    if (t & 0x70) == 0x40:
        return raw[5:].split(b"\x00")[0].decode("cp1252", "replace"), "Rede"
    if (t & 0x70) == 0x30 or t == 0x74:
        longn = _ext_longname(raw)
        short = ""
        if (t & 0x70) == 0x30 and len(raw) > 14:
            if t & 0x04:
                short = _cstr(raw, 14, True)
            else:
                short = raw[14:].split(b"\x00")[0].decode("cp1252", "replace")
        kind = "Arquivo" if (t & 0x70) == 0x30 and (t & 0x03) == 2 else "Pasta"
        return (longn or short or f"<item 0x{t:02X}>"), kind
    return f"<item 0x{t:02X}>", "Outro"


# =========================================================== COLETORES =======
def load_recentes():
    base = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
    if not os.path.isdir(base):
        raise OSError("Pasta 'Recent' não encontrada.")
    rows = []
    for fn in os.listdir(base):
        if not fn.lower().endswith(".lnk"):
            continue
        fp = os.path.join(base, fn)
        try:
            with open(fp, "rb") as f:
                info = parse_lnk(f.read())
            aberto = fmt_ts(os.path.getmtime(fp))
        except OSError:
            continue
        alvo = info["target"] if info and info["target"] else ""
        rows.append((fn[:-4], alvo or "(alvo indisponível)",
                     aberto, fmt_dt(info["mtime"]) if info else "—",
                     estado_disco(alvo) if alvo else "Não verificado"))
    return rows, ""


KNOWN_APPIDS = {
    "1b4dd67f29cb1962": "Windows Explorer",
    "f01b4d95cf55d32a": "Windows Explorer",
    "5f7b5f1e01b83767": "Acesso rápido",
}


def load_jumplists():
    base = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
    rows, achou = [], False
    for sub, auto in (("AutomaticDestinations", True), ("CustomDestinations", False)):
        d = os.path.join(base, sub)
        if not os.path.isdir(d):
            continue
        achou = True
        for fn in os.listdir(d):
            fp = os.path.join(d, fn)
            appid = fn.split(".")[0].lower()
            app = KNOWN_APPIDS.get(appid, appid)
            try:
                with open(fp, "rb") as f:
                    data = f.read()
                visto = fmt_ts(os.path.getmtime(fp))
            except OSError:
                continue
            blobs = []
            if auto:
                try:
                    blobs = [b for n, b in CFB(data).streams() if n.lower() != "destlist"]
                except Exception:
                    continue
            else:
                blobs = split_lnks(data)
            for b in blobs:
                info = parse_lnk(b)
                if not info or not info["target"]:
                    continue
                rows.append((app, nome_de(info["target"]), info["target"], visto,
                             "Automática" if auto else "Personalizada", estado_disco(info["target"])))
    if not achou:
        raise OSError("Pastas de Jump Lists não encontradas.")
    return rows, "A data exibida é a da última atualização do arquivo da Jump List do aplicativo."


def load_shellbags():
    if winreg is None:
        raise OSError("Disponível apenas no Windows.")
    roots = [
        ("Software\\Microsoft\\Windows\\Shell\\BagMRU", "NTUSER.DAT"),
        ("Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", "UsrClass.dat"),
    ]
    rows = []

    def walk(path, prefix, origem, depth, raiz):
        if depth > 40:
            return
        try:
            k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        except OSError:
            return
        items = []
        try:
            nsub, nval, lw = winreg.QueryInfoKey(k)[:3]
            for i in range(nval):
                try:
                    name, data, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                if name.isdigit() and isinstance(data, (bytes, bytearray)):
                    items.append((name, bytes(data)))
        finally:
            winreg.CloseKey(k)
        if not raiz:
            rows.append((prefix, kind_cache.get(path, "?"), fmt_dt(ft_to_dt(lw)), origem))
        for name, data in items:
            info = shell_item_info(data)
            label, kind = info if info else ("<item desconhecido>", "?")
            sub = path + "\\" + name
            kind_cache[sub] = kind
            walk(sub, join_win(prefix, label), origem, depth + 1, False)

    kind_cache = {}
    for path, origem in roots:
        walk(path, "", origem, 0, True)
    if not rows:
        return rows, "Nenhum registro de ShellBags encontrado."
    return rows, "A data é a da última gravação da chave no registro (≈ último acesso à pasta pelo Explorer)."


def load_shimcache_raw():
    if winreg is None:
        raise OSError("Disponível apenas no Windows.")
    try:
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                           r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache", 0, winreg.KEY_READ)
    except PermissionError:
        raise PermissionError("Acesso negado. Abra o ULCKLOADDER como administrador para ler o ShimCache.")
    try:
        data, _t = winreg.QueryValueEx(k, "AppCompatCache")
    finally:
        winreg.CloseKey(k)
    return parse_shimcache(bytes(data))


def load_shimcache():
    entries = load_shimcache_raw()
    rows = []
    for i, (path, ft) in enumerate(entries, 1):
        rows.append((str(i), nome_de(path), path, estado_disco(path), fmt_dt(ft_to_dt(ft))))
    return rows, ("Presença no ShimCache indica que o sistema viu o arquivo; sozinha, não prova execução. "
                  "A data é a última modificação do arquivo, não o momento da execução.")


def _sid_atual():
    try:
        out = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True,
                             creationflags=0x08000000, timeout=10).stdout
        m = re.search(r"S-1-[\d-]+", out)
        return m.group(0) if m else None
    except Exception:
        return None


def parse_recycle_i(d):
    ver = struct.unpack_from("<Q", d, 0)[0]
    size = struct.unpack_from("<Q", d, 8)[0]
    dele = struct.unpack_from("<Q", d, 16)[0]
    if ver == 2:
        n = struct.unpack_from("<I", d, 24)[0]
        path = d[28:28 + n * 2].decode("utf-16le", "replace").rstrip("\x00")
    elif ver == 1:
        path = d[24:24 + 520].decode("utf-16le", "replace").split("\x00")[0]
    else:
        raise ValueError("versão de $I desconhecida")
    return path, size, ft_to_dt(dele)


def load_apagados(mode):
    rows, avisos = [], []
    if mode in ("Todos", "Lixeira"):
        drives = fixed_drives() or [os.environ.get("SystemDrive", "C:") + "\\"]
        for drv in drives:
            rb = drv + "$Recycle.Bin"
            try:
                sids = os.listdir(rb)
            except OSError:
                sid = _sid_atual()
                sids = [sid] if sid else []
            for sid in sids:
                sd = os.path.join(rb, sid)
                try:
                    names = os.listdir(sd)
                except OSError:
                    continue
                for n in names:
                    if not n.startswith("$I"):
                        continue
                    try:
                        with open(os.path.join(sd, n), "rb") as f:
                            path, size, dele = parse_recycle_i(f.read(4096))
                    except (OSError, ValueError, struct.error):
                        continue
                    r_ok = os.path.exists(os.path.join(sd, "$R" + n[2:]))
                    rows.append((nome_de(path), path, fmt_dt(dele), fmt_size(size),
                                 "Na Lixeira" if r_ok else "Lixeira (conteúdo ausente)",
                                 f"Lixeira {drv[:2]} · {sid} · {n}"))
    if mode in ("Todos", "Indícios (ShimCache)"):
        try:
            for path, ft in load_shimcache_raw():
                if existe(path) is False:
                    rows.append((nome_de(path), path, "—", "—", "Ausente do disco (indício)",
                                 f"ShimCache · mod. registrada: {fmt_dt(ft_to_dt(ft))}"))
        except Exception as e:
            avisos.append(f"ShimCache não lido: {e}")
    msg = ("Metadados apenas — não há recuperação de arquivos. Itens do ShimCache são indícios "
           "(o arquivo pode ter sido movido, renomeado ou desinstalado).")
    if avisos:
        msg += "  ·  " + " ".join(avisos)
    return rows, msg


# ---- navegadores ----
def browser_dbs():
    la, ra = os.environ.get("LOCALAPPDATA", ""), os.environ.get("APPDATA", "")
    out = []
    for nome, base in (("Chrome", os.path.join(la, "Google", "Chrome", "User Data")),
                       ("Edge", os.path.join(la, "Microsoft", "Edge", "User Data"))):
        if os.path.isdir(base):
            for d in sorted(os.listdir(base)):
                if d == "Default" or d.startswith("Profile "):
                    h = os.path.join(base, d, "History")
                    if os.path.isfile(h):
                        out.append((nome if d == "Default" else f"{nome} ({d})", h))
    for nome, base in (("Opera GX", os.path.join(ra, "Opera Software", "Opera GX Stable")),
                       ("Opera", os.path.join(ra, "Opera Software", "Opera Stable"))):
        for h in (os.path.join(base, "History"), os.path.join(base, "Default", "History")):
            if os.path.isfile(h):
                out.append((nome, h))
                break
    return out


def read_history_db(src, fn):
    tmp = tempfile.mkdtemp(prefix="ulck_")
    try:
        dst = os.path.join(tmp, "h.db")
        shutil.copyfile(src, dst)
        for ext in ("-wal", "-shm", "-journal"):
            if os.path.exists(src + ext):
                try:
                    shutil.copyfile(src + ext, dst + ext)
                except OSError:
                    pass
        con = sqlite3.connect(dst)
        try:
            return fn(con)
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def q_downloads(con):
    cols = {r[1] for r in con.execute("PRAGMA table_info(downloads)")}
    tp = "target_path" if "target_path" in cols else "current_path"
    tab = "d.tab_url" if "tab_url" in cols else "''"
    ref = "d.referrer" if "referrer" in cols else "''"
    sql = (f"SELECT d.{tp}, d.current_path, d.start_time, d.total_bytes, {tab}, {ref}, "
           "(SELECT c.url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY c.chain_index DESC LIMIT 1) "
           "FROM downloads d ORDER BY d.start_time DESC")
    return con.execute(sql).fetchall()


def q_history(con):
    return con.execute("SELECT url, title, visit_count, last_visit_time FROM urls "
                       "ORDER BY last_visit_time DESC LIMIT 100000").fetchall()


def q_searches(con):
    return con.execute("SELECT k.term, u.url, u.last_visit_time FROM keyword_search_terms k "
                       "JOIN urls u ON u.id=k.url_id ORDER BY u.last_visit_time DESC LIMIT 100000").fetchall()


def load_downloads():
    dbs = browser_dbs()
    if not dbs:
        raise OSError("Nenhum navegador compatível (Chrome, Edge, Opera GX) encontrado.")
    rows, avisos = [], []
    for nav, h in dbs:
        try:
            for tp, cp, st, tb, tab, ref, url in read_history_db(h, q_downloads):
                caminho = tp or cp or ""
                rows.append((nav, nome_de(caminho) if caminho else "(sem nome)", caminho or "—",
                             fmt_size(tb), fmt_dt(chrome_to_dt(st)), url or tab or ref or "—",
                             estado_disco(caminho) if caminho else "Não verificado"))
        except PermissionError:
            avisos.append(f"{nav}: arquivo em uso — feche o navegador")
        except Exception as e:
            avisos.append(f"{nav}: {e}")
    return rows, ("  ·  ".join(avisos))


def load_historico(mode):
    dbs = browser_dbs()
    if not dbs:
        raise OSError("Nenhum navegador compatível (Chrome, Edge, Opera GX) encontrado.")
    rows, avisos = [], []
    for nav, h in dbs:
        try:
            if mode == "Pesquisas":
                for term, url, t in read_history_db(h, q_searches):
                    rows.append((nav, f"Pesquisa: {term}", url, "—", fmt_dt(chrome_to_dt(t))))
            else:
                for url, title, vc, t in read_history_db(h, q_history):
                    rows.append((nav, title or "(sem título)", url, str(vc), fmt_dt(chrome_to_dt(t))))
        except PermissionError:
            avisos.append(f"{nav}: arquivo em uso — feche o navegador")
        except Exception as e:
            avisos.append(f"{nav}: {e}")
    return rows, "  ·  ".join(avisos)


# ------------------------------------------------------ arquivos suspeitos ---
SUSPECT_NAME_TERMS = (
    "cylex", "real", "xeno", "nexomia", "velocity", "fflag",
    "executor", "injector", "exploit", "cheat", "roblox",
)
# Extensoes de script/execucao que merecem triagem quando ha outros indicadores.
SCRIPT_EXTS = {".exe", ".dll", ".sys", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe",
               ".js", ".jse", ".wsf", ".wsh", ".hta", ".scr", ".com", ".jar", ".msi"}
SIZE_CYLEX_MIN = 6 * 1024 * 1024
SIZE_CYLEX_MAX = 8 * 1024 * 1024
JSON_TEXT_LIMIT = 2 * 1024 * 1024


def defender_detections():
    """Retorna caminhos que o Microsoft Defender registrou como detecoes; sem rede."""
    if not IS_WIN:
        return {}
    ps = ("$ErrorActionPreference='Stop'; "
          "Get-MpThreatDetection | Select-Object ThreatID,ThreatStatusID,Resources "
          "| ConvertTo-Json -Depth 5 -Compress")
    try:
        cp = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                            capture_output=True, text=True, timeout=18,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if cp.returncode != 0 or not cp.stdout.strip():
            return {}
        data = json.loads(cp.stdout)
        if isinstance(data, dict):
            data = [data]
        found = {}
        for item in data if isinstance(data, list) else []:
            resources = item.get("Resources", [])
            if isinstance(resources, str):
                resources = [resources]
            for resource in resources or []:
                # Recursos do Defender costumam vir como "file:_C:\\..."
                value = str(resource)
                if value.lower().startswith("file:"):
                    value = value[5:].lstrip("_")
                if os.path.isabs(value):
                    found[os.path.normcase(os.path.normpath(value))] = str(item.get("ThreatID", "Detecção do Defender"))
        return found
    except Exception:
        return {}


def sha256_file(path, limit=150 * 1024 * 1024):
    """Hash somente leitura; evita arquivos enormes para não travar a varredura."""
    h = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > limit:
                    return "Não calculado (acima de 150 MB)"
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return "Não disponível (sem acesso)"


def inspect_json(path):
    """Analisa JSON como dados, nunca executa seu conteúdo."""
    indicators = []
    try:
        if os.path.getsize(path) > JSON_TEXT_LIMIT:
            return indicators
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            raw = f.read(JSON_TEXT_LIMIT + 1)
        try:
            parsed = json.loads(raw)
        except (ValueError, TypeError):
            indicators.append("JSON inválido ou truncado")
            parsed = None
        low = raw.lower()
        patterns = (
            ("powershell", "referência a PowerShell"),
            ("frombase64string", "uso de decodificação Base64 em script"),
            ("invoke-expression", "referência a execução dinâmica de comandos"),
            ("downloadstring", "referência a download de conteúdo por script"),
            ("wscript.shell", "referência ao Windows Script Host"),
            ("mshta.exe", "referência ao mshta"),
            ("rundll32", "referência ao rundll32"),
            ("regsvr32", "referência ao regsvr32"),
            ("loadstring", "referência a execução dinâmica de código Lua"),
            ("getgenv", "referência a ambiente de executor Roblox"),
            ("synapse", "referência a ferramenta de execução Roblox"),
            ("webhook", "referência a webhook"),
        )
        for needle, label in patterns:
            if needle in low:
                indicators.append(label)
        if parsed is not None and not isinstance(parsed, (dict, list, str, int, float, bool, type(None))):
            indicators.append("estrutura JSON incomum")
    except OSError:
        pass
    return list(dict.fromkeys(indicators))


def default_suspect_folders():
    home = os.path.expanduser("~")
    candidates = [os.path.join(home, n) for n in ("Downloads", "Desktop", "Documents")]
    la = os.environ.get("LOCALAPPDATA", "")
    ra = os.environ.get("APPDATA", "")
    candidates += [os.path.join(la, "Temp"), os.path.join(la, "Roblox"),
                   os.path.join(ra, "Roblox")]
    return list(dict.fromkeys(os.path.normpath(x) for x in candidates if x and os.path.isdir(x)))


# ============================================================ INTERFACE ======
class Btn(tk.Label):
    def __init__(self, parent, text, cmd, primary=False, **kw):
        self.base = RED_BG if primary else PANEL2
        super().__init__(parent, text=text, bg=self.base, fg=FG, font=F_BTN, padx=16, pady=6,
                         cursor="hand2", highlightthickness=1,
                         highlightbackground=RED_D if primary else BORDER, **kw)
        self.cmd = cmd
        self.bind("<Enter>", lambda e: self.config(bg=RED_D))
        self.bind("<Leave>", lambda e: self.config(bg=self.base))
        self.bind("<ButtonRelease-1>", lambda e: self.cmd())


def clickable(widget, cmd, enter=None, leave=None):
    widget.bind("<ButtonRelease-1>", lambda e: cmd())
    if enter:
        widget.bind("<Enter>", lambda e: enter())
    if leave:
        widget.bind("<Leave>", lambda e: leave())
    for c in widget.winfo_children():
        clickable(c, cmd, enter, leave)


def make_entry(parent, var=None, width=30):
    return tk.Entry(parent, textvariable=var, width=width, bg=PANEL2, fg=FG, insertbackground=FG,
                    relief="flat", font=(FONT, 10), highlightthickness=1, highlightbackground=BORDER,
                    highlightcolor=RED, disabledbackground=PANEL2)


def caption(parent, text, **kw):
    return tk.Label(parent, text=text, bg=kw.pop("bg", BG), fg=MUTED, font=F_CAP, **kw)


class DataPage(tk.Frame):
    key = ""
    title = ""
    tipo_log = ""
    columns = []        # [(nome, largura)]
    path_col = None     # coluna com caminho (copiar / mostrar no Explorer)
    note = ""
    modes = None        # lista de opcoes do seletor "Visão"
    auto = True
    MAX_SHOW = 20000

    def __init__(self, app, parent):
        super().__init__(parent, bg=BG)
        self.app = app
        self.rows, self.hay, self.filtered = [], [], []
        self.loaded = self.busy = False
        self.sort_col, self.sort_desc = None, False
        self.stop_event = threading.Event()

        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=28, pady=(22, 0))
        tk.Label(head, text=self.title, bg=BG, fg=FG, font=F_TITLE).pack(side="left")
        Btn(head, "Atualizar", self.refresh).pack(side="right")
        Btn(head, "Exportar CSV", self.export).pack(side="right", padx=8)
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(12, 10))

        self.extra = tk.Frame(self, bg=BG)
        self.extra.pack(fill="x", padx=28)
        self.build_extra(self.extra)

        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", padx=28, pady=(0, 8))
        caption(bar, "BUSCAR").pack(side="left", padx=(0, 8))
        self.q = tk.StringVar()
        self._filter_after = None
        make_entry(bar, self.q, 44).pack(side="left", ipady=4)
        self.q.trace_add("write", self.queue_filter)
        if self.modes:
            caption(bar, "VISÃO").pack(side="left", padx=(18, 8))
            self.mode = tk.StringVar(value=self.modes[0])
            cb = ttk.Combobox(bar, textvariable=self.mode, values=self.modes, state="readonly", width=24)
            cb.pack(side="left")
            cb.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.status = tk.Label(bar, text="", bg=BG, fg=MUTED, font=F_SMALL, anchor="e")
        self.status.pack(side="right")

        box = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        box.pack(fill="both", expand=True, padx=28, pady=(0, 6))
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        ids = [f"c{i}" for i in range(len(self.columns))]
        self.tree = ttk.Treeview(box, columns=ids, show="headings", selectmode="extended")
        for i, (nm, w) in enumerate(self.columns):
            self.tree.heading(ids[i], text=nm.upper(), anchor="w", command=lambda c=i: self.sort_by(c))
            self.tree.column(ids[i], width=int(w * app.S), minwidth=int(60 * app.S), anchor="w", stretch=(i == len(self.columns) - 1))
        vs = ttk.Scrollbar(box, orient="vertical", command=self.tree.yview)
        hs = ttk.Scrollbar(box, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        self.tree.tag_configure("odd", background=ROW_ALT)
        self.tree.tag_configure("warn", foreground=AMBER)

        self.foot = tk.Label(self, text=self.note, bg=BG, fg=DIM, font=F_SMALL, anchor="w", justify="left", wraplength=int(1000 * app.S))
        self.foot.pack(fill="x", padx=28, pady=(0, 10))

        self.menu = tk.Menu(self, tearoff=0, bg=PANEL2, fg=FG, activebackground=RED_BG, activeforeground=FG, bd=0)
        self.menu.add_command(label="Copiar linha", command=self.copy_row)
        if self.path_col is not None:
            self.menu.add_command(label="Copiar caminho", command=self.copy_path)
            self.menu.add_command(label="Mostrar no Explorer", command=self.show_explorer)
        self.tree.bind("<Button-3>", self.popup)

    # ---- ganchos para subclasses ----
    def build_extra(self, f):
        pass

    def prepare(self, mode):
        return mode

    def load(self, ctx):
        raise NotImplementedError

    def log_row(self, r):
        return (r[0], "", "", self.tipo_log, "", "Registro encontrado")

    def on_show(self):
        if self.auto and not self.loaded and not self.busy:
            self.refresh()

    # ---- carregamento ----
    def set_status(self, text, color=MUTED):
        self.status.config(text=text, fg=color)

    def refresh(self):
        if self.busy:
            return
        mode = self.mode.get() if self.modes else None
        try:
            ctx = self.prepare(mode)
        except Exception as e:
            self.set_status(str(e), ERR)
            return
        self.busy = True
        self.stop_event.clear()
        self.set_status("Carregando…", MUTED)

        def work():
            try:
                rows, msg = self.load(ctx)
                self.app.post(self._done, rows, msg, None)
            except Exception as e:
                self.app.post(self._done, [], "", str(e) or type(e).__name__)

        threading.Thread(target=work, daemon=True).start()

    def _done(self, rows, msg, err):
        self.busy = False
        self.loaded = True
        self.rows = rows
        self.hay = [" ".join(map(str, r)).lower() for r in rows]
        self.sort_col = None
        self.app.logs[self.key] = [self.log_row(r) for r in rows]
        self.app.last_audit = datetime.now()
        self.apply_filter()
        self.foot.config(text=(self.note + ("  ·  " + msg if msg and msg not in self.note else "")).strip())
        if err:
            self.set_status(err, ERR)
        self.app.refresh_summary()

    def queue_filter(self, *_):
        # Pequeno debounce para manter a digitação fluida em listas grandes.
        if self._filter_after is not None:
            try:
                self.after_cancel(self._filter_after)
            except tk.TclError:
                pass
        self._filter_after = self.after(90, self.apply_filter)

    def apply_filter(self):
        self._filter_after = None
        terms = self.q.get().lower().split()
        if terms:
            self.filtered = [r for r, h in zip(self.rows, self.hay) if all(t in h for t in terms)]
        else:
            self.filtered = list(self.rows)
        self.fill()

    def row_tags(self, i, r):
        tags = ["odd"] if i % 2 else []
        if any("Ausente" in str(c) for c in r):
            tags.append("warn")
        return tuple(tags)

    def fill(self):
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(self.filtered[:self.MAX_SHOW]):
            self.tree.insert("", "end", values=r, tags=self.row_tags(i, r))
        n, tot = len(self.filtered), len(self.rows)
        txt = f"{fmt_n(n)} de {fmt_n(tot)} itens" if self.q.get().strip() else f"{fmt_n(tot)} itens"
        if n > self.MAX_SHOW:
            txt += f"  ·  exibindo {fmt_n(self.MAX_SHOW)} (use a busca ou exporte o CSV completo)"
        if self.loaded:
            self.set_status(txt, MUTED)

    def sort_by(self, col):
        self.sort_desc = (not self.sort_desc) if self.sort_col == col else False
        self.sort_col = col
        paired = sorted(zip(self.rows, self.hay), key=lambda p: sort_key(p[0][col]), reverse=self.sort_desc)
        self.rows = [p[0] for p in paired]
        self.hay = [p[1] for p in paired]
        for i, (nm, _w) in enumerate(self.columns):
            arrow = (" ▼" if self.sort_desc else " ▲") if i == col else ""
            self.tree.heading(f"c{i}", text=nm.upper() + arrow)
        self.apply_filter()

    # ---- menu de contexto / exportacao ----
    def popup(self, ev):
        iid = self.tree.identify_row(ev.y)
        if iid:
            if iid not in self.tree.selection():
                self.tree.selection_set(iid)
            self.menu.tk_popup(ev.x_root, ev.y_root)

    def _sel_values(self):
        sel = self.tree.selection()
        return [self.tree.item(i, "values") for i in sel]

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)

    def copy_row(self):
        self._copy("\n".join("\t".join(map(str, v)) for v in self._sel_values()))

    def copy_path(self):
        self._copy("\n".join(str(v[self.path_col]) for v in self._sel_values()))

    def show_explorer(self):
        vals = self._sel_values()
        if vals and IS_WIN:
            p = str(vals[0][self.path_col])
            if os.path.exists(p):
                subprocess.Popen(f'explorer /select,"{p}"')

    def export(self):
        if not self.filtered:
            messagebox.showinfo(APP_NAME, "Não há dados para exportar.")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=f"ulckloadder_{self.key}.csv",
                                          filetypes=[("CSV", "*.csv")])
        if fn:
            with open(fn, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow([c[0] for c in self.columns])
                w.writerows(self.filtered)


# ---------------------------------------------------------- paginas ---------
class AuditPage(DataPage):
    key, title, tipo_log = "auditoria", "Auditoria de arquivos", "Auditoria"
    columns = [("Nome", 230), ("Caminho completo", 480), ("Modificado", 140), ("Criado", 140), ("Tamanho (bytes)", 110)]
    path_col = 1
    auto = False
    note = "Somente leitura: os arquivos são apenas listados, nunca abertos nem executados."

    def build_extra(self, f):
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", pady=(0, 8))
        caption(row, "PASTAS", width=11, anchor="w").pack(side="left", anchor="n")
        self.lb = tk.Listbox(row, height=3, bg=PANEL, fg=FG, selectbackground=RED_BG, selectforeground=FG,
                             relief="flat", highlightthickness=1, highlightbackground=BORDER, activestyle="none",
                             font=(FONT, 9), selectmode="extended")
        self.lb.pack(side="left", fill="x", expand=True)
        col = tk.Frame(row, bg=BG)
        col.pack(side="left", padx=(8, 0))
        for t, c in (("Adicionar pasta", self.add_folder), ("Todas as unidades", self.add_drives),
                     ("Remover", self.rem_folder)):
            Btn(col, t, c).pack(fill="x", pady=1)
        home = os.path.expanduser("~")
        for n in ("Downloads", "Desktop", "Documents"):
            p = os.path.join(home, n)
            if os.path.isdir(p):
                self.lb.insert("end", p)

        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", pady=(0, 8))
        caption(row, "EXTENSÕES", width=11, anchor="w").pack(side="left")
        self.ext_vars = {}
        for e, v in ((".exe", True), (".dll", True), (".json", True)):
            var = tk.BooleanVar(value=v)
            self.ext_vars[e] = var
            tk.Checkbutton(row, text=e, variable=var, bg=BG, fg=FG, selectcolor=PANEL2, activebackground=BG,
                           activeforeground=FG, font=(FONT, 9), highlightthickness=0, bd=0).pack(side="left", padx=(0, 10))
        caption(row, "OUTRAS (ex.: .sys, .bat)").pack(side="left", padx=(10, 6))
        self.custom = tk.StringVar()
        make_entry(row, self.custom, 22).pack(side="left", ipady=3)

        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", pady=(0, 10))
        caption(row, "NOME CONTÉM", width=11, anchor="w").pack(side="left")
        self.name = tk.StringVar()
        make_entry(row, self.name, 30).pack(side="left", ipady=3)
        Btn(row, "Iniciar auditoria", self.refresh, primary=True).pack(side="left", padx=(14, 6))
        Btn(row, "Parar", self.stop_event.set).pack(side="left")

    def add_folder(self):
        p = filedialog.askdirectory(title="Selecionar pasta para auditar")
        if p and p not in self.lb.get(0, "end"):
            self.lb.insert("end", os.path.normpath(p))

    def add_drives(self):
        for d in fixed_drives():
            if d not in self.lb.get(0, "end"):
                self.lb.insert("end", d)

    def rem_folder(self):
        for i in reversed(self.lb.curselection()):
            self.lb.delete(i)

    def prepare(self, mode):
        folders = list(self.lb.get(0, "end"))
        exts = [e for e, v in self.ext_vars.items() if v.get()]
        for x in re.split(r"[,; ]+", self.custom.get()):
            x = x.strip().lower().lstrip("*")
            if x:
                exts.append(x if x.startswith(".") else "." + x)
        name = self.name.get().strip().lower()
        if not folders:
            raise ValueError("Selecione ao menos uma pasta.")
        if not exts and not name:
            raise ValueError("Marque uma extensão ou digite parte do nome.")
        return dict(folders=folders, exts=tuple(exts), name=name,
                    sub=self.app.opt_sub.get(), limit=max(1000, int(self.app.opt_limit.get())))

    def load(self, c):
        rows, stack, seen = [], list(c["folders"]), set()
        exts, name = c["exts"], c["name"]
        for s in stack:
            seen.add(os.path.normcase(os.path.normpath(s)))
        trunc = False
        while stack and not trunc:
            if self.stop_event.is_set():
                break
            d = stack.pop()
            try:
                it = os.scandir(d)
            except OSError:
                continue
            with it:
                for e in it:
                    try:
                        if e.is_dir(follow_symlinks=False):
                            k = os.path.normcase(e.path)
                            if c["sub"] and not is_junction(e) and k not in seen:
                                seen.add(k)
                                stack.append(e.path)
                            continue
                        if not e.is_file(follow_symlinks=False):
                            continue
                        low = e.name.lower()
                        if exts and not low.endswith(exts):
                            continue
                        if name and name not in low:
                            continue
                        st = e.stat(follow_symlinks=False)
                        rows.append((e.name, e.path, fmt_ts(st.st_mtime), fmt_ts(st.st_ctime), fmt_size(st.st_size)))
                        if len(rows) % 500 == 0:
                            self.app.post(self.set_status, f"Varrendo… {fmt_n(len(rows))} encontrados")
                        if len(rows) >= c["limit"]:
                            trunc = True
                            break
                    except (OSError, ValueError, OverflowError):
                        continue
        msg = ""
        if trunc:
            msg = f"Limite de {fmt_n(c['limit'])} resultados atingido (ajuste em Configurações)."
        elif self.stop_event.is_set():
            msg = "Auditoria interrompida — resultados parciais."
        return rows, msg

    def log_row(self, r):
        return (r[0], r[1], r[2], "Auditoria", "Pasta selecionada", "Arquivo encontrado")


class RecentesPage(DataPage):
    key, title, tipo_log = "recentes", "Arquivos recentes", "Arquivo recente"
    columns = [("Nome", 240), ("Caminho do alvo", 460), ("Aberto em", 140), ("Alvo modificado", 140), ("Estado", 120)]
    path_col = 1
    note = "Fonte: atalhos (.lnk) da pasta Recent do usuário. 'Aberto em' = data do atalho."

    def load(self, ctx):
        return load_recentes()

    def log_row(self, r):
        return (r[0], r[1], r[2], "Arquivo recente", "Recent (.lnk)", r[4])


class ApagadosPage(DataPage):
    key, title, tipo_log = "apagados", "Arquivos apagados", "Apagado"
    columns = [("Nome original", 220), ("Caminho original", 400), ("Data de exclusão", 140), ("Tamanho (bytes)", 110),
               ("Estado", 170), ("Metadados / origem", 360)]
    path_col = 1
    modes = ["Todos", "Lixeira", "Indícios (ShimCache)"]

    def load(self, ctx):
        return load_apagados(ctx)

    def log_row(self, r):
        return (r[0], r[1], r[2], "Apagado", r[5].split(" · ")[0], r[4])


class DownloadsPage(DataPage):
    key, title, tipo_log = "downloads", "Downloads", "Download"
    columns = [("Navegador", 110), ("Arquivo", 230), ("Caminho", 340), ("Tamanho (bytes)", 110), ("Baixado em", 140),
               ("Origem (URL)", 380), ("Estado", 120)]
    path_col = 2
    note = "Fonte: bancos de histórico do Chrome, Edge e Opera GX (lidos a partir de uma cópia temporária)."

    def load(self, ctx):
        return load_downloads()

    def log_row(self, r):
        return (r[1], r[2], r[4], "Download", r[0], r[6])


class HistoricoPage(DataPage):
    key, title, tipo_log = "historico", "Histórico de navegação", "Navegação"
    columns = [("Navegador", 110), ("Título / pesquisa", 300), ("URL", 480), ("Visitas", 70), ("Data", 140)]
    modes = ["Navegação", "Pesquisas"]
    note = "Fonte: bancos de histórico do Chrome, Edge e Opera GX (lidos a partir de uma cópia temporária)."

    def load(self, ctx):
        return load_historico(ctx)

    def log_row(self, r):
        tipo = "Pesquisa" if str(r[1]).startswith("Pesquisa:") else "Navegação"
        return (r[1], r[2], r[4], tipo, r[0], "Registro encontrado")


class JumpListsPage(DataPage):
    key, title, tipo_log = "jumplists", "Jump Lists", "Jump List"
    columns = [("Aplicativo (AppID)", 170), ("Arquivo/Pasta", 230), ("Caminho", 430), ("Visto em", 140), ("Tipo", 110),
               ("Estado", 120)]
    path_col = 2

    def load(self, ctx):
        return load_jumplists()

    def log_row(self, r):
        return (r[1], r[2], r[3], "Jump List", r[0], r[5])


class ShellBagsPage(DataPage):
    key, title, tipo_log = "shellbags", "ShellBags", "ShellBag"
    columns = [("Caminho navegado", 560), ("Tipo", 90), ("Última gravação da chave", 170), ("Origem", 120)]

    def load(self, ctx):
        return load_shellbags()

    def log_row(self, r):
        return (nome_de(r[0]), r[0], r[2], "ShellBag", r[3], "Registro encontrado")


class ShimCachePage(DataPage):
    key, title, tipo_log = "shimcache", "ShimCache (AppCompatCache)", "ShimCache"
    columns = [("#", 50), ("Nome", 230), ("Caminho", 520), ("Estado", 130), ("Última modificação", 150)]
    path_col = 2

    def load(self, ctx):
        return load_shimcache()

    def log_row(self, r):
        return (r[1], r[2], r[4], "ShimCache", "AppCompatCache", r[3])


class LogsPage(DataPage):
    key, title, tipo_log = "logs", "Logs", "Log"
    columns = [("Nome", 230), ("Caminho", 430), ("Data", 140), ("Tipo", 110), ("Origem", 150), ("Resultado da análise", 170)]
    path_col = 1
    modes = ["Todos", "Auditoria", "Arquivo recente", "Apagado", "Download", "Navegação", "Pesquisa", "Jump List",
             "ShellBag", "ShimCache", "Triagem de segurança"]
    note = "Consolida tudo o que foi lido nesta sessão. Os logs ficam apenas em memória até você exportar."

    def prepare(self, mode):
        return mode

    def load(self, mode):
        out = []
        for lst in self.app.logs.values():
            out += lst
        if mode and mode != "Todos":
            out = [r for r in out if r[3] == mode]
        return out, ""

    def on_show(self):
        self.refresh()

    def _done(self, rows, msg, err):
        self.busy = False
        self.loaded = True
        self.rows = rows
        self.hay = [" ".join(map(str, r)).lower() for r in rows]
        self.apply_filter()
        if err:
            self.set_status(err, ERR)

    def log_row(self, r):
        return r


class SuspeitosPage(DataPage):
    key, title, tipo_log = "suspeitos", "Arquivos suspeitos", "Triagem de segurança"
    columns = [("Nome", 190), ("Localização completa", 390), ("Tamanho", 90), ("Extensão", 75),
               ("Motivo da identificação", 300), ("Risco", 90), ("Status", 155), ("SHA-256", 260)]
    path_col = 1
    auto = False
    note = ("Triagem heurística e somente leitura. Nome, tamanho ou extensão isolados não confirmam malware. "
            "O histórico local do Microsoft Defender é consultado quando disponível; não há envio para a internet.")

    def build_extra(self, f):
        row = tk.Frame(f, bg=BG)
        row.pack(fill="x", pady=(0, 8))
        caption(row, "PASTAS PARA ANALISAR", width=18, anchor="w").pack(side="left", anchor="n")
        self.lb = tk.Listbox(row, height=3, bg=PANEL, fg=FG, selectbackground=RED_BG, selectforeground=FG,
                             relief="flat", highlightthickness=1, highlightbackground=BORDER,
                             activestyle="none", font=(FONT, 9), selectmode="extended")
        self.lb.pack(side="left", fill="x", expand=True)
        col = tk.Frame(row, bg=BG)
        col.pack(side="left", padx=(8, 0))
        for label, cmd in (("Adicionar pasta", self.add_folder), ("Todas as unidades", self.add_drives),
                           ("Remover", self.rem_folder)):
            Btn(col, label, cmd).pack(fill="x", pady=1)
        for folder in default_suspect_folders():
            self.lb.insert("end", folder)
        row2 = tk.Frame(f, bg=BG)
        row2.pack(fill="x", pady=(0, 9))
        tk.Label(row2, text="Analisa nomes relacionados a ferramentas de terceiros, JSON, scripts e arquivos na faixa de 6–8 MB. A varredura pode levar alguns minutos.",
                 bg=BG, fg=MUTED, font=F_SMALL, anchor="w").pack(side="left", fill="x", expand=True)
        Btn(row2, "Iniciar análise", self.refresh, primary=True).pack(side="right")

    def add_folder(self):
        folder = filedialog.askdirectory(title="Selecionar pasta para análise")
        if folder and folder not in self.lb.get(0, "end"):
            self.lb.insert("end", os.path.normpath(folder))

    def add_drives(self):
        for drive in fixed_drives():
            if drive not in self.lb.get(0, "end"):
                self.lb.insert("end", drive)

    def rem_folder(self):
        for i in reversed(self.lb.curselection()):
            self.lb.delete(i)

    def prepare(self, mode):
        folders = list(self.lb.get(0, "end"))
        if not folders:
            raise ValueError("Adicione ao menos uma pasta para analisar.")
        return folders

    def load(self, folders):
        detections = defender_detections()
        rows, stack, seen = [], list(folders), set()
        for folder in stack:
            seen.add(os.path.normcase(os.path.abspath(folder)))
        scanned = 0
        while stack and not self.stop_event.is_set():
            folder = stack.pop()
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        if self.stop_event.is_set():
                            break
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if not is_junction(entry):
                                    key = os.path.normcase(os.path.abspath(entry.path))
                                    if key not in seen:
                                        seen.add(key); stack.append(entry.path)
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            scanned += 1
                            if scanned % 1000 == 0:
                                self.app.post(self.set_status, f"Analisando… {fmt_n(scanned)} arquivos verificados")
                            st = entry.stat(follow_symlinks=False)
                            name = entry.name.lower()
                            ext = os.path.splitext(name)[1].lower()
                            full = os.path.normcase(os.path.normpath(os.path.abspath(entry.path)))
                            is_json = ext == ".json"
                            name_hits = [term for term in SUSPECT_NAME_TERMS
                                         if (term == "real" and (name.startswith("real") or re.search(r"(^|[^a-z0-9])real([^a-z0-9]|$)", name)))
                                         or (term != "real" and term in name)]
                            size_hit = SIZE_CYLEX_MIN <= st.st_size <= SIZE_CYLEX_MAX
                            # Não sinaliza os executáveis oficiais mais comuns do cliente/Studio Roblox.
                            official_roblox = name in {"robloxplayerbeta.exe", "robloxplayerlauncher.exe",
                                                       "robloxplayerinstaller.exe", "robloxstudiobeta.exe",
                                                       "robloxstudioinstaller.exe"}
                            if official_roblox:
                                name_hits = [x for x in name_hits if x != "roblox"]
                            script_hit = ext in SCRIPT_EXTS
                            if not (is_json or name_hits or size_hit or script_hit):
                                continue
                            indicators = []
                            if script_hit:
                                indicators.append("formato executável/script; extensão sozinha não indica ameaça")
                            if name_hits:
                                indicators.append("nome contém: " + ", ".join(name_hits))
                            if size_hit:
                                indicators.append("tamanho entre 6 e 8 MB (faixa solicitada para triagem Cylex)")
                            json_indicators = inspect_json(entry.path) if is_json else []
                            if json_indicators:
                                indicators.extend(json_indicators)
                            # JSON simples e sem sinais não deve virar alerta apenas pela extensão.
                            defender = detections.get(full)
                            if defender:
                                risk, status = "Crítico", "Detecção registrada pelo Defender (histórico)"
                                indicators.append("histórico local do Microsoft Defender: " + defender)
                            else:
                                content_signals = [x for x in json_indicators if x != "JSON inválido ou truncado"]
                                score = len(name_hits) + (1 if size_hit else 0) + len(content_signals)
                                if score >= 3:
                                    risk, status = "Alto", "Suspeito — requer validação"
                                elif score >= 2:
                                    risk, status = "Médio", "Suspeito — requer validação"
                                elif score == 1:
                                    risk, status = "Baixo", "Indício isolado — não confirmado"
                                else:
                                    risk, status = "Informativo", "Sem evidências suficientes"
                            digest = sha256_file(entry.path)
                            rows.append((entry.name, entry.path, fmt_size(st.st_size) + " bytes", ext or "(sem extensão)",
                                         "; ".join(dict.fromkeys(indicators)), risk, status, digest))
                        except (OSError, ValueError, OverflowError):
                            continue
            except OSError:
                continue
        msg = f"{fmt_n(scanned)} arquivos verificados · {fmt_n(len(rows))} itens para revisão"
        if not detections:
            msg += " · histórico do Defender indisponível ou sem detecções acessíveis"
        if self.stop_event.is_set():
            msg += " · análise interrompida; resultados parciais"
        return rows, msg

    def row_tags(self, i, row):
        tags = list(super().row_tags(i, row))
        if row[5] in ("Alto", "Crítico"):
            tags.append("warn")
        return tuple(tags)

    def log_row(self, row):
        return (row[0], row[1], "—", self.tipo_log, row[5], row[6] + " · " + row[4])


class SummaryPage(tk.Frame):
    key = "resumo"

    def __init__(self, app, parent):
        super().__init__(parent, bg=BG)
        self.app = app
        self.cv = tk.Canvas(self, bg=BG, highlightthickness=0)
        self.cv.pack(fill="both", expand=True)
        self.pts = [[random.random(), random.random(), (random.random() - .5) * .00040,
                     (random.random() - .5) * .00055, random.random() < .22] for _ in range(58)]
        cv = self.cv
        S = app.S
        tk.Label(cv, text="Resumo", bg=BG, fg=FG, font=F_TITLE).place(x=28, y=22)
        Btn(cv, "Varredura completa", app.sweep, primary=True).place(relx=1.0, x=-28, y=22, anchor="ne")
        tk.Label(cv, text=APP_NAME, bg=BG, fg=FG, font=(FONT, 28, "bold")).place(x=26, y=int(62 * S))
        tk.Label(cv, text="auditoria forense de artefatos do Windows  ·  somente leitura", bg=BG, fg=RED,
                 font=(FONT, 9, "bold")).place(x=30, y=int(116 * S))
        self.cards = {}
        titulos = [("arq", "ARQUIVOS ENCONTRADOS"), ("reg", "REGISTROS ANALISADOS"),
                   ("ult", "ÚLTIMA AUDITORIA"), ("acc", "NÍVEL DE ACESSO")]
        for i, (k, t) in enumerate(titulos):
            f = tk.Frame(cv, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
            f.place(relx=0.03 + i * 0.24, y=int(158 * S), relwidth=0.22, height=int(104 * S))
            tk.Frame(f, bg=RED if i == 0 else BORDER, width=2).pack(side="left", fill="y")
            inner = tk.Frame(f, bg=PANEL)
            inner.pack(fill="both", expand=True, padx=14, pady=10)
            tk.Label(inner, text=t, bg=PANEL, fg=MUTED, font=F_CAP).pack(anchor="w")
            v = tk.Label(inner, text="—", bg=PANEL, fg=FG, font=F_BIG)
            v.pack(anchor="w", pady=(4, 0))
            s = tk.Label(inner, text="", bg=PANEL, fg=DIM, font=F_SMALL)
            s.pack(anchor="w")
            self.cards[k] = (v, s)
        tk.Label(cv, text="ATALHOS", bg=BG, fg=MUTED, font=F_CAP).place(x=28, y=int(292 * S))
        tiles = [("auditoria", "Auditoria de arquivos", "Buscar .exe, .dll e outras extensões"),
                 ("recentes", "Arquivos recentes", "Atalhos de arquivos abertos"),
                 ("apagados", "Arquivos apagados", "Lixeira e indícios de exclusão"),
                 ("downloads", "Downloads", "Chrome, Edge e Opera GX"),
                 ("historico", "Histórico de navegação", "Páginas visitadas e pesquisas"),
                 ("shimcache", "ShimCache", "AppCompatCache (requer administrador)"),
                 ("suspeitos", "Arquivos suspeitos", "Triagem de possíveis ameaças")]
        for i, (k, t, d) in enumerate(tiles):
            f = tk.Frame(cv, bg=PANEL, highlightthickness=1, highlightbackground=BORDER, cursor="hand2")
            f.place(relx=0.03 + (i % 3) * 0.32, y=int((320 + (i // 3) * 82) * S), relwidth=0.30, height=int(68 * S))
            tk.Label(f, text=t, bg=PANEL, fg=AMBER if k == "suspeitos" else FG,
                     font=(FONT, 10, "bold")).pack(anchor="w", padx=14, pady=(12, 0))
            tk.Label(f, text=d, bg=PANEL, fg=MUTED, font=F_SMALL).pack(anchor="w", padx=14)
            clickable(f, lambda k=k: app.show(k),
                      enter=lambda f=f: f.config(highlightbackground=RED),
                      leave=lambda f=f: f.config(highlightbackground=BORDER))
        self.update_cards(None)
        self.after(60, self.tick)

    def update_cards(self, st):
        a, r, u, c = self.cards["arq"], self.cards["reg"], self.cards["ult"], self.cards["acc"]
        if not st:
            a[0].config(text="—"); a[1].config(text="rode a Varredura completa primeiro")
            r[0].config(text="—"); r[1].config(text="")
            u[0].config(text="—", font=(MONO, 13, "bold")); u[1].config(text="")
        else:
            a[0].config(text=fmt_n(st["arquivos"])); a[1].config(text="na Auditoria de arquivos")
            r[0].config(text=fmt_n(st["registros"])); r[1].config(text="em todas as fontes lidas")
            u[0].config(text=fmt_dt(st["ultima"]), font=(MONO, 13, "bold")); u[1].config(text="")
        adm = is_admin()
        c[0].config(text="ADMIN" if adm else "USUÁRIO", fg=GREEN if adm else AMBER)
        c[1].config(text="acesso completo" if adm else "ShimCache exige administrador")

    def tick(self):
        if self.app.current == self.key:
            cv = self.cv
            w, h = max(cv.winfo_width(), 2), max(cv.winfo_height(), 2)
            cv.delete("fx")
            for p in self.pts:
                p[0] = (p[0] + p[2]) % 1.0
                p[1] = (p[1] + p[3]) % 1.0
            xy = [(p[0] * w, p[1] * h) for p in self.pts]
            n, D = len(xy), 150.0
            for i in range(n):
                for j in range(i + 1, n):
                    d = math.hypot(xy[i][0] - xy[j][0], xy[i][1] - xy[j][1])
                    if d < D:
                        red = self.pts[i][4] or self.pts[j][4]
                        col = blend(BG, "#8a1d23" if red else "#4a4a50", 1 - d / D)
                        cv.create_line(xy[i][0], xy[i][1], xy[j][0], xy[j][1], fill=col, tags="fx")
            for (x, y), p in zip(xy, self.pts):
                r = 2.2 if p[4] else 1.6
                cv.create_oval(x - r, y - r, x + r, y + r, fill=RED if p[4] else "#9a9aa2", outline="", tags="fx")
            cv.tag_lower("fx")
        self.after(50, self.tick)

    def on_show(self):
        self.app.refresh_summary()


class SettingsPage(tk.Frame):
    key = "config"

    def __init__(self, app, parent):
        super().__init__(parent, bg=BG)
        self.app = app
        tk.Label(self, text="Configurações", bg=BG, fg=FG, font=F_TITLE).pack(anchor="w", padx=28, pady=(22, 0))
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", padx=28, pady=(12, 14))

        def secao(txt):
            caption(self, txt).pack(anchor="w", padx=28, pady=(10, 6))

        secao("NÍVEL DE ACESSO")
        row = tk.Frame(self, bg=BG)
        row.pack(anchor="w", padx=28)
        adm = is_admin()
        tk.Label(row, text="Executando como administrador" if adm else "Executando como usuário comum",
                 bg=BG, fg=GREEN if adm else AMBER, font=(FONT, 10, "bold")).pack(side="left")
        if not adm and IS_WIN:
            Btn(row, "Reabrir como administrador", self.relaunch).pack(side="left", padx=14)
        tk.Label(self, text="Alguns artefatos (ShimCache, Lixeira de outros usuários) só são legíveis como administrador.",
                 bg=BG, fg=DIM, font=F_SMALL).pack(anchor="w", padx=28, pady=(4, 0))

        secao("AUDITORIA DE ARQUIVOS")
        tk.Checkbutton(self, text="Incluir subpastas", variable=app.opt_sub, bg=BG, fg=FG, selectcolor=PANEL2,
                       activebackground=BG, activeforeground=FG, font=(FONT, 10), highlightthickness=0).pack(anchor="w", padx=24)
        row = tk.Frame(self, bg=BG)
        row.pack(anchor="w", padx=28, pady=(6, 0))
        tk.Label(row, text="Limite de resultados:", bg=BG, fg=FG, font=(FONT, 10)).pack(side="left")
        tk.Spinbox(row, from_=1000, to=2000000, increment=10000, textvariable=app.opt_limit, width=9, bg=PANEL2,
                   fg=FG, buttonbackground=PANEL2, relief="flat", insertbackground=FG, highlightthickness=1,
                   highlightbackground=BORDER, font=(FONT, 10)).pack(side="left", padx=10)

        secao("EXPORTAÇÃO")
        Btn(self, "Exportar todos os logs (CSV)", self.export_logs).pack(anchor="w", padx=28)

        secao("GARANTIAS DE SEGURANÇA")
        for t in ("Somente leitura: não apaga, não modifica e não executa arquivos encontrados.",
                  "Nenhuma informação é enviada para servidores externos (o programa não usa rede).",
                  "Não classifica arquivos como vírus ou cheats pela extensão ou pelo nome.",
                  "Respeita as permissões do Windows; o que não puder ser lido é ignorado.",
                  "Bancos de navegadores são lidos em cópia temporária, removida logo após a leitura."):
            tk.Label(self, text="■  " + t, bg=BG, fg=MUTED, font=(FONT, 9)).pack(anchor="w", padx=28, pady=1)
        tk.Label(self, text=APP_NAME, bg=BG, fg=DIM, font=F_SMALL).pack(anchor="w", padx=28, pady=(18, 0))

    def relaunch(self):
        try:
            if getattr(sys, "frozen", False):
                exe, params = sys.executable, ""
            else:
                exe, params = sys.executable, f'"{os.path.abspath(__file__)}"'
            r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
            if r > 32:
                self.app.destroy()
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Não foi possível reabrir como administrador:\n{e}")

    def export_logs(self):
        todos = [r for lst in self.app.logs.values() for r in lst]
        if not todos:
            messagebox.showinfo(APP_NAME, "Ainda não há logs. Rode a Varredura completa primeiro.")
            return
        fn = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="ulckloadder_logs.csv",
                                          filetypes=[("CSV", "*.csv")])
        if fn:
            with open(fn, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["Nome", "Caminho", "Data", "Tipo", "Origem", "Resultado da análise"])
                w.writerows(todos)

    def on_show(self):
        pass


NAV = [("resumo", "Resumo"), ("auditoria", "Auditoria de arquivos"), ("recentes", "Arquivos recentes"),
       ("apagados", "Arquivos apagados"), ("downloads", "Downloads"), ("historico", "Histórico de navegação"),
       ("jumplists", "Jump Lists"), ("shellbags", "ShellBags"), ("shimcache", "ShimCache (AppCompatCache)"),
       ("logs", "Logs"), ("config", "Configurações")]
SWEEP = ["recentes", "apagados", "downloads", "historico", "jumplists", "shellbags", "shimcache", "auditoria"]


def dark_titlebar(win):
    try:
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
        one = ctypes.c_int(1)
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(one), ctypes.sizeof(one))
        cor = ctypes.c_int(0x0B0A0A)  # COLORREF 0x00BBGGRR
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(cor), ctypes.sizeof(cor))
    except Exception:
        pass


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.S = max(1.0, self.winfo_fpixels("1i") / 96.0)  # escala do Windows (125%, 150%...)
        self.geometry(f"{int(1220 * self.S)}x{int(760 * self.S)}")
        self.minsize(int(1000 * self.S), int(620 * self.S))
        self.configure(bg=BG)
        self.q = queue.Queue()
        self.logs = {}
        self.last_audit = None
        self.current = None
        self.opt_sub = tk.BooleanVar(value=True)
        self.opt_limit = tk.IntVar(value=200000)
        self._estilo()
        self._icone()

        side = tk.Frame(self, bg=SIDEBAR, width=int(250 * self.S))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(self, bg=BORDER, width=1).pack(side="left", fill="y")
        self.body = tk.Frame(self, bg=BG)
        self.body.pack(side="left", fill="both", expand=True)

        brand = tk.Frame(side, bg=SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(22, 0))
        tk.Label(brand, text="■", bg=SIDEBAR, fg=RED, font=(FONT, 10)).pack(side="left", padx=(0, 8))
        tk.Label(brand, text=APP_NAME, bg=SIDEBAR, fg=FG, font=F_BRAND).pack(side="left")
        tk.Label(side, text="AUDITORIA FORENSE  ·  SOMENTE LEITURA", bg=SIDEBAR, fg=DIM, font=(FONT, 7)).pack(
            anchor="w", padx=40, pady=(2, 16))
        sw = tk.Label(side, text="VARREDURA COMPLETA", bg="#1d0a0c", fg=FG, font=F_BTN, pady=10, cursor="hand2",
                      highlightthickness=1, highlightbackground=RED_D)
        sw.pack(fill="x", padx=16, pady=(0, 14))
        sw.bind("<Enter>", lambda e: sw.config(bg=RED_D))
        sw.bind("<Leave>", lambda e: sw.config(bg="#1d0a0c"))
        sw.bind("<ButtonRelease-1>", lambda e: self.sweep())

        self.nav = {}
        for key, label in NAV:
            row = tk.Frame(side, bg=SIDEBAR, cursor="hand2")
            row.pack(fill="x")
            ind = tk.Frame(row, bg=SIDEBAR, width=3)
            ind.pack(side="left", fill="y")
            lb = tk.Label(row, text=label, bg=SIDEBAR, fg=MUTED, font=F_NAV, anchor="w", padx=18, pady=7)
            lb.pack(side="left", fill="x", expand=True)
            for w in (row, lb):
                w.bind("<ButtonRelease-1>", lambda e, k=key: self.show(k))
                w.bind("<Enter>", lambda e, k=key: self._hover(k, True))
                w.bind("<Leave>", lambda e, k=key: self._hover(k, False))
            self.nav[key] = (row, ind, lb)

        badges = tk.Frame(side, bg=SIDEBAR)
        badges.pack(side="bottom", fill="x", padx=14, pady=14)
        adm = is_admin()
        for t, c in (("ADMIN" if adm else "USUÁRIO", GREEN if adm else AMBER), ("SOMENTE LEITURA", MUTED)):
            tk.Label(badges, text=t, bg=SIDEBAR, fg=c, font=(MONO, 7, "bold"), padx=6, pady=2,
                     highlightthickness=1, highlightbackground=BORDER).pack(side="left", padx=(0, 6))

        self.pages = {}
        for cls in (SummaryPage, AuditPage, RecentesPage, ApagadosPage, DownloadsPage, HistoricoPage,
                    JumpListsPage, ShellBagsPage, ShimCachePage, SuspeitosPage, LogsPage, SettingsPage):
            self.pages[cls.key] = cls(self, self.body)
        self.show("resumo")
        dark_titlebar(self)
        self.after(80, self.poll)

    def _estilo(self):
        st = ttk.Style(self)
        st.theme_use("clam")
        st.layout("Treeview", [("Treeview.treearea", {"sticky": "nswe"})])
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=int(26 * self.S),
                     borderwidth=0, font=(FONT, 9))
        st.configure("Treeview.Heading", background=PANEL2, foreground=MUTED, relief="flat", borderwidth=0,
                     font=(FONT, 8, "bold"), padding=(8, 7))
        st.map("Treeview", background=[("selected", RED_BG)], foreground=[("selected", "#ffffff")])
        st.map("Treeview.Heading", background=[("active", PANEL2)], foreground=[("active", FG)])
        for o in ("Vertical", "Horizontal"):
            st.configure(f"{o}.TScrollbar", background="#26262a", troughcolor=PANEL, bordercolor=PANEL,
                         arrowcolor=MUTED, lightcolor="#26262a", darkcolor="#26262a", gripcount=0)
            st.map(f"{o}.TScrollbar", background=[("active", RED_D)])
        st.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2, foreground=FG, arrowcolor=MUTED,
                     bordercolor=BORDER, lightcolor=PANEL2, darkcolor=PANEL2, selectbackground=PANEL2,
                     selectforeground=FG)
        st.map("TCombobox", fieldbackground=[("readonly", PANEL2)], foreground=[("readonly", FG)],
               selectbackground=[("readonly", PANEL2)], selectforeground=[("readonly", FG)])
        self.option_add("*TCombobox*Listbox.background", PANEL2)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", RED_BG)
        self.option_add("*TCombobox*Listbox.selectForeground", FG)

    def _icone(self):
        try:
            base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
            ico = os.path.join(base, "ulckloadder.ico")
            if os.path.isfile(ico):
                self.iconbitmap(ico)
                return
            img = tk.PhotoImage(width=32, height=32)
            img.put(BG, to=(0, 0, 32, 32))
            for y in range(32):
                for x in range(32):
                    if abs(x - 15.5) + abs(y - 15.5) <= 13:
                        img.put(RED if abs(x - 15.5) + abs(y - 15.5) > 5 else BG, (x, y))
            self.iconphoto(True, img)
            self._icon_ref = img
        except Exception:
            pass

    def _hover(self, key, on):
        if key == self.current:
            return
        row, ind, lb = self.nav[key]
        lb.config(fg=FG if on else MUTED, bg="#131315" if on else SIDEBAR)

    def show(self, key):
        self.current = key
        for k, (row, ind, lb) in self.nav.items():
            on = k == key
            lb.config(bg=RED_BG if on else SIDEBAR, fg=FG if on else MUTED)
            ind.config(bg=RED if on else SIDEBAR)
        for p in self.pages.values():
            p.pack_forget()
        pg = self.pages[key]
        pg.pack(fill="both", expand=True)
        pg.on_show()

    def post(self, fn, *args):
        self.q.put((fn, args))

    def poll(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                try:
                    fn(*args)
                except Exception:
                    pass
        except queue.Empty:
            pass
        self.after(80, self.poll)

    def sweep(self):
        for k in SWEEP:
            self.pages[k].refresh()

    def refresh_summary(self):
        data = [p for p in self.pages.values() if isinstance(p, DataPage) and p.key != "logs"]
        if not any(p.loaded for p in data):
            self.pages["resumo"].update_cards(None)
            return
        self.pages["resumo"].update_cards({
            "arquivos": len(self.pages["auditoria"].rows),
            "registros": sum(len(p.rows) for p in data),
            "ultima": self.last_audit,
        })


# ------------------------------------------------------------------ login ---
# Guardamos apenas o hash (nao a senha em texto). Isto e um portao de acesso
# local simples: impede o uso casual, mas nao e seguranca forte.
_SALT = "ulck-v1-9c41"
_HASH = "a0b2eef5c6aa597191e27dee8155a0eddb769bb86da2c3942044441c183470fd"


def autenticar(login, senha):
    calc = hashlib.sha256(f"{_SALT}:{login.strip().lower()}:{senha}".encode("utf-8")).hexdigest()
    return hmac.compare_digest(calc, _HASH)


class LoginWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.ok = False
        self.tentativas = 0
        S = max(1.0, self.winfo_fpixels("1i") / 96.0)
        w, h = int(420 * S), int(470 * S)
        self.title(APP_NAME + " — Acesso")
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth() - w) // 2}+{(self.winfo_screenheight() - h) // 2}")
        self.resizable(False, False)
        self.configure(bg=BG)
        box = tk.Frame(self, bg=BG)
        box.pack(fill="both", expand=True, padx=int(44 * S), pady=int(36 * S))
        tk.Label(box, text="■", bg=BG, fg=RED, font=(FONT, 16)).pack(anchor="w")
        tk.Label(box, text=APP_NAME, bg=BG, fg=FG, font=(FONT, 24, "bold")).pack(anchor="w", pady=(6, 0))
        tk.Label(box, text="AUDITORIA FORENSE  ·  SOMENTE LEITURA", bg=BG, fg=DIM, font=(FONT, 8)).pack(anchor="w")
        tk.Frame(box, bg=BORDER, height=1).pack(fill="x", pady=(18, 18))
        caption(box, "LOGIN").pack(anchor="w", pady=(0, 4))
        self.u = tk.StringVar()
        e1 = make_entry(box, self.u, 30)
        e1.pack(fill="x", ipady=6)
        caption(box, "SENHA").pack(anchor="w", pady=(14, 4))
        self.p = tk.StringVar()
        e2 = make_entry(box, self.p, 30)
        e2.config(show="•")
        e2.pack(fill="x", ipady=6)
        self.err = tk.Label(box, text="", bg=BG, fg=ERR, font=F_SMALL)
        self.err.pack(anchor="w", pady=(10, 0))
        Btn(box, "ENTRAR", self.entrar, primary=True).pack(fill="x", pady=(14, 0), ipady=4)
        for e in (e1, e2):
            e.bind("<Return>", self.entrar)
        self.bind("<Return>", self.entrar)
        e1.focus_set()
        dark_titlebar(self)

    def entrar(self, *_):
        if autenticar(self.u.get(), self.p.get()):
            self.ok = True
            self.destroy()
            return
        self.tentativas += 1
        self.p.set("")
        if self.tentativas >= 5:
            self.err.config(text="Muitas tentativas. Fechando…")
            self.after(1200, self.destroy)
        else:
            self.err.config(text=f"Login ou senha incorretos ({self.tentativas}/5).")


def main():
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    login = LoginWindow()
    login.mainloop()
    if not login.ok:
        return
    App().mainloop()


if __name__ == "__main__":
    main()
