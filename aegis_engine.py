# -*- coding: utf-8 -*-
"""AEGIS 神盾扫描器 · 扫描引擎

纯 Python 标准库实现，零第三方依赖。

引擎由四层组成：
    1. 哈希信誉层    已知恶意文件哈希（内置 + signatures/blacklist.txt）
    2. 特征匹配层    类 YARA 的字节/正则特征规则（aegis_rules.py）
    3. 静态启发层    PE 结构分析、节区熵值、导入表、加壳识别、宏检测、压缩包递归
    4. 文件名层      双扩展名、RLO 伪装、注册机等

所有层的结果汇总成一个加权分值，再折算成最终判定。
"""

from __future__ import annotations

import io
import json
import math
import os
import re
import struct
import threading
import time
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Optional

import aegis_rules as R

ENGINE_NAME = "AEGIS Engine"
ENGINE_VERSION = "1.0.0"

# ---- 各种限制 -------------------------------------------------------------
SIG_SCAN_LIMIT = 8 * 1024 * 1024          # 特征匹配最多扫描文件前 8MB
ENTROPY_SAMPLE_LIMIT = 8 * 1024 * 1024    # 熵值计算的最大取样
DEFAULT_MAX_FILE_SIZE = 64 * 1024 * 1024  # 默认跳过的超大文件阈值
ARCHIVE_MEMBER_LIMIT = 16 * 1024 * 1024   # 压缩包内单个成员的最大解压尺寸

VERDICT_MALICIOUS = "malicious"
VERDICT_SUSPICIOUS = "suspicious"
VERDICT_CLEAN = "clean"
VERDICT_ERROR = "error"

VERDICT_LABEL = {
    VERDICT_MALICIOUS: "恶意",
    VERDICT_SUSPICIOUS: "可疑",
    VERDICT_CLEAN: "安全",
    VERDICT_ERROR: "错误",
}

# 跳过扫描的文件扩展名（纯资源类，扫了没意义还慢）
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".wmv",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".db", ".pak", ".idx", ".bin.dat",
}

SCRIPT_EXTENSIONS = {
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
    ".bat", ".cmd", ".sh", ".bash", ".zsh", ".py", ".pyw", ".pl", ".rb",
    ".hta", ".jar", ".php", ".asp", ".aspx", ".jsp", ".lua", ".ahk", ".inf",
}

# 系统目录：默认不扫，扫描自己的项目目录时用不上
SYSTEM_DIRS = {
    "c:\\windows", "c:\\$recycle.bin", "c:\\recovery",
    "c:\\programdata\\microsoft\\windows defender",
}


# ===========================================================================
#  数据结构
# ===========================================================================
@dataclass
class Finding:
    """一条检出记录。"""
    rule_id: str
    name: str
    family: str
    severity: str          # malicious / suspicious / pua / info
    score: int
    detail: str = ""
    desc: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "family": self.family,
            "severity": self.severity,
            "score": self.score,
            "detail": self.detail,
            "desc": self.desc,
        }


@dataclass
class ScanResult:
    """一个文件的扫描结果。"""
    path: str
    size: int = 0
    sha256: str = ""
    md5: str = ""
    kind: str = "unknown"
    score: int = 0
    verdict: str = VERDICT_CLEAN
    findings: list = field(default_factory=list)
    duration_ms: float = 0.0
    error: str = ""
    iocs: dict = field(default_factory=dict)

    @property
    def threat_name(self) -> str:
        if not self.findings:
            return ""
        top = max(self.findings, key=lambda f: f.score)
        return top.name

    @property
    def verdict_label(self) -> str:
        return VERDICT_LABEL.get(self.verdict, self.verdict)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "kind": self.kind,
            "score": self.score,
            "verdict": self.verdict,
            "threat_name": self.threat_name,
            "duration_ms": round(self.duration_ms, 2),
            "error": self.error,
            "iocs": self.iocs,
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanOptions:
    """扫描配置。"""
    heuristics: bool = True
    scan_archives: bool = True
    scan_office: bool = True
    detect_pua: bool = True
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    threads: int = 8
    archive_depth: int = 2
    archive_max_members: int = 200
    skip_large_by_extension: bool = True


# ===========================================================================
#  工具函数
# ===========================================================================
def entropy(data: bytes) -> float:
    """计算香农熵（0~8）。越高越像加密/压缩数据。"""
    if not data:
        return 0.0
    sample = data[:ENTROPY_SAMPLE_LIMIT]
    n = len(sample)
    counts = Counter(sample)
    e = 0.0
    for c in counts.values():
        p = c / n
        e -= p * math.log2(p)
    return e


def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} TB"


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


def _u64(b: bytes, o: int) -> int:
    return struct.unpack_from("<Q", b, o)[0]


def _cstr(b: bytes, o: int, limit: int = 256) -> str:
    if o is None or o < 0 or o >= len(b):
        return ""
    end = b.find(b"\x00", o, min(o + limit, len(b)))
    if end < 0:
        end = min(o + limit, len(b))
    try:
        return b[o:end].decode("ascii", "ignore")
    except Exception:
        return ""


def extract_iocs(data: bytes, limit: int = 40) -> dict:
    """从文件内容里提取 IOC：URL / IP / 域名 / 邮箱。"""
    head = data[:SIG_SCAN_LIMIT]
    out = {"urls": [], "ips": [], "emails": [], "domains": []}
    try:
        urls = re.findall(rb"https?://[^\s\"'<>\)\]\x00]{4,200}", head)
        for u in urls:
            s = u.decode("ascii", "ignore")
            if s not in out["urls"]:
                out["urls"].append(s)
            if len(out["urls"]) >= limit:
                break
        ips = re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", head)
        for i in ips:
            s = i.decode("ascii", "ignore")
            if s not in out["ips"] and s not in ("0.0.0.0", "127.0.0.1"):
                out["ips"].append(s)
            if len(out["ips"]) >= limit:
                break
        mails = re.findall(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,10}", head)
        for m in mails:
            s = m.decode("ascii", "ignore")
            if s not in out["emails"]:
                out["emails"].append(s)
            if len(out["emails"]) >= limit:
                break
    except Exception:
        pass
    return {k: v for k, v in out.items() if v}


# ===========================================================================
#  文件类型识别
# ===========================================================================
def classify(data: bytes, filename: str = "") -> str:
    """判断文件类型，返回 kind 字符串。"""
    if len(data) >= 2 and data[:2] == b"MZ":
        # 必须能定位到 PE 签名才算真正的 PE
        if len(data) >= 0x40:
            try:
                e_lfanew = _u32(data, 0x3C)
                if 0 < e_lfanew < len(data) - 4 and data[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
                    return "pe"
            except Exception:
                pass
        return "mz"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if data[:4] == b"%PDF":
        return "pdf"
    if data[:4] == b"PK\x03\x04" or data[:4] == b"PK\x05\x06":
        # 区分普通 zip 和 Office OOXML
        if b"[Content_Types].xml" in data[:8192] or b"PK\x03\x04" in data[:4]:
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    names = z.namelist()
                    if "[Content_Types].xml" in names:
                        for n in names:
                            if n.startswith(("word/", "xl/", "ppt/")):
                                return "ooxml"
                        return "ooxml"
                    return "zip"
            except Exception:
                return "zip"
        return "zip"
    if data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00":
        return "rar"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if data[:2] == b"\x1f\x8b":
        return "gzip"
    if data[:4] == b"MSCF":
        return "cab"
    if data[:2] == b"BM":
        return "image"

    ext = os.path.splitext(filename)[1].lower()
    if ext in SCRIPT_EXTENSIONS:
        return "script"

    # 文本判定：先试着按 UTF-8 解码（中文脚本/说明很常见），失败再退回可打印字符占比
    head = data[:8192]
    if head and b"\x00" not in head:
        try:
            head.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            pass
        printable = sum(1 for c in head if 32 <= c < 127 or c in (9, 10, 13))
        if printable / len(head) > 0.90:
            return "text"
    return "binary"


def kinds_for(kind: str) -> set:
    """把文件类别映射成规则 targets 用的类别集合。"""
    return {
        "pe": {"pe", "binary", "text", "script"},
        "mz": {"binary", "text"},
        "elf": {"binary", "text"},
        "ole": {"office", "binary", "text", "script"},
        "ooxml": {"office", "binary", "text", "script"},
        "pdf": {"pdf", "binary", "text"},
        "zip": {"archive", "binary", "text"},
        "rar": {"archive", "binary"},
        "7z": {"archive", "binary"},
        "gzip": {"archive", "binary"},
        "cab": {"archive", "binary"},
        "script": {"script", "text"},
        "text": {"text", "script"},
        "binary": {"binary", "text"},
        "image": {"image", "binary"},
    }.get(kind, {"binary", "text"})


# ===========================================================================
#  规则匹配
# ===========================================================================
def _compile_patterns(patterns) -> tuple:
    out = []
    for kind, value, desc in patterns:
        if kind == "regex":
            out.append(("regex", re.compile(value), desc))
        elif kind == "hex":
            out.append(("ascii", bytes.fromhex(value.replace(" ", "")), desc))
        else:
            out.append(("ascii", value, desc))
    return tuple(out)


COMPILED_RULES = []
for _r in R.RULES:
    _c = dict(_r)
    _c["_compiled"] = _compile_patterns(_r["patterns"])
    COMPILED_RULES.append(_c)


def match_rules(data: bytes, kinds: set, detect_pua: bool = True) -> list:
    """对文件内容跑一遍特征规则。"""
    findings = []
    head = data[:SIG_SCAN_LIMIT] if len(data) > SIG_SCAN_LIMIT else data

    for rule in COMPILED_RULES:
        targets = rule["targets"]
        if "any" not in targets and not (set(targets) & kinds):
            continue
        if not detect_pua and rule["severity"] == "pua":
            continue

        patterns = rule["_compiled"]
        cond = rule["condition"]
        need = len(patterns) if cond == "all" else int(cond)

        hits = []
        for pkind, pat, desc in patterns:
            found = False
            if pkind == "regex":
                found = pat.search(head) is not None
            else:
                found = head.find(pat) >= 0
            if found:
                hits.append(desc)
                if cond != "all" and len(hits) >= need:
                    break
        if len(hits) < need:
            continue

        findings.append(Finding(
            rule_id=rule["id"],
            name=rule["name"],
            family=rule["family"],
            severity=rule["severity"],
            score=int(rule["score"]),
            detail="；".join(hits[:6]),
            desc=rule.get("desc", ""),
        ))
    return findings


def match_filename(filename: str, detect_pua: bool = True) -> list:
    """对文件名跑一遍规则。"""
    findings = []
    base = os.path.basename(filename)
    for rule in R.FILENAME_RULES:
        if not detect_pua and rule["severity"] == "pua":
            continue
        try:
            if re.search(rule["regex"], base):
                findings.append(Finding(
                    rule_id=rule["id"],
                    name=rule["name"],
                    family=rule["family"],
                    severity=rule["severity"],
                    score=int(rule["score"]),
                    detail=f"文件名: {base}",
                    desc=rule.get("desc", ""),
                ))
        except Exception:
            continue
    return findings


# ===========================================================================
#  可选：YARA 支持
# ===========================================================================
# 装了 yara-python 就自动启用 rules/ 目录下的 .yar 规则；没装则完全跳过，
# 不影响任何其它功能。AEGIS 自带的规则引擎和 YARA 是并行工作的两套匹配层。
try:
    import yara as _yara_module
except Exception:
    _yara_module = None

YARA_AVAILABLE = _yara_module is not None
_yara_state = {"rules": None, "count": 0, "error": "", "loaded": False}


def load_yara_rules(rules_dir: str = "") -> dict:
    """把 rules/ 目录下的 .yar / .yara 编译成规则集。"""
    if _yara_state["loaded"]:
        return _yara_state
    _yara_state["loaded"] = True
    if not YARA_AVAILABLE:
        return _yara_state

    base = rules_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    if not os.path.isdir(base):
        return _yara_state

    sources = {}
    for root, _dirs, files in os.walk(base):
        for n in files:
            if n.lower().endswith((".yar", ".yara")):
                try:
                    with open(os.path.join(root, n), "r", encoding="utf-8",
                              errors="ignore") as fh:
                        sources[n] = fh.read()
                except Exception:
                    pass
    if not sources:
        return _yara_state

    try:
        _yara_state["rules"] = _yara_module.compile(sources=sources)
        _yara_state["count"] = len(sources)
    except Exception as exc:
        _yara_state["error"] = f"{type(exc).__name__}: {exc}"
    return _yara_state


def match_yara(data: bytes) -> list:
    """用已加载的 YARA 规则匹配文件内容。"""
    rules = _yara_state["rules"]
    if rules is None:
        return []
    out = []
    try:
        for m in rules.match(data=data, timeout=10):
            meta = dict(m.meta or {})
            sev = str(meta.get("severity", "suspicious")).lower()
            if sev not in ("malicious", "suspicious", "pua", "info"):
                sev = "suspicious"
            try:
                score = int(meta.get("score", 45))
            except Exception:
                score = 45
            ids = list((m.strings or {}).keys())
            out.append(Finding(
                rule_id=f"YARA.{m.rule}",
                name=str(meta.get("name", m.rule)),
                family=str(meta.get("family", "YARA.Rule")),
                severity=sev,
                score=score,
                detail=("命中字符串标识：" + "，".join(ids[:6])) if ids else "规则条件满足",
                desc=str(meta.get("description", "来自 rules/ 目录的自定义 YARA 规则。")),
            ))
    except Exception:
        pass
    return out


# ===========================================================================
#  PE 静态分析
# ===========================================================================
def parse_pe(data: bytes) -> Optional[dict]:
    """手工解析 PE 结构。解析失败返回 None。"""
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return None
        e_lfanew = _u32(data, 0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(data):
            return None
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return None

        coff = e_lfanew + 4
        machine = _u16(data, coff)
        n_sections = _u16(data, coff + 2)
        timestamp = _u32(data, coff + 4)
        size_opt = _u16(data, coff + 16)
        characteristics = _u16(data, coff + 18)

        if n_sections > 96:      # 正常 PE 不会有这么多节区
            return None

        opt = coff + 20
        if opt + size_opt > len(data) or size_opt < 2:
            return None
        magic = _u16(data, opt)
        is64 = magic == 0x20B
        if magic not in (0x10B, 0x20B):
            return None

        entry = _u32(data, opt + 16)
        subsystem = _u16(data, opt + 68)
        dllchar = _u16(data, opt + 70)
        n_rva = _u32(data, opt + (108 if is64 else 92))
        dd_off = opt + (112 if is64 else 96)

        dirs = []
        for i in range(min(n_rva, 16)):
            o = dd_off + i * 8
            if o + 8 > len(data):
                break
            dirs.append((_u32(data, o), _u32(data, o + 4)))

        sec_off = opt + size_opt
        sections = []
        for i in range(n_sections):
            o = sec_off + i * 40
            if o + 40 > len(data):
                break
            name = data[o:o + 8].rstrip(b"\x00").decode("latin-1", "ignore")
            vsize = _u32(data, o + 8)
            vaddr = _u32(data, o + 12)
            rsize = _u32(data, o + 16)
            raddr = _u32(data, o + 20)
            chars = _u32(data, o + 36)
            raw = b""
            if raddr and rsize and raddr + rsize <= len(data):
                raw = data[raddr:raddr + rsize]
            elif raddr and raddr < len(data):
                raw = data[raddr:]
            sections.append({
                "name": name,
                "vsize": vsize,
                "vaddr": vaddr,
                "rsize": rsize,
                "raddr": raddr,
                "chars": chars,
                "entropy": entropy(raw) if raw else 0.0,
                "raw_len": len(raw),
            })

        def rva_to_off(rva: int) -> Optional[int]:
            for s in sections:
                span = max(s["vsize"], s["rsize"])
                if s["vaddr"] <= rva < s["vaddr"] + span:
                    delta = rva - s["vaddr"]
                    if delta < s["rsize"]:
                        off = s["raddr"] + delta
                        if 0 <= off < len(data):
                            return off
            return None

        # ---- 导入表 ----
        imports = {}
        if len(dirs) > 1 and dirs[1][0]:
            io_ = rva_to_off(dirs[1][0])
            if io_ is not None:
                for i in range(300):
                    d = io_ + i * 20
                    if d + 20 > len(data):
                        break
                    oft = _u32(data, d)
                    name_rva = _u32(data, d + 12)
                    ft = _u32(data, d + 16)
                    if oft == 0 and name_rva == 0 and ft == 0:
                        break
                    dll = _cstr(data, rva_to_off(name_rva)) if name_rva else ""
                    thunk_rva = oft or ft
                    t_off = rva_to_off(thunk_rva)
                    fns = []
                    if t_off is not None:
                        step = 8 if is64 else 4
                        for j in range(4000):
                            p = t_off + j * step
                            if p + step > len(data):
                                break
                            val = _u64(data, p) if is64 else _u32(data, p)
                            if val == 0:
                                break
                            high = 1 << 63 if is64 else 1 << 31
                            if not (val & high):
                                n_off = rva_to_off(val)
                                if n_off is not None:
                                    fn = _cstr(data, n_off + 2)
                                    if fn:
                                        fns.append(fn)
                    if dll or fns:
                        imports[dll or "?"] = fns
                if len(imports) > 100:
                    imports = dict(list(imports.items())[:100])

        # ---- 覆盖数据（Overlay）----
        end_of_image = 0
        for s in sections:
            if s["raddr"] and s["rsize"]:
                end_of_image = max(end_of_image, s["raddr"] + s["rsize"])
        overlay = max(0, len(data) - end_of_image) if end_of_image else 0

        # ---- 数字签名 ----
        signed = bool(len(dirs) > 4 and dirs[4][0] and dirs[4][1])

        all_funcs = set()
        for fns in imports.values():
            all_funcs.update(fns)

        return {
            "machine": machine,
            "is64": is64,
            "sections": sections,
            "entry": entry,
            "subsystem": subsystem,
            "dllchar": dllchar,
            "timestamp": timestamp,
            "characteristics": characteristics,
            "imports": imports,
            "functions": all_funcs,
            "overlay": overlay,
            "signed": signed,
            "size_of_image_dirs": dirs,
        }
    except Exception:
        return None


def analyze_pe(data: bytes, pe: dict) -> list:
    """基于 PE 结构做启发式判定。"""
    findings = []
    sections = pe["sections"]
    funcs = pe["functions"]

    # ---- 节区熵值 / 加壳识别 ----
    packers = set()
    high_entropy_sections = []
    for s in sections:
        name = s["name"]
        if name in R.PACKER_SECTIONS:
            packers.add(R.PACKER_SECTIONS[name])
        if s["raw_len"] >= 4096 and s["entropy"] > 7.20:
            high_entropy_sections.append(f"{name or '?'}(熵 {s['entropy']:.2f})")

    if packers:
        findings.append(Finding(
            rule_id="Heur.PE.Packer",
            name=f"加壳程序：{', '.join(sorted(packers))}",
            family="Packed",
            severity="suspicious",
            score=28,
            detail=f"检测到特征节区名：{', '.join(s['name'] for s in sections if s['name'] in R.PACKER_SECTIONS)}",
            desc="程序被加壳/保护。加壳本身是常见做法，但也是恶意软件躲避静态分析的首选手段。",
        ))
    if high_entropy_sections:
        findings.append(Finding(
            rule_id="Heur.PE.HighEntropy",
            name="节区数据高度随机（疑似加密或压缩）",
            family="Packed",
            severity="suspicious",
            score=20,
            detail="高熵节区：" + "，".join(high_entropy_sections[:5]),
            desc="正常代码节区的熵值通常在 6.0 以下。超过 7.2 基本说明内容被加密或压缩过。",
        ))

    # ---- 可写且可执行节区 ----
    wx = [s["name"] or "?" for s in sections
          if (s["chars"] & 0x80000000) and (s["chars"] & 0x20000000)]
    if wx:
        findings.append(Finding(
            rule_id="Heur.PE.WXSection",
            name="存在可写且可执行的节区（W+X）",
            family="Exploit",
            severity="suspicious",
            score=22,
            detail="节区：" + "，".join(wx[:5]),
            desc="同时具备写和执行权限的内存段，通常意味着运行时会动态生成并执行代码（shellcode 加载器特征）。",
        ))

    # ---- 可疑导入 ----
    hits = []
    total = 0
    for fn in funcs:
        if fn in R.SUSPICIOUS_IMPORTS:
            sc, why = R.SUSPICIOUS_IMPORTS[fn]
            hits.append((sc, fn, why))
    hits.sort(reverse=True)
    for sc, fn, why in hits[:12]:
        total += sc
    group_score = min(total, 90)
    if hits:
        top = hits[:8]
        findings.append(Finding(
            rule_id="Heur.PE.SuspiciousImports",
            name="导入表包含高危 API 组合",
            family="Suspicious.Behavior",
            severity="malicious" if group_score >= 70 else "suspicious",
            score=group_score,
            detail="；".join(f"{fn}（{why}，+{sc}）" for sc, fn, why in top),
            desc="导入函数反映了程序能做什么。单个 API 不足为凭，但成组出现（如注入 + 联网 + 加密）就很有说明性。",
        ))

    # ---- 无导入表 ----
    if not pe["imports"] and len(data) > 8192:
        findings.append(Finding(
            rule_id="Heur.PE.NoImports",
            name="没有导入表",
            family="Packed",
            severity="suspicious",
            score=25,
            detail="PE 导入表为空",
            desc="正常 Windows 程序必然导入系统 DLL。导入表为空说明它靠动态解析 API 隐藏自己，通常是被加壳或刻意混淆。",
        ))

    # ---- 时间戳异常 ----
    ts = pe["timestamp"]
    now = int(time.time())
    if ts == 0:
        findings.append(Finding(
            rule_id="Heur.PE.ZeroTimestamp",
            name="编译时间戳为零",
            family="Packed",
            severity="suspicious",
            score=12,
            detail="TimeDateStamp = 0",
            desc="时间戳被抹掉了，常见于加壳器或刻意隐藏来源的样本。",
        ))
    elif ts > now + 86400 * 30 or ts < 315532800:  # 未来时间 / 1990 年之前
        findings.append(Finding(
            rule_id="Heur.PE.BadTimestamp",
            name="编译时间戳不合理",
            family="Suspicious.Metadata",
            severity="suspicious",
            score=15,
            detail=f"TimeDateStamp = {ts}（{time.strftime('%Y-%m-%d', time.gmtime(ts)) if 0 < ts < 4102444800 else '越界'}）",
            desc="时间戳指向未来或 1990 年之前，通常是伪造的。",
        ))

    # ---- 入口点异常 ----
    entry = pe["entry"]
    if entry:
        inside = False
        for s in sections:
            span = max(s["vsize"], s["rsize"])
            if s["vaddr"] <= entry < s["vaddr"] + span:
                inside = True
                break
        if not inside:
            findings.append(Finding(
                rule_id="Heur.PE.EntryOutside",
                name="入口点不在任何节区内",
                family="Packed",
                severity="malicious",
                score=45,
                detail=f"AddressOfEntryPoint = 0x{entry:X}",
                desc="代码入口落在节区之外，是加壳器或畸形文件的典型特征。",
            ))

    # ---- 叠加数据 ----
    if pe["overlay"] > 64 * 1024 and len(data):
        ratio = pe["overlay"] / len(data)
        if ratio > 0.4:
            findings.append(Finding(
                rule_id="Heur.PE.Overlay",
                name="文件尾部存在大量附加数据",
                family="Suspicious.Metadata",
                severity="suspicious",
                score=15,
                detail=f"Overlay {format_size(pe['overlay'])}，占全文 {ratio:.0%}",
                desc="节区之后还挂着大块数据，常见于「正常程序 + 夹带 payload」的捆绑器（dropper）。",
            ))

    # ---- 证书 ----
    if pe["signed"]:
        findings.append(Finding(
            rule_id="Info.PE.Signed",
            name="包含数字签名",
            family="Info",
            severity="info",
            score=-15,
            detail="存在 Security 目录（Authenticode 签名）",
            desc="带有效数字签名的程序可信度显著更高（注意：签名也可能被盗用，这里只做减分参考）。",
        ))
    elif len(data) > 64 * 1024:
        findings.append(Finding(
            rule_id="Info.PE.Unsigned",
            name="没有数字签名",
            family="Info",
            severity="info",
            score=0,
            detail="未找到 Authenticode 签名目录",
            desc="仅供参考。绝大多数开源程序和绿色软件都没有签名。",
        ))

    return findings


# ===========================================================================
#  Office 文档结构分析
# ===========================================================================
def analyze_office(data: bytes, kind: str) -> list:
    """分析 Office 文档的宏、远程模板、DDE 等。"""
    findings = []

    if kind == "ole":
        markers = []
        for m, label in ((b"_VBA_PROJECT", "VBA 工程"), (b"VBA", "VBA"),
                         (b"Macros", "宏存储"), (b"ThisDocument", "文档模块")):
            if m in data:
                markers.append(label)
        if b"_VBA_PROJECT" in data or b"Macros" in data:
            findings.append(Finding(
                rule_id="Heur.Office.OleMacro",
                name="旧版 Office 文档中包含宏",
                family="Trojan.Macro",
                severity="suspicious",
                score=35,
                detail="检测到 " + "，".join(sorted(set(markers))),
                desc=".doc/.xls 等旧格式把宏存在 OLE 流里。如果没有宏，这里不应该出现 VBA 标记。",
            ))
        return findings

    # OOXML
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            lower = [n.lower() for n in names]

            # 1) VBA 宏工程
            macro_entries = [n for n in names if n.lower().endswith("vbaproject.bin")]
            if macro_entries:
                macro_bytes = b""
                for n in macro_entries[:3]:
                    try:
                        info = z.getinfo(n)
                        if info.file_size <= ARCHIVE_MEMBER_LIMIT:
                            macro_bytes += z.read(n)
                    except Exception:
                        pass
                hits = match_rules(macro_bytes, {"office", "binary", "text", "script"}) if macro_bytes else []
                findings.append(Finding(
                    rule_id="Heur.Office.MacroProject",
                    name="文档包含 VBA 宏工程",
                    family="Trojan.Macro",
                    severity="suspicious",
                    score=38,
                    detail="宏存储：" + "，".join(macro_entries[:3]) +
                           (f"；宏内命中 {len(hits)} 条特征" if hits else ""),
                    desc="文档内嵌 vbaProject.bin。正常办公文档极少带宏，带宏的邮件附件是钓鱼重灾区。",
                ))
                findings.extend(hits)

            # 2) 远程模板注入
            for n in names:
                if not n.lower().endswith(".rels"):
                    continue
                try:
                    if z.getinfo(n).file_size > 4 * 1024 * 1024:
                        continue
                    content = z.read(n)
                except Exception:
                    continue
                if b'TargetMode="External"' in content:
                    targets = re.findall(rb'Target="([^"]{0,200})"', content)
                    ext = [t.decode("latin-1", "ignore") for t in targets
                           if t.startswith(b"http")]
                    if ext:
                        findings.append(Finding(
                            rule_id="Heur.Office.RemoteTemplate",
                            name="远程模板注入（远程拉取文档模板）",
                            family="Trojan.Macro",
                            severity="malicious",
                            score=65,
                            detail=f"{n} → {', '.join(ext[:3])}",
                            desc="文档打开时会去远程地址下载模板，而远程模板里可以塞宏。这是绕过「本地文档无宏」检查的经典手法。",
                        ))

            # 3) 嵌入对象
            embeds = [n for n in names
                      if "embeddings/" in n.lower() or n.lower().endswith("oleobject1.bin")]
            if embeds:
                sub = []
                for n in embeds[:5]:
                    try:
                        info = z.getinfo(n)
                        if info.file_size <= ARCHIVE_MEMBER_LIMIT:
                            blob = z.read(n)
                            if blob[:2] == b"MZ":
                                sub.append(f"{n}（内嵌可执行文件！）")
                            else:
                                sub.append(f"{n}（{format_size(info.file_size)}）")
                    except Exception:
                        pass
                sev = "malicious" if any("可执行" in s for s in sub) else "suspicious"
                findings.append(Finding(
                    rule_id="Heur.Office.EmbeddedObject",
                    name="文档包含嵌入对象",
                    family="Trojan.Macro",
                    severity=sev,
                    score=55 if sev == "malicious" else 20,
                    detail="；".join(sub),
                    desc="文档里嵌了别的文件。内嵌 PE 可执行文件是明确的投毒信号。",
                ))

            # 4) 文档 XML 里的 DDE
            for n in names:
                if not n.lower().endswith(".xml"):
                    continue
                try:
                    info = z.getinfo(n)
                    if info.file_size > 8 * 1024 * 1024:
                        continue
                    content = z.read(n)
                except Exception:
                    continue
                if b"DDEAUTO" in content.upper():
                    findings.append(Finding(
                        rule_id="Heur.Office.DDE",
                        name="文档中包含 DDE 自动执行字段",
                        family="Trojan.Macro",
                        severity="malicious",
                        score=60,
                        detail=f"文件：{n}",
                        desc="DDE 字段不需要宏就能拉起外部程序，是钓鱼文档的常见免宏执行方式。",
                    ))
                    break

            # 5) 加密 zip（Office 文档加密）
            try:
                for info in z.infolist():
                    if info.flag_bits & 0x1:
                        findings.append(Finding(
                            rule_id="Heur.Office.Encrypted",
                            name="Office 文档被加密",
                            family="Suspicious.Metadata",
                            severity="suspicious",
                            score=20,
                            detail="压缩流设置了加密标志",
                            desc="带密码的文档常被用来绕过邮件网关的静态扫描（密码写在邮件正文里）。",
                        ))
                        break
            except Exception:
                pass
    except Exception:
        pass

    return findings


# ===========================================================================
#  核心分析入口
# ===========================================================================
def analyze_bytes(display_path: str, data: bytes, options: ScanOptions,
                  depth: int = 0, hash_cache: Optional[dict] = None) -> ScanResult:
    """对一个内存中的数据块做完整分析。文件扫描和压缩包成员扫描共用这条路径。"""
    t0 = time.perf_counter()
    res = ScanResult(path=display_path, size=len(data))
    findings = []

    try:
        import hashlib
        res.sha256 = hashlib.sha256(data).hexdigest()
        res.md5 = hashlib.md5(data).hexdigest()

        # ---- 第 1 层：哈希信誉 ----
        known = R.KNOWN_BAD_HASHES.get(res.sha256) or R.KNOWN_BAD_HASHES.get(res.md5)
        if hash_cache:
            known = known or hash_cache.get(res.sha256)
        if known:
            findings.append(Finding(
                rule_id="Hash.KnownMalware",
                name=f"已知恶意文件：{known}",
                family="Known.Malware",
                severity="malicious",
                score=100,
                detail=f"SHA-256 {res.sha256}",
                desc="文件哈希命中已知恶意样本库，这是置信度最高的判定方式。",
            ))

        filename = display_path.split(" >> ")[-1]
        res.kind = classify(data, filename)

        # ---- 第 2 层：文件名规则 ----
        findings.extend(match_filename(filename, options.detect_pua))

        # ---- 第 3 层：内容特征规则 ----
        kinds = kinds_for(res.kind)
        findings.extend(match_rules(data, kinds, options.detect_pua))
        findings.extend(match_yara(data))

        # ---- 第 4 层：结构启发式 ----
        if options.heuristics:
            if res.kind == "pe":
                pe = parse_pe(data)
                if pe:
                    findings.extend(analyze_pe(data, pe))
                else:
                    res.error = "PE 解析失败"
            elif res.kind in ("mz",):
                findings.append(Finding(
                    rule_id="Heur.MZBroken",
                    name="MZ 头但 PE 结构损坏",
                    family="Suspicious.Metadata",
                    severity="suspicious",
                    score=20,
                    detail="文件以 MZ 开头但找不到有效的 PE 头",
                    desc="可能是被截断的可执行文件，也可能是刻意构造的畸形文件。",
                ))

            # 非 PE 文件里出现 PE 头 → 强烈可疑
            if res.kind not in ("pe", "mz", "ooxml", "ole"):
                idx = data.find(b"MZ")
                while 0 <= idx < min(len(data), SIG_SCAN_LIMIT) - 0x40:
                    try:
                        e = _u32(data, idx + 0x3C)
                        if 0 < e < len(data) - idx - 4 and data[idx + e:idx + e + 4] == b"PE\x00\x00":
                            findings.append(Finding(
                                rule_id="Heur.EmbeddedPE",
                                name="文件中嵌入了 Windows 可执行体",
                                family="Trojan.Dropper",
                                severity="malicious",
                                score=60,
                                detail=f"在偏移 0x{idx:X} 处发现完整 PE 文件头",
                                desc="非可执行文件里藏着一整个 exe，基本可以直接判定为投放器 / 捆绑器。",
                            ))
                            break
                    except Exception:
                        pass
                    idx = data.find(b"MZ", idx + 1)
                    if idx > SIG_SCAN_LIMIT:
                        break

            # 文本文档里出现超长 Base64 块
            if res.kind in ("text", "script", "pdf", "ooxml"):
                for m in re.finditer(rb"[A-Za-z0-9+/]{300,}={0,2}", data[:SIG_SCAN_LIMIT]):
                    findings.append(Finding(
                        rule_id="Heur.LongBase64",
                        name="超大 Base64 数据块",
                        family="Obfuscated",
                        severity="suspicious",
                        score=22,
                        detail=f"偏移 0x{m.start():X}，长度 {len(m.group(0))} 字符",
                        desc="超过 300 字符的 Base64 块通常是隐藏的 payload 或配置数据。",
                    ))
                    break

        # ---- 第 5 层：Office 结构 ----
        if options.scan_office and res.kind in ("ole", "ooxml"):
            findings.extend(analyze_office(data, res.kind))

        # ---- IOC 提取 ----
        if res.kind in ("text", "script", "pdf", "ooxml", "ole") or res.score > 0:
            res.iocs = extract_iocs(data)

        # ---- 汇总 ----
        findings.sort(key=lambda f: (-f.score, f.rule_id))
        if not options.detect_pua:
            findings = [f for f in findings if f.severity != "pua"]
        res.findings = findings
        res.score = max(0, sum(f.score for f in findings))

        if any(f.severity == "malicious" for f in findings) or res.score >= 70:
            res.verdict = VERDICT_MALICIOUS
        elif res.score >= 20 and any(f.severity != "info" for f in findings):
            res.verdict = VERDICT_SUSPICIOUS
        else:
            res.verdict = VERDICT_CLEAN

    except Exception as exc:  # 单个文件出错绝不能中断整轮扫描
        res.error = f"{type(exc).__name__}: {exc}"
        res.verdict = VERDICT_ERROR

    res.duration_ms = (time.perf_counter() - t0) * 1000.0
    return res


def scan_file(path: str, options: ScanOptions, hash_cache: Optional[dict] = None) -> ScanResult:
    """扫描磁盘上的单个文件（含压缩包递归）。"""
    ext = os.path.splitext(path)[1].lower()
    if options.skip_large_by_extension and ext in SKIP_EXTENSIONS:
        return ScanResult(path=path, verdict=VERDICT_CLEAN, kind="skipped")
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return ScanResult(path=path, verdict=VERDICT_ERROR,
                          error="文件在扫描过程中消失（很可能已被安全软件清除）")
    except OSError as exc:
        return ScanResult(path=path, verdict=VERDICT_ERROR, error=str(exc))

    if size > options.max_file_size:
        return ScanResult(path=path, size=size, verdict=VERDICT_CLEAN, kind="skipped-too-large")

    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except PermissionError:
        return ScanResult(path=path, size=size, verdict=VERDICT_ERROR,
                          error="访问被拒绝：文件被占用，或被安全软件的实时防护拦截")
    except FileNotFoundError:
        return ScanResult(path=path, verdict=VERDICT_ERROR,
                          error="文件在扫描过程中消失（很可能已被安全软件清除）")
    except OSError as exc:
        return ScanResult(path=path, size=size, verdict=VERDICT_ERROR, error=str(exc))

    res = analyze_bytes(path, data, options, depth=0, hash_cache=hash_cache)

    # ---- 压缩包递归 ----
    if options.scan_archives and res.kind == "zip" and options.archive_depth > 0:
        res.findings.extend(_scan_zip_members(path, data, options, depth=1))
        res.findings.sort(key=lambda f: (-f.score, f.rule_id))
        res.score = max(0, sum(f.score for f in res.findings))
        if any(f.severity == "malicious" for f in res.findings) or res.score >= 70:
            res.verdict = VERDICT_MALICIOUS
        elif res.score >= 20 and any(f.severity != "info" for f in res.findings):
            res.verdict = VERDICT_SUSPICIOUS
    return res


def _scan_zip_members(path: str, data: bytes, options: ScanOptions, depth: int) -> list:
    """递归扫描 zip 内部成员，把结果作为父文件的 finding 返回。"""
    out = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            infos = [i for i in z.infolist() if not i.is_dir()]
            if len(infos) > options.archive_max_members:
                out.append(Finding(
                    rule_id="Heur.Archive.TooManyMembers",
                    name=f"压缩包成员过多（{len(infos)} 个），仅扫描前 {options.archive_max_members} 个",
                    family="Info",
                    severity="info",
                    score=0,
                    detail=f"共 {len(infos)} 个成员",
                    desc="为避免扫描时间失控，只扫描了前若干个成员。",
                ))
                infos = infos[:options.archive_max_members]

            for info in infos:
                if info.file_size > ARCHIVE_MEMBER_LIMIT:
                    continue
                try:
                    blob = z.read(info)
                except Exception:
                    continue
                if not blob:
                    continue
                sub = analyze_bytes(f"{path} >> {info.filename}", blob, options,
                                    depth=depth, hash_cache=None)
                if sub.verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
                    for f in sub.findings:
                        if f.severity == "info":
                            continue
                        out.append(Finding(
                            rule_id=f"[包内 {info.filename}] {f.rule_id}",
                            name=f.name,
                            family=f.family,
                            severity=f.severity,
                            score=f.score,
                            detail=f.detail,
                            desc=f.desc,
                        ))

                # 嵌套压缩包
                if (options.archive_depth > depth and sub.kind == "zip"):
                    out.extend(_scan_zip_members(f"{path} >> {info.filename}",
                                                 blob, options, depth + 1))
    except Exception:
        pass
    return out


# ===========================================================================
#  目录遍历 & 并发扫描
# ===========================================================================
def iter_files(targets: Iterable[str], follow_symlinks: bool = False) -> Iterator[str]:
    """把「文件或目录」列表展开成文件路径生成器。"""
    for t in targets:
        if os.path.isfile(t):
            yield t
        elif os.path.isdir(t):
            for root, dirs, files in os.walk(t, followlinks=follow_symlinks):
                dirs[:] = [d for d in dirs if not d.startswith("$") or d == "$Recycle.Bin"]
                for name in files:
                    yield os.path.join(root, name)


class Scanner:
    """扫描调度器：多线程 + 进度回调 + 取消。"""

    def __init__(self, options: Optional[ScanOptions] = None):
        self.options = options or ScanOptions()
        self.cancel_event = threading.Event()
        self.hash_cache: dict = {}
        self._load_external_hashes()
        load_yara_rules()

    def _load_external_hashes(self):
        """加载 signatures/blacklist.txt（每行一个 SHA-256 或 MD5，可用 # 注释）。"""
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, "signatures", "blacklist.txt")
        if not os.path.isfile(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 1)
                    h = parts[0].lower()
                    if len(h) in (32, 64):
                        self.hash_cache[h] = parts[1] if len(parts) > 1 else "外部特征库命中"
        except Exception:
            pass

    def cancel(self):
        self.cancel_event.set()

    def reset(self):
        self.cancel_event.clear()

    def scan(self,
             targets: Iterable[str],
             on_result: Optional[Callable[[ScanResult], None]] = None,
             on_progress: Optional[Callable[[dict], None]] = None,
             on_done: Optional[Callable[[dict], None]] = None) -> dict:
        """执行一轮扫描。回调全部在调用线程（工作线程）里触发。"""
        t_start = time.perf_counter()
        self.reset()

        files = list(iter_files(targets))
        total = len(files)
        stats = {
            "total": total, "done": 0, "threats": 0, "suspicious": 0,
            "errors": 0, "skipped": 0, "bytes": 0, "elapsed": 0.0,
            "cancelled": False, "results": [], "error_list": [],
        }

        if on_progress:
            on_progress(dict(stats, current=""))

        workers = max(1, min(self.options.threads, 32))

        def work(fp: str) -> ScanResult:
            if self.cancel_event.is_set():
                return ScanResult(path=fp, kind="cancelled")
            return scan_file(fp, self.options, self.hash_cache)

        with ThreadPoolExecutor(max_workers=workers) as pool:
            for res in pool.map(work, files):
                if self.cancel_event.is_set():
                    stats["cancelled"] = True
                    break
                stats["done"] += 1
                stats["bytes"] += res.size
                if res.verdict == VERDICT_MALICIOUS:
                    stats["threats"] += 1
                    stats["results"].append(res)
                elif res.verdict == VERDICT_SUSPICIOUS:
                    stats["suspicious"] += 1
                    stats["results"].append(res)
                elif res.verdict == VERDICT_ERROR:
                    stats["errors"] += 1
                    if len(stats["error_list"]) < 50:
                        stats["error_list"].append({"path": res.path, "error": res.error})
                elif res.kind in ("skipped", "skipped-too-large"):
                    stats["skipped"] += 1

                if on_result and res.verdict in (VERDICT_MALICIOUS, VERDICT_SUSPICIOUS):
                    on_result(res)
                if on_progress and (stats["done"] % 5 == 0 or stats["done"] == total):
                    on_progress(dict(stats, current=res.path))

        stats["elapsed"] = time.perf_counter() - t_start
        if on_progress:
            on_progress(dict(stats, current=""))
        if on_done:
            on_done(stats)
        return stats


# ===========================================================================
#  报告导出
# ===========================================================================
def export_json(stats: dict, path: str, targets: Iterable[str] = ()):
    payload = {
        "engine": f"{ENGINE_NAME} {ENGINE_VERSION}",
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": list(targets),
        "summary": {k: v for k, v in stats.items() if k != "results"},
        "detections": [r.to_dict() for r in stats.get("results", [])],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    return path


def export_text(stats: dict, path: str, targets: Iterable[str] = ()):
    lines = []
    lines.append("=" * 72)
    lines.append(f"  AEGIS 神盾扫描器 · 扫描报告")
    lines.append("=" * 72)
    lines.append(f"引擎版本 : {ENGINE_NAME} {ENGINE_VERSION}")
    lines.append(f"扫描时间 : {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"扫描目标 : {', '.join(targets)}")
    lines.append("")
    lines.append(f"扫描文件 : {stats.get('total', 0)}")
    lines.append(f"完成     : {stats.get('done', 0)}")
    lines.append(f"恶意     : {stats.get('threats', 0)}")
    lines.append(f"可疑     : {stats.get('suspicious', 0)}")
    lines.append(f"错误     : {stats.get('errors', 0)}")
    lines.append(f"耗时     : {stats.get('elapsed', 0):.2f} 秒")
    lines.append("")
    lines.append("-" * 72)
    lines.append("  检出明细")
    lines.append("-" * 72)
    if not stats.get("results"):
        lines.append("  未发现威胁。")
    for r in stats.get("results", []):
        lines.append("")
        lines.append(f"[{r.verdict_label}] {r.threat_name or '未知'}  (分值 {r.score})")
        lines.append(f"  文件   : {r.path}")
        lines.append(f"  大小   : {format_size(r.size)}   类型: {r.kind}")
        lines.append(f"  SHA256 : {r.sha256}")
        for f in r.findings:
            if f.severity == "info":
                continue
            lines.append(f"    - [{f.severity}] {f.name} (+{f.score})")
            if f.detail:
                lines.append(f"        依据: {f.detail}")
        if r.iocs:
            for key, vals in r.iocs.items():
                lines.append(f"    IOC {key}: {', '.join(vals[:8])}")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path
