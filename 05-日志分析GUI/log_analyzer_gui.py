#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================
 访问日志图形化分析工具  (access-log-analyzer GUI)
================================================================

把应急响应中对 access.log 的分析方法固化成规则引擎 + 桌面界面：
  1. 基线统计  —— 时间范围/状态码/来源/UA/速率，先知道"正常"长什么样
  2. 规则检测  —— SQLi/XSS/路径遍历/命令执行/敏感路径/扫描器/已知组件
  3. 成败判定  —— 攻击特征 + 2xx，并区分"高置信成功"与"兜底页假成功"
  4. 行为聚合  —— 目录扫描/批量拦截/分布式同载荷/404→200 翻转/爆破
  5. 攻击链    —— 按时间还原 扫描→探测→利用→落地
  6. 产出      —— 攻击者画像、告警明细、时间线、IOC、结论与处置建议

支持格式：Apache/Nginx combined 与 common、IIS W3C。
依赖：仅 Python 标准库（tkinter / csv / json / gzip / zipfile），无需 pip 安装。

运行：  python log_analyzer_gui.py
        python log_analyzer_gui.py samples/access.log     # 启动即打开该文件
"""

import argparse
import calendar
import csv
import gzip
import io
import ipaddress
import json
import math
import os
import queue
import re
import sys
import threading
import time
import traceback
import unicodedata
import webbrowser
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import unquote_plus

APP_NAME = "访问日志分析工具"
APP_VER = "1.0"
APP_SUB = "基线 · 规则 · 成败判定 · 攻击链 · IOC"

# =====================================================================
# 一、常量与规则库
# =====================================================================

# dataclass(slots=True) 需要 Python 3.10+，3.9 上自动降级
_DC_SLOTS = {"slots": True} if sys.version_info >= (3, 10) else {}

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEV_LABEL = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}
SEV_COLOR = {"critical": "#ef4444", "high": "#f97316", "medium": "#eab308",
             "low": "#6b7280", "info": "#38bdf8"}

CAT_LABEL = {
    "sqli": "SQL注入", "xss": "XSS", "traversal": "路径遍历", "rce": "命令执行",
    "exfil": "数据外带", "sensitive": "敏感路径", "cve": "已知组件", "scanner": "扫描器",
    "ua": "可疑UA", "method": "异常方法", "upload": "上传写入", "brute": "暴力破解",
    "dirscan": "目录扫描", "abn": "异常请求",
}
CAT_COLOR = {
    "sqli": "#ef4444", "xss": "#f97316", "traversal": "#eab308", "rce": "#dc2626",
    "exfil": "#be123c", "sensitive": "#38bdf8", "cve": "#ec4899", "scanner": "#a855f7",
    "ua": "#64748b", "method": "#06b6d4", "upload": "#f43f5e", "brute": "#f59e0b",
    "dirscan": "#8b5cf6", "abn": "#94a3b8",
}

# 视为"攻击载荷"的类别（用于成败判定）
ATTACK_CATS = {"sqli", "xss", "traversal", "rce", "exfil", "sensitive", "cve", "upload"}
# 探测类方法，不承载可用载荷
PROBE_METHODS = {"OPTIONS", "HEAD", "TRACE"}


@dataclass(frozen=True)
class Rule:
    rid: str
    name: str
    cat: str
    sev: str
    target: str          # uri / ua / method
    pattern: str
    desc: str = ""
    needles: tuple = ()


def _r(rid, name, cat, sev, pattern, target="uri", desc="", needles=()):
    return Rule(rid, name, cat, sev, target, pattern, desc, tuple(n.lower() for n in needles))


RULES = [
    # ---- SQL 注入 ----
    _r("SQLI-001", "SQL注入-UNION查询", "sqli", "high",
       r"union\s*(\+|%20|\s)*((all\s*(\+|%20|\s)*)?)select", needles=["union"]),
    _r("SQLI-002", "SQL注入-布尔盲注/万能密码", "sqli", "high",
       r"['\"]?\s*(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+", needles=[" or ", " and ", "="]),
    _r("SQLI-003", "SQL注入-时间盲注", "sqli", "critical",
       r"(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_\w+\.sleep)\s*\(",
       needles=["sleep", "benchmark", "waitfor", "dbms_"]),
    _r("SQLI-004", "SQL注入-元数据/文件读写", "sqli", "critical",
       r"(information_schema|load_file\s*\(|into\s+(out|dump)file|extractvalue\s*\(|updatexml\s*\(|@@version|load\s+data\s+infile)",
       needles=["information_schema", "load_file", "outfile", "extractvalue", "updatexml", "@@"]),
    _r("SQLI-005", "SQL注入-引号闭合探针", "sqli", "high",
       r"[?&][^=&\s]+=[^&\s]*['\"]", desc="参数值中出现引号，典型的闭合探测",
       needles=["'", '"', "%27", "%22"]),
    _r("SQLI-006", "SQL注入-注释截断", "sqli", "medium", r"(--|/\*!)", needles=["--", "/*!"]),
    _r("SQLI-007", "数据外带-DNS/HTTP回连", "exfil", "critical",
       r"(dnslog|bxss\.me|interact\.sh|ceye\.io|oast\.|collaborator)",
       needles=["dnslog", "bxss", "interact.sh", "ceye", "oast", "collaborator"]),

    # ---- XSS ----
    _r("XSS-001", "XSS-脚本标签注入", "xss", "high",
       r"<\s*script|%3c\s*script", needles=["<script", "%3cscript", "%3c", "<img", "<svg"]),
    _r("XSS-002", "XSS-事件处理器/伪协议", "xss", "medium",
       r"(javascript:|vbscript:|on(error|load|click|mouseover|focus)\s*=|document\.cookie|alert\s*\(|prompt\s*\()",
       needles=["javascript:", "onerror", "onload", "document.cookie", "alert("]),

    # ---- 路径遍历 / LFI ----
    _r("TRAV-001", "路径遍历-目录跳转", "traversal", "high",
       r"(\.\./|%2e%2e%2f|%2e%2e/|\.\.\\|\.\.%5c)", needles=["..", "%2e%2e", "..%5c"]),
    _r("TRAV-002", "路径遍历-系统敏感文件", "traversal", "critical",
       r"(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|php://(filter|input)|web-inf|meta-inf|/proc/self)",
       needles=["/etc/passwd", "/etc/shadow", "win.ini", "boot.ini", "php://", "web-inf", "proc/self"]),

    # ---- 命令执行 ----
    _r("RCE-001", "命令执行-Windows命令", "rce", "critical",
       r"(cmd\.exe|command\.com|powershell(\.exe)?(?=[\s&\"';|]|$)|winnt[/\\]system32|certutil|bitsadmin|mshta)",
       needles=["cmd.exe", "powershell", "winnt", "certutil", "bitsadmin", "mshta"]),
    _r("RCE-002", "命令执行-Shell拼接", "rce", "critical",
       r"(/bin/(sh|bash)|[;|%7c]\s*(cat|ls|id|whoami|uname|curl|wget|nc|nslookup)\b|\$\([^)]{1,80}\)|`[^`]{1,80}`)",
       needles=["/bin/", ";cat", "|cat", "whoami", "$(", "`"]),

    # ---- 敏感路径 ----
    _r("SENS-001", "敏感路径-配置与凭据", "sensitive", "high",
       r"(\.env\b|/\.git/|/\.svn/|web\.config|\.htaccess|\.htpasswd|/\.idea/|config\.(php|inc|json|yml|yaml))",
       needles=[".env", ".git", ".svn", "web.config", "htaccess", ".idea", "config."]),
    _r("SENS-002", "敏感路径-备份与数据库", "sensitive", "medium",
       r"\.(bak|old|orig|swp|sql|mdb|sqlite|db|dump|zip|tar|gz|rar)($|\?)",
       needles=[".bak", ".old", ".sql", ".mdb", ".sqlite", ".zip", ".tar", ".gz", ".rar", ".swp"]),
    _r("SENS-003", "敏感路径-管理后台/中间件", "sensitive", "low",
       r"(/phpmyadmin|/pma/|adminer|/manager/html|/actuator|/druid/|/nacos/|/solr/|wp-admin|/administrator/)",
       needles=["phpmyadmin", "pma/", "adminer", "manager/html", "actuator", "druid", "nacos", "wp-admin"]),

    # ---- 已知组件/CVE ----
    _r("CVE-001", "已知组件-Struts2/OGNL", "cve", "critical",
       r"(%24%7b|\$\{[^}]{0,80}(getruntime|processbuilder))",
       needles=["%24%7b", "${", "getruntime", "processbuilder"]),
    _r("CVE-002", "已知组件-Log4j JNDI", "cve", "critical",
       r"\$\{jndi:(ldap|rmi|dns)", needles=["jndi:", "ldap", "rmi:"]),
    _r("CVE-003", "已知组件-PHP-CGI参数注入", "cve", "critical",
       r"(phprc\s*=|allow_url_include|auto_prepend_file|cgi\.force_redirect)",
       needles=["phprc", "allow_url_include", "auto_prepend_file", "cgi.force_redirect"]),
    _r("CVE-004", "已知组件-XMLRPC/WebDAV探测", "cve", "medium",
       r"(/api/xmlrpc|pingback\.ping|/graphql|/webdav/|/sling/)",
       needles=["xmlrpc", "pingback", "graphql", "webdav", "/sling"]),

    # ---- IIS 特性 ----
    _r("IIS-001", "IIS-Unicode解码遍历", "traversal", "critical",
       r"(%c0%af|%c1%9c|%e0%80%af|%u[0-9a-f]{4})",
       needles=["%c0%af", "%c1%9c", "%e0%80%af", "%u"]),
    _r("IIS-002", "IIS-备用数据流/短文件名", "abn", "high",
       r"(::\$data|~[0-9]{1,2}\.[a-z0-9]{2,4}(\?|$)|%7e[0-9]{1,2})",
       needles=["::$data", "~", "%7e"]),
]

_SCANNER_UA = {
    "sqlmap": "sqlmap", "nikto": "Nikto", "nmap": "Nmap", "masscan": "Masscan",
    "zgrab": "ZGrab", "dirbuster": "DirBuster", "gobuster": "Gobuster",
    "dirsearch": "dirsearch", "wfuzz": "Wfuzz", "fuzz faster u fool": "ffuf",
    "ffuf": "ffuf", "nuclei": "Nuclei", "acunetix": "Acunetix", "awvs": "AWVS",
    "appscan": "AppScan", "nessus": "Nessus", "w3af": "w3af", "burp": "Burp",
    "xray": "Xray", "fscan": "fscan", "goby": "Goby", "whatweb": "WhatWeb",
    "wpscan": "WPScan", "joomscan": "JoomScan", "python-requests": "python-requests",
    "python-urllib": "python-urllib", "go-http-client": "go-http-client",
    "curl/": "curl", "wget/": "wget", "libwww-perl": "LWP",
}
_METHOD_RULES = {
    "TRACE": ("METH-001", "TRACE 方法（XST 探测）", "medium"),
    "PUT": ("METH-002", "PUT 方法（直接写文件）", "high"),
    "DELETE": ("METH-003", "DELETE 方法（删除资源）", "high"),
    "OPTIONS": ("METH-004", "OPTIONS 方法（探测支持的动词）", "info"),
    "PROPFIND": ("METH-005", "PROPFIND（WebDAV 枚举）", "medium"),
    "MKCOL": ("METH-006", "MKCOL（WebDAV 建目录）", "medium"),
    "CONNECT": ("METH-007", "CONNECT（代理隧道）", "medium"),
}

# =====================================================================
# 二、数据模型
# =====================================================================


@dataclass(**_DC_SLOTS)
class Alert:
    rid: str
    name: str
    cat: str
    sev: str
    field: str
    value: str
    desc: str = ""


@dataclass(**_DC_SLOTS)
class Rec:
    ts: int
    ip: str
    method: str
    uri: str
    status: int
    bytes: int
    ua: str
    ref: str
    taken: int = 0
    user: str = "-"
    raw: str = ""
    file: str = ""
    alerts: tuple = ()
    weak: bool = False          # 成功判定的"弱证据"标记
    is_success: bool = False    # 判定为高置信成功
    reason: str = ""


@dataclass
class Insight:
    kind: str
    sev: str
    title: str
    text: str
    ev: list = field(default_factory=list)


# =====================================================================
# 三、解析器
# =====================================================================

RX_APACHE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-|-)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?(?P<tail>.*)$'
)
RX_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:\[]+)(?:\[(\d+)\])?:\s*(.*)$")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}


def parse_apache_ts(s: str) -> int:
    m = re.match(r"(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})", s)
    if not m:
        return 0
    mo = MONTHS.get(m.group(2))
    if mo is None:
        return 0
    return calendar.timegm((int(m.group(3)), mo + 1, int(m.group(1)),
                            int(m.group(4)), int(m.group(5)), int(m.group(6)), 0, 0, 0))


def detect_type(lines) -> tuple:
    """返回 (类型 id, 置信度 0-100, 说明)。"""
    head = [l for l in lines[:40] if l.strip()]
    if not head:
        return ("empty", 0, "文件为空")
    joined = "\n".join(head)
    n_apache = sum(1 for l in head if RX_APACHE.match(l))
    if n_apache >= 8 or (n_apache >= 3 and n_apache / len(head) > 0.5):
        return ("web_apache", min(99, 70 + n_apache), "Apache/Nginx 访问日志（combined/common）")
    if head[0].startswith("#Software: Microsoft Internet Information") or any(
            l.startswith("#Fields:") for l in head[:6]):
        return ("web_iis", 97, "IIS W3C 扩展日志")
    if n_apache >= 1:
        return ("web_apache", 55, "疑似访问日志（样本较少）")
    if sum(1 for l in head if RX_SYSLOG.match(l)) >= 3:
        return ("linux_auth", 90, "Linux 认证日志（syslog）")
    if re.search(r"TimeCreated|EventID|EventId|ProviderName", head[0], re.I):
        return ("win_events", 88, "Windows 事件日志 CSV")
    if re.search(r"# Time:|# Query_time:|# User@Host:", joined):
        return ("db", 88, "数据库日志（MySQL 慢查询/通用）")
    if sum(1 for l in head if l.strip().startswith("{")) >= 3:
        return ("generic", 60, "JSON 行日志（通用）")
    return ("generic", 20, "未识别的通用文本日志")


def iter_log_lines(path: str):
    """打开日志（支持 .gz/.zip），自动处理 BOM 与编码。"""
    low = path.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    with zf.open(info) as fh:
                        yield from _decode(fh.read())
        return
    if low.endswith(".gz"):
        with gzip.open(path, "rb") as fh:
            yield from _decode(fh.read())
        return
    with open(path, "rb") as fh:
        yield from _decode(fh.read())


def _decode(data: bytes):
    for enc in ("utf-8-sig", "utf-8", "gb18030", "latin-1"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        text = data.decode("utf-8", errors="replace")
    # 用 StringIO 惰性迭代，避免 split() 再复制一份全部行（大日志能省一半峰值内存）
    for line in io.StringIO(text):
        yield line.rstrip("\r\n")


def parse_log(path: str, forced_type: str = "") -> tuple:
    """解析日志文件 → (records, 统计信息 dict)。"""
    lines = list(iter_log_lines(path))
    tname, conf, note = detect_type(lines)
    if forced_type:
        tname, note = forced_type, note + "（手动指定）"
    info = {"file": os.path.basename(path), "path": path, "type": tname,
            "conf": conf, "note": note, "lines": len(lines), "bad": 0,
            "bad_samples": []}
    recs = []
    if tname == "web_iis":
        recs = _parse_iis(lines, info)
    elif tname in ("win_events", "db"):
        info["note"] += "｜本工具聚焦访问日志，该类日志仅做识别，不做深度分析"
    elif tname == "linux_auth":
        recs = _parse_apache(lines, info)
        if not recs:                      # 回退到 syslog 解析
            info["bad"], info["bad_samples"] = 0, []
            recs = _parse_syslog(lines, info)
    elif tname == "generic":
        recs = _parse_apache(lines, info)
        if not recs:
            info["bad"], info["bad_samples"] = 0, []
            recs = _parse_generic(lines, info)
    else:
        recs = _parse_apache(lines, info)
    recs.sort(key=lambda r: r.ts)
    return recs, info


def _parse_apache(lines, info) -> list:
    out = []
    for i, line in enumerate(lines):
        if not line.strip():
            continue
        m = RX_APACHE.match(line)
        if not m:
            info["bad"] += 1
            if len(info["bad_samples"]) < 8:
                info["bad_samples"].append(f"{i+1}: {line[:180]}")
            continue
        d = m.groupdict()
        parts = (d["req"] or "").split(" ")
        uri = parts[1] if len(parts) > 1 else "-"
        out.append(Rec(
            ts=parse_apache_ts(d["ts"] or ""),
            ip=d["ip"], method=(parts[0] or "-").upper(), uri=uri,
            status=int(d["status"]) if (d["status"] or "").isdigit() else 0,
            bytes=int(d["bytes"]) if (d["bytes"] or "").isdigit() else 0,
            ua=d["ua"] or "-", ref=d["ref"] or "-",
            user=d["user"] if d["user"] not in ("-", None) else "-",
            raw=line, file=info["file"],
        ))
    return out


def _parse_iis(lines, info) -> list:
    out, fields = [], None
    for i, line in enumerate(lines):
        if not line:
            continue
        if line.startswith("#"):
            if line.startswith("#Fields:"):
                fields = line[8:].strip().split(" ")
            continue
        if not line.strip():
            continue
        if not fields:
            info["bad"] += 1
            continue
        p = line.split(" ")
        if len(p) != len(fields):
            info["bad"] += 1
            if len(info["bad_samples"]) < 8:
                info["bad_samples"].append(f"{i+1}: {line[:180]}")
            continue
        o = {f.lower(): v for f, v in zip(fields, p)}
        d, t = o.get("date", ""), o.get("time", "")
        try:
            ts = calendar.timegm((int(d[0:4]), int(d[5:7]), int(d[8:10]),
                                  int(t[0:2]), int(t[3:5]), int(t[6:8]), 0, 0, 0))
        except Exception:
            ts = 0
        uri = o.get("cs-uri-stem", "-")
        q = o.get("cs-uri-query", "-")
        if q and q != "-":
            uri += "?" + q
        out.append(Rec(
            ts=ts, ip=o.get("c-ip", "-"), method=o.get("cs-method", "-").upper(), uri=uri,
            status=int(o.get("sc-status", 0) or 0),
            bytes=int(o.get("sc-bytes", 0) or 0) if (o.get("sc-bytes", "0") or "0").isdigit() else 0,
            ua=o.get("cs(user-agent)", "-"), ref=o.get("cs(referer)", "-"),
            taken=int(o.get("time-taken", 0) or 0) if (o.get("time-taken", "0") or "0").isdigit() else 0,
            user=o.get("cs-username", "-"), raw=line, file=info["file"],
        ))
    return out


def _parse_syslog(lines, info) -> list:
    out = []
    for line in lines:
        m = RX_SYSLOG.match(line)
        if not m:
            info["bad"] += 1
            continue
        t = m.group(1)
        mon = MONTHS.get(t[:3], 1)
        ts = calendar.timegm((datetime.now().year, mon, int(t[4:6]),
                              int(t[7:9]), int(t[10:12]), int(t[13:15]), 0, 0, 0))
        msg = m.group(5)
        ipm = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", msg)
        out.append(Rec(ts=ts, ip=ipm.group(1) if ipm else "-", method="-", uri=msg,
                       status=0, bytes=0, ua="-", ref="-", raw=line, file=info["file"]))
    return out


def _parse_generic(lines, info) -> list:
    out = []
    for line in lines:
        if not line.strip():
            continue
        m = re.match(r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})", line)
        ts = 0
        if m:
            try:
                ts = calendar.timegm((int(m.group(1)[0:4]), int(m.group(1)[5:7]), int(m.group(1)[8:10]),
                                      int(m.group(2)[0:2]), int(m.group(2)[3:5]), int(m.group(2)[6:8]), 0, 0, 0))
            except Exception:
                ts = 0
        ipm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        out.append(Rec(ts=ts, ip=ipm.group(1) if ipm else "-", method="-", uri=line,
                       status=0, bytes=0, ua="-", ref="-", raw=line, file=info["file"]))
    return out


# =====================================================================
# 四、规则检测
# =====================================================================


def decode_uri(s: str) -> str:
    if not s or s == "-":
        return ""
    out = s
    if "%" in out:
        try:
            out = unquote_plus(out)
        except Exception:
            pass
        if "%" in out:
            try:
                out = unquote_plus(out)
            except Exception:
                pass
    elif "+" in out:
        out = out.replace("+", " ")
    return out


_COMPILED = [(r, re.compile(r.pattern, re.I)) for r in RULES]


def scan_record(rec: Rec) -> tuple:
    """对单条记录执行规则，返回 Alert 列表。"""
    uri_dec = decode_uri(rec.uri)
    low = (rec.uri + " " + uri_dec).lower()
    hits = []
    for rule, rx in _COMPILED:
        if rule.needles and not any(n in low for n in rule.needles):
            continue
        m = rx.search(uri_dec) or rx.search(rec.uri)
        if m:
            hits.append(Alert(rule.rid, rule.name, rule.cat, rule.sev,
                              "cs-uri-stem/query", m.group(0)[:180], rule.desc))

    # UA 指纹
    ua = (rec.ua or "").lower()
    for k, label in _SCANNER_UA.items():
        if k in ua:
            hits.append(Alert("SCAN-UA", f"扫描器-{label}", "scanner", "medium",
                              "User-Agent", rec.ua[:120], "UA 命中已知扫描工具"))
            break
    ua_s = (rec.ua or "").strip()
    if not ua_s or ua_s == "-":
        hits.append(Alert("UA-001", "可疑UA-空", "ua", "medium", "User-Agent", "(空)",
                          "空 UA，常见于脚本化请求"))
    elif re.fullmatch(r"mozilla/5\.0|mozilla/4\.0", ua_s, re.I):
        hits.append(Alert("UA-002", "可疑UA-裸 Mozilla（伪造）", "ua", "medium",
                          "User-Agent", ua_s, "不完整的伪造 UA，自动化工具常用"))
    elif len(ua_s) <= 8:
        hits.append(Alert("UA-003", "可疑UA-极短", "ua", "low", "User-Agent", ua_s, "疑似脚本"))
    if "<script" in ua or "javascript:" in ua:
        hits.append(Alert("UA-004", "UA注入-XSS载荷", "xss", "high", "User-Agent",
                          rec.ua[:120], "UA 中注入脚本，可能针对日志系统"))

    # 异常方法
    if rec.method in _METHOD_RULES:
        rid, name, sev = _METHOD_RULES[rec.method]
        hits.append(Alert(rid, name, "method", sev, "cs-method", rec.method,
                          "非常规 HTTP 动词"))

    # 慢响应 + 注入特征 → 时间盲注生效迹象
    if rec.taken >= 3000 and any(a.cat == "sqli" for a in hits):
        hits.append(Alert("SQLI-SLOW", "注入嫌疑-响应超时", "sqli", "critical",
                          "time-taken", f"{rec.taken}ms",
                          "含注入特征且响应耗时超长，疑似时间盲注生效"))
    return tuple(hits)


# =====================================================================
# 五、分析引擎
# =====================================================================


class Result:
    """一次分析的全部产出。"""

    def __init__(self, recs, infos):
        self.recs = recs
        self.infos = infos
        self.insights = []          # Insight
        self.conclusions = []       # Insight（结论，分级）
        self.profiles = []          # 攻击者画像
        self.attack_success = []    # 高置信成功
        self.attack_weak = []       # 弱证据（兜底页等）
        self.timeline = []
        self.ioc = {}
        self.stats = {}
        self.soft200 = False
        self.soft200_note = ""

    # ---------- 基线 ----------
    def baseline(self):
        recs = self.recs
        st = {}
        if not recs:
            self.stats = {"n": 0}
            return
        ts = [r.ts for r in recs if r.ts]
        st["n"] = len(recs)
        st["t0"], st["t1"] = (min(ts), max(ts)) if ts else (0, 0)
        st["ips"] = len({r.ip for r in recs})
        st["status"] = dict(Counter(r.status for r in recs).most_common())
        st["methods"] = dict(Counter(r.method for r in recs).most_common())
        st["ua"] = Counter(r.ua for r in recs).most_common(12)
        st["bytes"] = sum(r.bytes for r in recs)
        st["alerted"] = sum(1 for r in recs if r.alerts)
        st["alerts"] = sum(len(r.alerts) for r in recs)
        st["bad"] = sum(i.get("bad", 0) for i in self.infos)
        # 速率：每秒峰值
        per_sec = Counter(r.ts for r in recs if r.ts)
        st["peak_sec"] = max(per_sec.values()) if per_sec else 0
        st["peak_sec_at"] = max(per_sec, key=per_sec.get) if per_sec else 0
        # 攻击类计数
        st["cat"] = dict(Counter(a.cat for r in recs for a in r.alerts).most_common())
        st["sev"] = dict(Counter(a.sev for r in recs for a in r.alerts).most_common())
        # Top 路径
        st["top_uri"] = Counter(r.uri for r in recs).most_common(15)
        st["top_404"] = Counter(r.uri for r in recs if r.status == 404).most_common(15)
        st["top_2xx"] = Counter(r.uri for r in recs if 200 <= r.status < 300).most_common(15)
        # 403/401 拦截
        st["blocked"] = sum(1 for r in recs if r.status in (401, 403))
        self.stats = st

    # ---------- 成败判定 ----------
    def judge_success(self):
        """
        判定原则（写进代码，避免主观）：
          · 只有「攻击载荷 + 2xx/3xx + 非探测方法」才进入候选
          · 强证据（直接判定成功）：外带类载荷、盲注超长耗时（≥3s）
          · 弱信号（降级为"证据不足"）：目标是根路径、该路径历史出现 404、
            响应大小与大量正常页面相同（模板页，无法据此确认）
        """
        recs = self.recs
        if not recs:
            return
        path_status = defaultdict(set)
        size_paths = defaultdict(set)
        for r in recs:
            path_status[r.uri].add(r.status)
            if r.bytes and 200 <= r.status < 300:
                size_paths[(r.status, r.bytes)].add(r.uri)
        # 同一响应大小被 >=8 个不同路径共用 → 模板页特征，大小不能作为判据
        amb_sizes = {k for k, v in size_paths.items() if len(v) >= 8}
        if amb_sizes:
            top = sorted(((k, len(size_paths[k])) for k in amb_sizes), key=lambda x: -x[1])[:3]
            self.soft200 = True
            self.soft200_note = (
                "该站点存在模板化响应（同一响应体大小被多个不同路径共用，如 "
                + "、".join(f"{s}字节×{n}路径" for (st, s), n in top)
                + "），因此“响应大小正常”不能反证请求无害，也不能直接作为成功依据。")

        strong, weak = [], []
        for r in recs:
            r.is_success = False
            if not r.alerts or r.method in PROBE_METHODS:
                continue
            if not (200 <= r.status < 400):
                continue
            if not any(a.cat in ATTACK_CATS for a in r.alerts):
                continue

            hard, weak_reasons = [], []
            for a in r.alerts:
                if a.cat == "exfil":
                    hard.append("外带类载荷（DNS/HTTP 回连）")
                if a.rid == "SQLI-SLOW":
                    hard.append(f"响应耗时 {r.taken}ms（时间盲注生效迹象）")
            if r.taken >= 3000 and any(a.cat == "sqli" for a in r.alerts):
                if not any("盲注" in x for x in hard):
                    hard.append(f"响应耗时 {r.taken}ms（时间盲注生效迹象）")

            if r.uri in ("/", "*", ""):
                weak_reasons.append("目标是站点根路径")
            if 404 in path_status.get(r.uri, set()):
                weak_reasons.append("该路径历史返回过 404")
            if (r.status, r.bytes) in amb_sizes:
                weak_reasons.append("响应大小与多个正常页面相同（模板页），无法据此确认")
            if not hard and not weak_reasons:
                hard.append("真实存在的路径 + 成功状态码 + 响应大小异常")

            if hard:
                r.weak = False
                r.reason = "；".join(dict.fromkeys(hard))
                r.is_success = True
                strong.append(r)
            else:
                r.weak = True
                r.reason = "；".join(dict.fromkeys(weak_reasons))
                weak.append(r)
        self.attack_success = strong
        self.attack_weak = weak

    # ---------- 聚合洞察 ----------
    def aggregate(self):
        recs = self.recs
        if not recs:
            return
        by_ip = defaultdict(list)
        for r in recs:
            by_ip[r.ip].append(r)

        # 1) 目录扫描
        for ip, rs in by_ip.items():
            n404 = sum(1 for r in rs if r.status == 404)
            if n404 >= 100 and n404 / len(rs) >= 0.7:
                self.insights.append(Insight(
                    "dirscan", "high", f"目录/文件扫描：{ip}",
                    f"该 IP 共 {len(rs):,} 次请求，404 响应 {n404:,} 次（{n404/len(rs)*100:.1f}%），"
                    f"属字典扫描特征。",
                    [f"{_ft(min(x.ts for x in rs))} ~ {_ft(max(x.ts for x in rs))}  "
                     f"共 {len(rs):,} 次"]))

        # 2) 批量拦截（聚合为一条）
        blocked = [(ip, sum(1 for r in rs if r.status == 403)) for ip, rs in by_ip.items()]
        blocked = [(ip, n) for ip, n in blocked if n >= 50]
        if blocked:
            blocked.sort(key=lambda x: -x[1])
            total = sum(n for _, n in blocked)
            self.insights.append(Insight(
                "blocked", "medium", f"WAF/服务端批量拦截：{len(blocked)} 个 IP 共 {total:,} 次 403",
                "这些请求均被 403 拒绝，属自动化注入扫描被打断，可作为封禁依据。",
                [f"{ip}  {n:,} 次" for ip, n in blocked[:12]]))

        # 3) 分布式/同载荷（多 IP 共用同一载荷模板）
        tpl = defaultdict(set)
        for r in recs:
            for a in r.alerts:
                if a.cat in ("sqli", "xss", "traversal", "rce", "exfil"):
                    tpl[re.sub(r"\d+", "N", a.value)].add(r.ip)
        multi = sorted(((t, s) for t, s in tpl.items() if len(s) >= 3),
                       key=lambda x: -len(x[1]))
        if multi:
            t, s = multi[0]
            self.insights.append(Insight(
                "dist", "high", f"疑似分布式/自动化攻击（同载荷来自 {len(s)} 个 IP）",
                f"载荷模板 `{t[:90]}` 由 {len(s)} 个不同来源发起，说明使用工具批量执行（僵尸网络/扫描平台），"
                f"应按模板特征统一拦截并封禁相关 IP。",
                [f"{t[:110]}  ← {len(s)} IP"]))

        # 4) 路径翻转 404 → 2xx
        first_status = {}
        flips = []
        dictpaths = {u for u, c in Counter(r.uri for r in recs if r.status == 404).items() if c >= 3}
        for r in recs:
            if r.uri in ("/", "*") or "*" in r.uri or "~" in r.uri:
                continue
            f = first_status.get(r.ip + r.uri)
            if f is None:
                first_status[r.ip + r.uri] = r.status
            elif f == 404 and 200 <= r.status < 400 and r.uri not in dictpaths:
                if len(flips) < 30:
                    flips.append((r, f))
        if flips:
            self.insights.append(Insight(
                "flip", "critical", f"路径由 404 变为可访问：{len(flips)} 个",
                "同一路径先 404 后 2xx，符合上传落地/写入成功特征，须核对这些文件内容。",
                [f"{_ft(r.ts)} {r.ip} {r.uri[:100]} → {r.status}" for r, _ in flips[:10]]))

        # 5) 写入方法/上传接口
        wr = [r for r in recs if r.method in ("PUT", "PROPFIND", "MKCOL", "DELETE", "COPY", "MOVE")]
        upok = [r for r in recs if 200 <= r.status < 300 and
                re.search(r"(upload|file_?manager|uploadify|ckfinder|fckeditor)", r.uri, re.I)]
        if wr or upok:
            okw = [r for r in wr if 200 <= r.status < 300]
            self.insights.append(Insight(
                "upload", "critical" if (okw or upok) else "high",
                f"文件写入/上传调用：写入方法 {len(wr)} 次，上传接口 2xx {len(upok)} 次",
                "出现 PUT/WebDAV 或访问上传处理脚本，需到站点目录检查新增可执行文件。",
                [f"{_ft(r.ts)} {r.ip} {r.method} {r.uri[:90]} → {r.status}"
                 for r in (wr + upok)[:10]]))

        # 6) 登录爆破
        for ip, rs in by_ip.items():
            cand = [r for r in rs if re.search(r"(login|signin|dologin|logon|auth)", r.uri, re.I)
                    and r.status not in (0, 404)]
            per = Counter(r.uri.split("?")[0] for r in cand)
            for path, n in per.items():
                if n >= 30:
                    fails = sum(1 for r in cand if r.status in (401, 403))
                    self.insights.append(Insight(
                        "brute", "critical" if any(200 <= r.status < 300 for r in cand) else "high",
                        f"登录接口高频访问（疑似爆破）：{ip} → {path}",
                        f"共 {n:,} 次请求，401/403 共 {fails:,} 次。"))

        # 7) 慢请求
        slow = [r for r in recs if r.taken >= 3000]
        if slow:
            hit = [r for r in slow if r.alerts]
            self.insights.append(Insight(
                "slow", "high" if hit else "medium",
                f"慢响应请求 {len(slow):,} 条（≥3s）",
                (f"其中 {len(hit)} 条带攻击特征，可能为时间盲注生效。" if hit
                 else "无攻击特征，可能为大查询或资源耗尽。"),
                [f"{_ft(r.ts)} {r.ip} {r.taken}ms {r.uri[:80]}" for r in
                 sorted(slow, key=lambda x: -x.taken)[:8]]))

        # 8) 内网来源
        ips = list(by_ip)
        if len(ips) > 1 and all(_is_private(ip) for ip in ips):
            self.insights.append(Insight(
                "scope", "info", "攻击来源均为内网地址",
                f"所有来源 IP 均为内网段（{'、'.join(sorted(ips)[:8])}），需确认是否为授权测试/横向移动。"))

        self.insights.sort(key=lambda x: -SEV_RANK.get(x.sev, 0))

    # ---------- 画像 / 时间线 / IOC ----------
    def build_profiles(self):
        by_ip = defaultdict(list)
        for r in self.recs:
            by_ip[r.ip].append(r)
        rows = []
        for ip, rs in by_ip.items():
            hits = [a for r in rs for a in r.alerts]
            cats = Counter(a.cat for a in hits)
            sev = max((a.sev for a in hits), key=lambda s: SEV_RANK.get(s, 0), default="")
            succ = sum(1 for r in rs if getattr(r, 'is_success', False))
            rows.append({
                "ip": ip, "n": len(rs), "hits": len(hits), "succ": succ,
                "blocked": sum(1 for r in rs if r.status in (401, 403)),
                "sev": sev,
                "cats": cats.most_common(),
                "status": Counter(r.status for r in rs).most_common(4),
                "ua": Counter(r.ua for r in rs).most_common(1)[0][0] if rs else "-",
                "first": min((r.ts for r in rs if r.ts), default=0),
                "last": max((r.ts for r in rs if r.ts), default=0),
                "pend": sum(1 for r in rs if r.alerts and r.weak and 200 <= r.status < 400
                            and r.method not in PROBE_METHODS
                            and any(a.cat in ATTACK_CATS for a in r.alerts)),
                "private": _is_private(ip),
            })
        rows.sort(key=lambda x: (-SEV_RANK.get(x["sev"], 0), -x["succ"], -x["hits"], -x["n"]))
        self.profiles = rows

    def build_timeline(self):
        evs = [r for r in self.recs if r.alerts]
        # 级别优先，再按时间
        evs.sort(key=lambda r: (-max(SEV_RANK.get(a.sev, 0) for a in r.alerts), r.ts))
        self.timeline = evs[:2000]

    def build_ioc(self):
        atk = Counter()
        for r in self.recs:
            if r.alerts:
                atk[r.ip] += len(r.alerts)
        uas = Counter()
        for r in self.recs:
            for a in r.alerts:
                if a.cat == "scanner":
                    uas[r.ua[:90]] += 1
        sens = sorted({r.uri for r in self.recs
                       if 200 <= r.status < 400 and any(a.cat == "sensitive" for a in r.alerts)})
        payloads, seen = [], set()
        for r in self.recs:
            for a in r.alerts:
                if a.cat in ("sqli", "xss", "traversal", "rce", "exfil"):
                    k = re.sub(r"\d+", "N", a.value)
                    if k not in seen:
                        seen.add(k)
                        payloads.append(a.value)
        score = lambda s: (100 if re.search(
            r"union|select|load_file|outfile|information_schema|\.\./|dnslog|<script|sleep|waitfor",
            s, re.I) else 0) + len(s) / 30
        payloads.sort(key=score, reverse=True)
        self.ioc = {
            "atk_ips": [ip for ip, _ in atk.most_common()],
            "scanners": [u for u, _ in uas.most_common(10)],
            "sensitive_2xx": sens,
            "payloads": payloads[:30],
            "users": sorted({r.user for r in self.recs if r.user not in ("-", "")}),
        }

    # ---------- 结论 ----------
    def build_conclusions(self):
        st = self.stats
        C = self.conclusions
        succ, weak = self.attack_success, self.attack_weak
        atk_recs = [r for r in self.recs if r.alerts and
                    any(a.cat in ATTACK_CATS for a in r.alerts) and r.method not in PROBE_METHODS]

        # 1. 成功判定（最高优先级）
        if succ:
            ips = Counter(r.ip for r in succ)
            C.append(Insight(
                "success", "critical", f"高置信攻击成功：{len(succ)} 条",
                f"这些请求命中攻击载荷并返回 2xx/3xx，且具有强证据（外带回连/超长耗时），或目标既非根路径、也非历史 404 路径"
                f"{'、响应体也不与兜底页一致' if self.soft200 else ''}，属于最可能是真实利用的请求。"
                f"涉及 {len(ips)} 个 IP（{'、'.join(f'{k}×{v}' for k, v in ips.most_common(6))}）。"
                f"请优先核对这些 URI 的响应内容与数据库审计日志。",
                [f"{_ft(r.ts)} {r.ip} {r.method} {r.uri[:120]} → {r.status}"
                 f"（{r.bytes}B{'，' + str(r.taken) + 'ms' if r.taken else ''}）：{r.reason}"
                 for r in succ[:20]]))
        if weak:
            C.append(Insight(
                "weak", "medium", f"成功状态码但证据不足：{len(weak)} 条（需人工确认）",
                "这些请求虽有攻击特征并返回 2xx，但目标为根路径/曾 404 的路径/与兜底页一致，"
                "不能直接判定利用成功。" + (self.soft200_note or "") +
                "建议补充响应体内容、应用日志或数据库审计后再定性。",
                [f"{_ft(r.ts)} {r.ip} {r.method} {r.uri[:110]} → {r.status}：{r.reason}"
                 for r in weak[:15]]))

        # 2. 攻击规模与拦截效果
        if atk_recs:
            blocked = sum(1 for r in atk_recs if r.status in (401, 403))
            rate = blocked / len(atk_recs) * 100
            ips = len({r.ip for r in atk_recs})
            C.append(Insight(
                "scale", "info" if rate >= 95 else "high",
                f"攻击规模：{len(atk_recs):,} 条攻击请求，来自 {ips} 个 IP",
                f"其中被 401/403 拦截 {blocked:,} 条（{rate:.1f}%）。"
                + ("防护基本有效，但仍需关注未拦截部分。" if rate >= 95
                   else "拦截率偏低，存在较多漏防，建议复核 WAF 规则。")))

        # 3. 最活跃攻击源（按“疑似成功→命中→请求量”排序，避免只打一次的 IP 排第一）
        if self.profiles:
            top = sorted([p for p in self.profiles if p["hits"] > 0],
                         key=lambda p: (-p["succ"], -p["hits"], -p["n"]))[:5]
            if top:
                C.append(Insight(
                    "top", "high",
                    f"重点攻击源：{top[0]['ip']}（请求 {top[0]['n']:,} 次，命中 {top[0]['hits']:,}，"
                    f"疑似成功 {top[0]['succ']}，待确认 {top[0].get('pend', 0)}）",
                    "TOP 攻击源（按疑似成功数、告警命中数排序）：",
                    [f"{p['ip']}  请求 {p['n']:,}  命中 {p['hits']}  成功 {p['succ']}  "
                     f"拦截 {p['blocked']:,}  类型：" +
                     "、".join(f"{CAT_LABEL.get(c, c)}×{n}" for c, n in p["cats"][:3]) +
                     f"  UA：{p['ua'][:40]}"
                     for p in top]))

        # 4. 攻击链阶段
        C.append(self._chain_conclusion())

        # 5. 判定口径说明
        C.append(Insight(
            "method", "info", "判定口径（为什么这样下结论）",
            "① 只有「攻击载荷 + 2xx」才进入成功候选；② 根路径、历史 404 路径、"
            "响应与兜底页一致的请求降级为“证据不足”；"
            "③ 外带类载荷（DNSLog 等）与超长耗时（时间盲注）单独作为强证据；"
            "④ 仅探测（全部 4xx）不计入攻击成功。"
            + ("本日志已检测到兜底页特征，2xx 的解释需格外谨慎。" if self.soft200 else "")))

        C.sort(key=lambda x: -SEV_RANK.get(x.sev, 0))

    def _chain_conclusion(self) -> Insight:
        """按阶段还原攻击链。"""
        stages = [
            ("扫描/探测", lambda r: r.status in (404, 403) and r.alerts),
            ("漏洞利用尝试", lambda r: r.alerts and any(a.cat in ("sqli", "xss", "traversal", "rce", "cve")
                                                        for a in r.alerts)),
            ("利用成功", lambda r: not r.weak and r.alerts and 200 <= r.status < 400),
            ("落地/写入", lambda r: r.method in ("PUT", "PROPFIND", "MKCOL") or
             (200 <= r.status < 300 and re.search(r"upload", r.uri, re.I))),
            ("数据外带", lambda r: any(a.cat == "exfil" for a in r.alerts)),
        ]
        lines, found = [], 0
        for name, fn in stages:
            hits = [r for r in self.recs if fn(r)]
            if hits:
                found += 1
                lines.append(f"{name}：{len(hits):,} 条，"
                             f"{_ft(min(x.ts for x in hits))} ~ {_ft(max(x.ts for x in hits))}，"
                             f"来源 {len({x.ip for x in hits})} 个 IP")
        if not lines:
            return Insight("chain", "info", "攻击链：未形成可识别的攻击阶段",
                           "日志中未出现阶段性攻击特征，可能为正常业务流量或样本不足。")
        sev = "critical" if found >= 4 else ("high" if found >= 3 else "medium")
        return Insight("chain", sev,
                       f"攻击链还原：识别到 {found} 个阶段",
                       "按时间顺序的阶段性统计（同一请求可能命中多个阶段）：", lines)

    # ---------- 主流程 ----------
    def run(self):
        t = time.time()
        for r in self.recs:
            r.alerts = scan_record(r)
        self.baseline()
        self.judge_success()
        self.aggregate()
        self.build_profiles()
        self.build_timeline()
        self.build_ioc()
        self.build_conclusions()
        self.stats["elapsed"] = time.time() - t
        return self


def _ft(ts: int) -> str:
    if not ts:
        return "????-??-?? ??:??:??"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _ft_span(a: int, b: int) -> str:
    """把「首次~末次」压成一行，同一天只写一次日期，避免列宽不够被截断。"""
    if not a and not b:
        return "—"
    if not a:
        return _ft(b)
    if not b:
        return _ft(a)
    da = datetime.fromtimestamp(a, timezone.utc)
    db = datetime.fromtimestamp(b, timezone.utc)
    if da.strftime("%Y-%m-%d") == db.strftime("%Y-%m-%d"):
        return f"{da:%m-%d %H:%M:%S} ~ {db:%H:%M:%S}"
    return f"{da:%m-%d %H:%M:%S} ~ {db:%m-%d %H:%M:%S}"


def _is_private(ip: str) -> bool:
    """仅把 RFC1918 / 环回 / 链路本地视为内网；文档网段(203.0.113.x 等)不算。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.is_loopback or a.is_link_local:
        return True
    return any(a in ipaddress.ip_network(n) for n in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def analyze_files(paths, forced_type="") -> Result:
    recs, infos = [], []
    for p in paths:
        try:
            rs, info = parse_log(p, forced_type)
            recs.extend(rs)
            infos.append(info)
        except Exception as exc:
            infos.append({"file": os.path.basename(p), "path": p, "type": "error",
                          "conf": 0, "note": f"解析失败：{exc}", "lines": 0, "bad": 0,
                          "bad_samples": [traceback.format_exc(limit=2)]})
    recs.sort(key=lambda r: r.ts)
    return Result(recs, infos).run()

# =====================================================================
# 六、导出（HTML / CSV / JSON）
# =====================================================================

HTML_CSS = """
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--fg:#e6edf3;--mut:#8b949e}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:13.5px/1.65 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif}
.wrap{max-width:1280px;margin:0 auto;padding:22px 26px 60px}
h1{font-size:20px;margin:0 0 6px}
h1 .tag{font-size:11px;color:var(--mut);border:1px solid var(--line);border-radius:20px;padding:1px 9px;margin-left:8px;font-weight:400}
.meta{color:var(--mut);font-size:12px;display:flex;flex-wrap:wrap;gap:6px 18px;margin-bottom:18px}
.meta b{color:#c9d1d9;font-weight:500}
h2{font-size:14px;margin:26px 0 12px;padding-left:10px;border-left:3px solid #38bdf8}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.kpi .v{font-size:23px;font-weight:700;line-height:1.2}
.kpi .l{color:var(--mut);font-size:11.5px}
.kpi.critical .v{color:#ef4444}.kpi.high .v{color:#f97316}.kpi.medium .v{color:#eab308}
.kpi.info .v{color:#38bdf8}.kpi.ok .v{color:#22c55e}.kpi.low .v{color:#6b7280}
.find{border-left:3px solid #6b7280;background:var(--card);border-radius:0 8px 8px 0;padding:11px 15px;margin-bottom:9px;
  border-top:1px solid var(--line);border-right:1px solid var(--line);border-bottom:1px solid var(--line)}
.find.critical{border-left-color:#ef4444;background:#1d1518}
.find.high{border-left-color:#f97316}.find.medium{border-left-color:#eab308}.find.info{border-left-color:#38bdf8}
.find .t{font-weight:600;font-size:13px;margin-bottom:3px}
.find .d{color:#a9b4c0;font-size:12.5px;white-space:pre-wrap}
.find .ev{margin-top:7px;padding:7px 9px;background:#0b0f14;border:1px solid var(--line);border-radius:5px;
  font:11px/1.7 Consolas,monospace;color:#9aa7b2;white-space:pre-wrap;max-height:190px;overflow:auto}
.sev{display:inline-block;font-size:10px;font-weight:600;padding:1px 7px;border-radius:10px;border:1px solid;margin-right:6px}
.sev.critical{color:#fca5a5;border-color:#7f1d1d;background:#2a1113}
.sev.high{color:#fdba74;border-color:#7c2d12;background:#2a1a10}
.sev.medium{color:#fde68a;border-color:#713f12;background:#2a2410}
.sev.low{color:#d1d5db;border-color:#374151;background:#1b2027}
.sev.info{color:#a5f3fc;border-color:#155e75;background:#0d242b}
table{width:100%;border-collapse:collapse;font-size:11.5px;background:var(--card);
  border:1px solid var(--line);border-radius:8px;overflow:hidden}
th{text-align:left;color:var(--mut);font-weight:500;font-size:10.5px;text-transform:uppercase;
  padding:8px 9px;background:#12171f;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:6px 9px;border-bottom:1px solid #21262d;vertical-align:top}
.tbl{max-height:600px;overflow:auto;border-radius:8px}
.uri{font-family:Consolas,monospace;font-size:10.8px;word-break:break-all;max-width:520px}
.mono{font-family:Consolas,monospace;font-size:10.8px;color:#9aa7b2}
.tag{display:inline-block;font-size:10px;padding:0 6px;border-radius:3px;background:#21262d;margin:0 3px 2px 0}
.ioc{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}
.ioc .card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.ioc h3{font-size:12px;margin:0 0 8px;color:#c9d1d9}
.ioc ul{margin:0;padding:0;list-style:none;max-height:200px;overflow:auto}
.ioc li{font:11.4px/1.7 Consolas,monospace;padding:2px 0;border-bottom:1px dashed #21262d;word-break:break-all}
.ioc li:last-child{border:none}
footer{margin-top:34px;padding-top:13px;border-top:1px solid var(--line);color:var(--mut);font-size:11px}
.warn{background:#2a1a10;border:1px solid #7c2d12;color:#fdba74;border-radius:7px;padding:9px 13px;font-size:12px;margin-bottom:14px}
"""


def _e(s) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def export_html(res: "Result", path: str, meta_name: str = "") -> str:
    st = res.stats
    if not st.get("n"):
        html = "<html><body style='background:#0d1117;color:#e6edf3;font-family:sans-serif'>" \
               "<h2>未解析到任何记录</h2></body></html>"
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path

    kpis = [
        ("请求总数", f"{st['n']:,}", "info"),
        ("独立客户端 IP", f"{st['ips']:,}", "info"),
        ("攻击 IP", f"{sum(1 for p in res.profiles if p['hits']):,}", "high"),
        ("高置信成功", f"{len(res.attack_success):,}", "critical" if res.attack_success else "ok"),
        ("待确认", f"{len(res.attack_weak):,}", "medium" if res.attack_weak else "ok"),
        ("被拦截(401/403)", f"{st['blocked']:,}", "medium"),
        ("解析异常行", f"{st['bad']:,}", "low"),
    ]
    kpi_html = "".join(
        f'<div class="kpi {c}"><div class="v">{v}</div><div class="l">{_e(l)}</div></div>'
        for l, v, c in kpis)

    def finds(items):
        out = []
        for f in items:
            ev = ""
            if f.ev:
                ev = '<div class="ev">' + _e("\n".join(f.ev[:20])) + "</div>"
            out.append(
                f'<div class="find {f.sev}"><div class="t">'
                f'<span class="sev {f.sev}">{SEV_LABEL[f.sev]}</span>{_e(f.title)}</div>'
                f'<div class="d">{_e(f.text)}</div>{ev}</div>')
        return "".join(out) or '<div class="muted">无</div>'

    # 攻击者画像
    prof_rows = "".join(
        "<tr>"
        f'<td class="mono">{_e(p["ip"])}{" (内网)" if p["private"] else ""}</td>'
        f'<td>{p["n"]:,}</td><td>{p["hits"]:,}</td>'
        f'<td>{p["succ"] if p["succ"] else "-"}</td><td>{p.get("pend") or "-"}</td>'
        f'<td>{p["blocked"]:,}</td>'
        f'<td><span class="sev {p["sev"] or "info"}">{SEV_LABEL.get(p["sev"], "-")}</span></td>'
        f'<td>{"".join(f"<span class=tag>{_e(CAT_LABEL.get(c,c))} {n}</span>" for c, n in p["cats"][:4])}</td>'
        f'<td class="mono">{_e(" ".join(f"{k}:{v}" for k, v in p["status"]))}</td>'
        f'<td class="mono">{_e(p["ua"][:60])}</td>'
        f'<td class="mono">{_e(_ft(p["first"]))}<br>{_e(_ft(p["last"]))}</td>'
        "</tr>" for p in res.profiles[:40])

    # 告警明细
    alerts = [r for r in res.recs if r.alerts]
    alerts.sort(key=lambda r: (-max(SEV_RANK.get(a.sev, 0) for a in r.alerts), r.ts))
    rows = []
    for r in alerts[:1500]:
        a = max(r.alerts, key=lambda x: SEV_RANK.get(x.sev, 0))
        flag = ('<span class="tag" style="background:#3f1416;color:#fca5a5">疑似成功</span>'
                if r.is_success else
                ('<span class="tag" style="background:#2a2410;color:#fde68a">待确认</span>'
                 if r.weak else ""))
        rows.append(
            "<tr>"
            f'<td class="mono">{_e(_ft(r.ts))}</td><td class="mono">{_e(r.ip)}</td>'
            f'<td class="mono">{_e(r.method)}</td><td class="uri">{_e(r.uri[:220])}</td>'
            f'<td class="mono">{r.status}</td><td>{r.bytes or "-"}</td>'
            f'<td><span class="sev {a.sev}">{SEV_LABEL[a.sev]}</span></td>'
            f'<td>{_e(CAT_LABEL.get(a.cat, a.cat))}</td><td>{_e(a.name)}</td>'
            f'<td class="uri" style="color:#f0a0a0">{_e(a.value[:120])}</td>'
            f"<td>{flag}</td></tr>")
    alert_html = "".join(rows) or '<tr><td colspan="11">无告警</td></tr>'

    def ioc_card(title, items):
        lis = "".join(f"<li>{_e(x)}</li>" for x in items[:60]) or "<li>（无）</li>"
        return f'<div class="card"><h3>{_e(title)}</h3><ul>{lis}</ul></div>'

    ioc = res.ioc
    ioc_html = "".join([
        ioc_card("攻击来源 IP", ioc.get("atk_ips", [])),
        ioc_card("扫描器/工具 UA", ioc.get("scanners", [])),
        ioc_card("敏感路径（2xx）", ioc.get("sensitive_2xx", [])),
        ioc_card("典型攻击载荷", ioc.get("payloads", [])),
        ioc_card("涉及账号", ioc.get("users", [])),
    ])

    files = "<br>".join(
        f'{_e(i["file"])} — {_e(i["type"])}（置信 {i["conf"]}%），{i["lines"]:,} 行，异常 {i["bad"]} 行'
        for i in res.infos)
    warn = ""
    if res.soft200:
        warn = f'<div class="warn">⚠ {_e(res.soft200_note)}</div>'

    html = f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>访问日志分析报告</title><style>{HTML_CSS}</style></head><body><div class="wrap">
<h1>访问日志应急分析报告<span class="tag">{APP_NAME} v{APP_VER}</span></h1>
<div class="meta">
  <span>文件 <b>{files}</b></span>
  <span>时间 <b>{_e(_ft(st.get('t0', 0)))} ~ {_e(_ft(st.get('t1', 0)))}</b></span>
  <span>耗时 <b>{st.get('elapsed', 0):.2f}s</b></span>
</div>
{warn}
<div class="kpis">{kpi_html}</div>
<h2>关键结论</h2>{finds(res.conclusions)}
<h2>聚合研判</h2>{finds(res.insights)}
<h2>攻击者画像</h2>
<div class="tbl"><table><thead><tr><th>来源 IP</th><th>请求</th><th>命中</th><th>疑似成功</th>
<th>待确认</th><th>拦截</th><th>最高级别</th><th>攻击类型</th><th>状态码</th><th>UA</th><th>首末时间</th>
</tr></thead><tbody>{prof_rows}</tbody></table></div>
<h2>告警明细 <span style="color:#8b949e;font-size:11.5px;font-weight:400">（前 1500 条，按严重度排序）</span></h2>
<div class="tbl"><table><thead><tr><th>时间</th><th>来源 IP</th><th>方法</th><th>URI</th><th>状态</th>
<th>字节</th><th>级别</th><th>类别</th><th>规则</th><th>命中值</th><th>判定</th></tr></thead>
<tbody>{alert_html}</tbody></table></div>
<h2>IOC 清单</h2><div class="ioc">{ioc_html}</div>
<footer>生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　|　{APP_NAME} v{APP_VER}　|　
数据来源：{_e(meta_name or '本机日志')}</footer>
</div></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


def export_csv(res: "Result", path: str) -> int:
    alerts = [r for r in res.recs if r.alerts]
    n = 0
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "来源IP", "方法", "URI", "状态码", "字节", "耗时ms", "UA",
                    "规则ID", "规则名称", "类别", "级别", "命中值", "判定", "判定依据", "原始日志"])
        for r in alerts:
            for a in r.alerts:
                judge = "疑似成功" if r.is_success else ("待确认" if r.weak else "")
                w.writerow([_ft(r.ts), r.ip, r.method, r.uri, r.status, r.bytes, r.taken, r.ua,
                            a.rid, a.name, CAT_LABEL.get(a.cat, a.cat), SEV_LABEL.get(a.sev, a.sev),
                            a.value, judge, r.reason, r.raw])
                n += 1
    return n


def export_json(res: "Result", path: str) -> str:
    st = res.stats
    data = {
        "tool": APP_NAME, "version": APP_VER,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "files": [{k: v for k, v in i.items() if k != "bad_samples"} for i in res.infos],
        "summary": {
            "records": st.get("n", 0), "unique_ip": st.get("ips", 0),
            "alerted_records": st.get("alerted", 0), "alerts": st.get("alerts", 0),
            "blocked": st.get("blocked", 0),
            "attack_success": len(res.attack_success), "attack_pending": len(res.attack_weak),
            "status": st.get("status", {}), "categories": st.get("cat", {}),
            "peak_per_sec": st.get("peak_sec", 0),
            "soft_200": res.soft200, "soft_200_note": res.soft200_note,
        },
        "profiles": [{k: v for k, v in p.items() if k not in ("status",)} for p in res.profiles],
        "conclusions": [{"severity": c.sev, "title": c.title, "text": c.text, "evidence": c.ev}
                        for c in res.conclusions],
        "insights": [{"severity": i.sev, "title": i.title, "text": i.text, "evidence": i.ev}
                     for i in res.insights],
        "ioc": res.ioc,
        "alerts": [{
            "time": _ft(r.ts), "ip": r.ip, "method": r.method, "uri": r.uri,
            "status": r.status, "bytes": r.bytes, "ua": r.ua, "judgement":
            ("疑似成功" if r.is_success else ("待确认" if r.weak else "")),
            "reason": r.reason,
            "findings": [{"rule": a.rid, "name": a.name, "category": a.cat,
                          "severity": a.sev, "matched": a.value} for a in r.alerts],
        } for r in res.recs if r.alerts][:20000],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return path

# =====================================================================
# 七、图形界面（tkinter）
# =====================================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 配色（深色安全运营风格）
BG = "#0d1117"
CARD = "#161b22"
CARD2 = "#12171f"
LINE = "#30363d"
FG = "#e6edf3"
MUT = "#8b949e"
DIM = "#6e7681"
ACC = "#38bdf8"
SEL = "#1f6feb"

F_UI = ("Microsoft YaHei UI", 9)
F_UI_S = ("Microsoft YaHei UI", 8)
F_UI_B = ("Microsoft YaHei UI", 9, "bold")
F_VAL = ("Microsoft YaHei UI", 17, "bold")
F_MONO = ("Consolas", 9)
F_MONO_S = ("Consolas", 8)


def enable_dpi_awareness():
    """必须在创建任何 Tk 窗口之前调用，否则高分屏下界面会被系统拉伸变糊。"""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)   # Win8.1+
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()        # Win7 兜底
    except Exception:
        pass


def _work_area():
    """返回桌面工作区 (left, top, right, bottom)，已扣掉任务栏；取不到返回 None。"""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        r = wintypes.RECT()
        # SPI_GETWORKAREA = 0x0030
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(r), 0):
            if r.right > r.left and r.bottom > r.top:
                return (r.left, r.top, r.right, r.bottom)
    except Exception:
        pass
    return None


def _rescale_fonts(scale):
    """按屏幕 DPI 缩放字体元组（模块级全局，Chart / App 都用同一套）。"""
    global F_UI, F_UI_S, F_UI_B, F_VAL, F_MONO, F_MONO_S
    if abs(scale - 1.0) < 0.01:
        return

    def f(family, size, *style):
        return (family, max(7, int(round(size * scale))), *style)

    F_UI = f("Microsoft YaHei UI", 9)
    F_UI_S = f("Microsoft YaHei UI", 8)
    F_UI_B = f("Microsoft YaHei UI", 9, "bold")
    F_VAL = f("Microsoft YaHei UI", 17, "bold")
    F_MONO = f("Consolas", 9)
    F_MONO_S = f("Consolas", 8)


class Chart:
    """在 Canvas 上自绘图表（折线 / 环形 / 柱状 / 横条），随窗口大小自适应。"""

    def __init__(self, parent, kind, height=210):
        self.kind = kind
        self.canvas = tk.Canvas(parent, bg=CARD, highlightthickness=0,
                                height=height, bd=0)
        self.data = None
        self.canvas.bind("<Configure>", lambda e: self.redraw())

    def widget(self):
        return self.canvas

    def set_data(self, data):
        self.data = data
        self.redraw()

    def redraw(self):
        c = self.canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 30 or h < 30 or self.data is None:
            return
        try:
            getattr(self, "_draw_" + self.kind)(w, h)
        except Exception:
            c.create_text(w / 2, h / 2, text="图表绘制失败", fill=DIM, font=F_UI_S)

    # ---- 折线：请求量趋势 ----
    def _draw_line(self, w, h):
        series = self.data.get("series") or []
        atk = self.data.get("attack") or []
        if not series:
            self.canvas.create_text(w / 2, h / 2, text="无时间数据", fill=DIM, font=F_UI_S)
            return
        padL, padR, padT, padB = 48, 12, 14, 22
        iw, ih = w - padL - padR, h - padT - padB
        mx = max(v for _, v in series) or 1
        t0, t1 = series[0][0], series[-1][0]
        if t1 == t0:
            t1 = t0 + 1
        # 数据极不均衡（如集中爆发）时用对数刻度，否则小值会被压成一条线
        vals = sorted(v for _, v in series if v > 0)
        med = vals[len(vals) // 2] if vals else 1
        use_log = mx > med * 20
        f = (lambda v: math.log10(v + 1)) if use_log else (lambda v: v)
        fmax = f(mx) or 1
        X = lambda t: padL + (t - t0) / (t1 - t0) * iw
        Y = lambda v: padT + ih - (f(v) / fmax) * ih

        # 网格 + Y 轴刻度
        if use_log:
            ticks = [0]
            p = 1
            while 10 ** p <= mx:
                ticks.append(10 ** p)
                p += 1
        else:
            ticks = [mx * k / 4 for k in range(5)]
        for v in ticks:
            y = Y(v)
            self.canvas.create_line(padL, y, w - padR, y, fill="#21262d")
            self.canvas.create_text(padL - 6, y, text=f"{int(v):,}", fill=DIM, anchor="e",
                                    font=F_MONO_S)
        if use_log:
            self.canvas.create_text(w - padR, padT - 2, text="对数刻度", fill=DIM, anchor="se",
                                    font=F_UI_S)

        # 面积 + 折线（总请求）：数据点稀疏时不能跨空洞连线，否则会画出误导性斜线
        step = self.data.get("step") or 1
        gap = step * 3

        def segments(items):
            out, cur = [], []
            for t, v in items:
                if cur and t - cur[-1][0] > gap:
                    out.append(cur)
                    cur = []
                cur.append((t, v))
            if cur:
                out.append(cur)
            return out

        segs = segments(series)
        for seg in segs:
            pts = []
            for t, v in seg:
                pts += [X(t), Y(v)]
            if len(seg) >= 2:
                self.canvas.create_polygon(*(pts + [X(seg[-1][0]), padT + ih,
                                                    X(seg[0][0]), padT + ih]),
                                           fill="#0d2230", outline="")
                self.canvas.create_line(*pts, fill=ACC, width=1.6)
            else:
                self.canvas.create_oval(pts[0] - 2.2, pts[1] - 2.2, pts[0] + 2.2, pts[1] + 2.2,
                                        fill=ACC, outline="")
        # 告警序列
        if atk:
            for seg in segments(atk):
                apts = []
                for t, v in seg:
                    apts += [X(t), Y(v)]
                if len(seg) >= 2:
                    self.canvas.create_line(*apts, fill="#ef4444", width=1.4)
                else:
                    self.canvas.create_oval(apts[0] - 2.6, apts[1] - 2.6, apts[0] + 2.6,
                                            apts[1] + 2.6, fill="#ef4444", outline="")

        # X 轴（首尾对齐避免被裁）
        for k in range(5):
            t = t0 + (t1 - t0) * k / 4
            self.canvas.create_text(X(t), h - 9,
                                    text=datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S"),
                                    fill=DIM, font=F_MONO_S,
                                    anchor="w" if k == 0 else ("e" if k == 4 else "center"))
        # 图例
        self.canvas.create_line(w - 148, padT, w - 134, padT, fill=ACC, width=2)
        self.canvas.create_text(w - 130, padT, text="总请求", fill=MUT, anchor="w", font=F_UI_S)
        self.canvas.create_line(w - 76, padT, w - 62, padT, fill="#ef4444", width=2)
        self.canvas.create_text(w - 58, padT, text="告警", fill=MUT, anchor="w", font=F_UI_S)

    # ---- 环形：攻击类型 ----
    def _draw_donut(self, w, h):
        items = self.data or []
        if not items:
            self.canvas.create_text(w / 2, h / 2, text="无告警", fill=DIM, font=F_UI_S)
            return
        total = sum(v for _, v, _ in items) or 1
        cx, cy = w * 0.34, h / 2
        r = min(w * 0.30, h * 0.42)
        r2 = r * 0.58
        start = 90.0
        for label, v, color in items:
            ext = -360.0 * v / total
            self.canvas.create_arc(cx - r, cy - r, cx + r, cy + r, start=start, extent=ext,
                                   fill=color, outline=CARD, width=1.5)
            start += ext
        self.canvas.create_oval(cx - r2, cy - r2, cx + r2, cy + r2, fill=CARD, outline=CARD)
        self.canvas.create_text(cx, cy - 6, text=f"{total:,}", fill=FG, font=F_UI_B)
        self.canvas.create_text(cx, cy + 10, text="告警", fill=MUT, font=F_UI_S)
        # 图例
        lx = cx + r + 18
        ly = cy - min(len(items), 8) * 9
        for i, (label, v, color) in enumerate(items[:8]):
            y = ly + i * 18
            self.canvas.create_rectangle(lx, y - 4, lx + 8, y + 4, fill=color, outline="")
            self.canvas.create_text(lx + 13, y, text=f"{label} {v:,}", fill="#c9d1d9",
                                    anchor="w", font=F_UI_S)

    # ---- 竖柱：状态码 ----
    def _draw_bar(self, w, h):
        items = self.data or []
        if not items:
            self.canvas.create_text(w / 2, h / 2, text="无数据", fill=DIM, font=F_UI_S)
            return
        padL, padR, padT, padB = 12, 12, 22, 22
        iw, ih = w - padL - padR, h - padT - padB
        mx = max(v for _, v in items) or 1
        bw = iw / max(len(items), 1)
        for i, (label, v) in enumerate(items[:10]):
            bh = max(1, v / mx * ih)
            x0 = padL + i * bw + bw * 0.18
            x1 = x0 + bw * 0.64
            y0 = padT + ih - bh
            color = ("#22c55e" if str(label).startswith("2") else
                     "#eab308" if str(label).startswith("3") else
                     "#f97316" if str(label).startswith("4") else "#ef4444")
            self.canvas.create_rectangle(x0, y0, x1, padT + ih, fill=color, outline="")
            self.canvas.create_text((x0 + x1) / 2, max(y0 - 7, 9), text=f"{v:,}", fill="#c9d1d9",
                                    font=F_MONO_S)
            self.canvas.create_text((x0 + x1) / 2, h - 9, text=str(label), fill=MUT, font=F_MONO_S)

    # ---- 横条：Top IP ----
    def _draw_hbar(self, w, h):
        items = self.data or []
        if not items:
            self.canvas.create_text(w / 2, h / 2, text="无数据", fill=DIM, font=F_UI_S)
            return
        n = min(len(items), 9)
        rowH = (h - 14) / n
        mx = max(v for _, v in items[:n]) or 1
        labelW = min(150, w * 0.36)
        for i, (label, v) in enumerate(items[:n]):
            y = 7 + i * rowH
            bw = max(2, (w - labelW - 62) * v / mx)
            self.canvas.create_text(4, y + rowH / 2 - 1, text=str(label)[:26], fill=MUT,
                                    anchor="w", font=F_MONO_S)
            self.canvas.create_rectangle(labelW, y + rowH * 0.24, labelW + bw,
                                         y + rowH * 0.76, fill="#ef4444", outline="")
            self.canvas.create_text(labelW + bw + 5, y + rowH / 2 - 1, text=f"{v:,}",
                                    fill="#c9d1d9", anchor="w", font=F_MONO_S)


class App(tk.Tk):
    def __init__(self, initial=None):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VER} — {APP_SUB}")
        # 按「工作区」而不是整屏来定尺寸/位置，否则在 1366x768 这类小屏上
        # 窗口底部会被任务栏压住（状态栏看不见）。
        wa = _work_area()
        if wa:
            ax, ay, aw, ah = wa[0], wa[1], wa[2] - wa[0], wa[3] - wa[1]
        else:
            ax, ay = 0, 0
            aw, ah = self.winfo_screenwidth(), self.winfo_screenheight()
        margin = 8
        avail_h = max(480, ah - margin * 2)
        border_h = 40                      # 标题栏 + 边框的粗略补偿
        w = max(900, min(1330, aw - margin * 2))
        h = max(520, min(880, avail_h - border_h))
        x = ax + max(0, (aw - w) // 2)
        y = ay + max(0, (avail_h - h - border_h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(min(1000, max(880, aw - 60)), min(640, max(520, avail_h - border_h)))
        self.configure(bg=BG)
        self.result = None
        self.paths = []
        self._q = queue.Queue()
        self._busy = False
        self._gen = 0              # 分析代次，用于丢弃过期结果
        self._closing = False
        self.alerts_filtered = []
        self._init_style()
        self._build()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        if initial:
            self.paths = list(initial)
            self.after(200, self.run_analysis)

    def _on_close(self):
        self._closing = True
        try:
            self.pb.stop()
        except Exception:
            pass
        self.destroy()

    # ---------- 样式 ----------
    def _init_style(self):
        # DPI 感知已在 main() 里提前设置；这里再兜底一次，并据此缩放字体
        enable_dpi_awareness()
        try:
            scale = max(1.0, min(1.6, self.winfo_fpixels("1i") / 96.0))
        except Exception:
            scale = 1.0
        _rescale_fonts(scale)
        self.scale = scale
        st = ttk.Style(self)
        try:
            st.theme_use("clam")
        except tk.TclError:
            pass
        st.configure(".", background=BG, foreground=FG, font=F_UI,
                     fieldbackground=CARD, bordercolor=LINE)
        st.configure("TFrame", background=BG)
        st.configure("Card.TFrame", background=CARD, relief="flat")
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Muted.TLabel", background=BG, foreground=MUT, font=F_UI_S)
        st.configure("Card.TLabel", background=CARD, foreground=MUT, font=F_UI_S)
        st.configure("TButton", background="#21262d", foreground="#c9d1d9",
                     bordercolor=LINE, padding=(11, 5), relief="flat", font=F_UI)
        st.map("TButton", background=[("active", "#2d333b"), ("disabled", "#161b22")],
               foreground=[("disabled", DIM)])
        st.configure("Accent.TButton", background="#1f6feb", foreground="#ffffff",
                     bordercolor="#1f6feb")
        st.map("Accent.TButton", background=[("active", "#388bfd")])
        st.configure("TCombobox", fieldbackground="#0b0f14", background="#21262d",
                     foreground=FG, arrowcolor=MUT, bordercolor=LINE, padding=(6, 3))
        st.map("TCombobox", fieldbackground=[("readonly", "#0b0f14")],
               foreground=[("readonly", FG)])
        st.configure("TEntry", fieldbackground="#0b0f14", foreground=FG, bordercolor=LINE,
                     insertcolor=FG, padding=(6, 3))
        st.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 6, 0, 0))
        st.configure("TNotebook.Tab", background="#161b22", foreground=MUT,
                     padding=(16, 7), font=F_UI, borderwidth=0)
        st.map("TNotebook.Tab", background=[("selected", "#0d1117")],
               foreground=[("selected", ACC)], expand=[("selected", (0, 0, 0, 1))])
        st.configure("Treeview", background=CARD, fieldbackground=CARD, foreground="#c9d1d9",
                     rowheight=int(23 * scale), borderwidth=0, font=F_UI_S)
        st.configure("Treeview.Heading", background=CARD2, foreground=MUT,
                     font=F_UI_S, relief="flat", padding=(6, 5))
        st.map("Treeview.Heading", background=[("active", "#1b222c")])
        st.map("Treeview", background=[("selected", SEL)], foreground=[("selected", "#ffffff")])
        st.configure("TProgressbar", background=ACC, troughcolor=CARD,
                     bordercolor=LINE, lightcolor=ACC, darkcolor=ACC)
        st.configure("Vertical.TScrollbar", background="#21262d", troughcolor=BG,
                     bordercolor=BG, arrowcolor=MUT)
        st.configure("Horizontal.TScrollbar", background="#21262d", troughcolor=BG,
                     bordercolor=BG, arrowcolor=MUT)
        st.configure("TPanedwindow", background=BG)
        # 下拉列表配色
        self.option_add("*TCombobox*Listbox.background", CARD)
        self.option_add("*TCombobox*Listbox.foreground", FG)
        self.option_add("*TCombobox*Listbox.selectBackground", SEL)

    # ---------- 布局 ----------
    def _build(self):
        # ---------- 第一行：品牌 + 主操作 + 导出 ----------
        bar = ttk.Frame(self, padding=(12, 8, 12, 2))
        bar.pack(fill="x")
        tk.Label(bar, text=APP_NAME, bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 12, "bold")).pack(side="left")
        tk.Label(bar, text="v" + APP_VER, bg=CARD, fg=ACC, font=F_UI_S,
                 padx=6, pady=1).pack(side="left", padx=(8, 16))

        ttk.Button(bar, text="打开日志…", style="Accent.TButton",
                   command=self.open_files).pack(side="left")
        ttk.Button(bar, text="重新分析", command=self.run_analysis).pack(side="left", padx=(6, 0))
        ttk.Button(bar, text="清空", command=self.clear_all).pack(side="left", padx=(6, 0))

        self.mb_export = ttk.Menubutton(bar, text="导出报告 ▾")
        menu = tk.Menu(self.mb_export, tearoff=0, bg=CARD, fg=FG,
                       activebackground=SEL, activeforeground="#fff", bd=0, font=F_UI)
        menu.add_command(label="导出 HTML 报告…", command=lambda: self.do_export("html"))
        menu.add_command(label="导出告警明细 CSV…", command=lambda: self.do_export("csv"))
        menu.add_command(label="导出结构化 JSON…", command=lambda: self.do_export("json"))
        menu.add_separator()
        menu.add_command(label="复制全部告警到剪贴板", command=self.copy_all_alerts)
        self.mb_export["menu"] = menu
        self.mb_export.pack(side="right")
        ttk.Button(bar, text="快捷键", width=0,
                   command=self._show_help).pack(side="right", padx=(0, 6))

        # ---------- 第二行：筛选条（拆出来避免窄屏挤成一团）----------
        fb = ttk.Frame(self, padding=(12, 4, 12, 6))
        fb.pack(fill="x")

        tk.Label(fb, text="类型", bg=BG, fg=MUT, font=F_UI_S).pack(side="left")
        self.cb_type = ttk.Combobox(fb, width=13, state="readonly",
                                    values=["自动识别", "Apache/Nginx 访问日志", "IIS W3C 日志"])
        self.cb_type.current(0)
        self.cb_type.pack(side="left", padx=(4, 12))
        self.cb_type.bind("<<ComboboxSelected>>", lambda e: self.run_analysis())

        tk.Label(fb, text="级别", bg=BG, fg=MUT, font=F_UI_S).pack(side="left")
        self.cb_sev = ttk.Combobox(fb, width=7, state="readonly",
                                   values=["全部", "严重", "高危", "中危", "低危", "信息"])
        self.cb_sev.current(0)
        self.cb_sev.pack(side="left", padx=(4, 10))
        self.cb_sev.bind("<<ComboboxSelected>>", lambda e: self.fill_alerts())

        # 快捷筛选胶囊（和上面的级别下拉是叠加关系）
        self.alert_mode = "all"
        self._chips = {}
        for key, label in (("all", "全部"), ("succ", "疑似成功"),
                           ("weak", "待确认"), ("high", "高危以上")):
            chip = tk.Label(fb, text=label, bg=CARD, fg=MUT, font=F_UI_S,
                            padx=9, pady=2, cursor="hand2",
                            highlightbackground=LINE, highlightthickness=1)
            chip.pack(side="left", padx=(0, 4))
            chip.bind("<Button-1>", lambda e, k=key: self._set_alert_mode(k))
            self._chips[key] = chip
        self._set_alert_mode("all", redraw=False)

        tk.Label(fb, text="搜索", bg=BG, fg=MUT, font=F_UI_S).pack(side="left", padx=(10, 0))
        self.var_q = tk.StringVar()
        self.ent_q = ttk.Entry(fb, textvariable=self.var_q, width=26)
        self.ent_q.pack(side="left", padx=(4, 4))
        self.ent_q.bind("<KeyRelease>", self._on_search_key)

        self.lbl_filter_hint = tk.Label(fb, text="", bg=BG, fg=DIM, font=F_UI_S)
        self.lbl_filter_hint.pack(side="right")

        # KPI 行（可点击：数字卡跳到对应页/筛选）
        self.kpi_row = ttk.Frame(self, padding=(12, 0, 12, 8))
        self.kpi_row.pack(fill="x")
        self.kpi_widgets = []
        specs = [("n", "请求总数", "info"), ("ips", "独立客户端 IP", "info"),
                 ("atkip", "攻击 IP", "high"), ("succ", "高置信成功", "critical"),
                 ("weak", "待确认", "medium"), ("blocked", "被拦截(401/403)", "medium"),
                 ("bad", "解析异常行", "low")]
        kpi_jump = {"succ": "succ", "weak": "weak", "atkip": "all", "blocked": "all"}
        for key, label, cls in specs:
            f = tk.Frame(self.kpi_row, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            f.pack(side="left", fill="x", expand=True, padx=(0, 8))
            v = tk.Label(f, text="—", bg=CARD, fg=SEV_COLOR.get(cls, FG), font=F_VAL)
            v.pack(anchor="w", padx=12, pady=(7, 0))
            l = tk.Label(f, text=label, bg=CARD, fg=MUT, font=F_UI_S)
            l.pack(anchor="w", padx=12, pady=(0, 7))
            self.kpi_widgets.append((key, v, cls))
            if key in kpi_jump:
                for w in (f, v, l):
                    w.configure(cursor="hand2")
                    w.bind("<Button-1>", lambda e, k=kpi_jump[key]: self._jump_alert_tab(k))

        # 状态栏：必须在 Notebook 之前 pack，否则 Notebook 的 expand 会把它挤成 0 高
        st = ttk.Frame(self, padding=(12, 3, 12, 3))
        st.pack(fill="x", side="bottom")
        self.pb = ttk.Progressbar(st, mode="indeterminate", length=120)
        self.pb.pack(side="right", padx=(8, 0))
        self.lbl_status = tk.Label(st, text="就绪 — 点击「打开日志…」导入 access.log", bg=BG,
                                   fg=MUT, font=F_UI_S, anchor="w")
        self.lbl_status.pack(side="left", fill="x", expand=True)

        # 主体：Notebook
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.tab_over = ttk.Frame(self.nb, padding=10)
        self.tab_prof = ttk.Frame(self.nb, padding=10)
        self.tab_alert = ttk.Frame(self.nb, padding=10)
        self.tab_time = ttk.Frame(self.nb, padding=10)
        self.tab_concl = ttk.Frame(self.nb, padding=10)
        self.tab_rule = ttk.Frame(self.nb, padding=10)
        self.nb.add(self.tab_over, text="  概览  ")
        self.nb.add(self.tab_prof, text="  攻击者画像  ")
        self.nb.add(self.tab_alert, text="  告警明细  ")
        self.nb.add(self.tab_time, text="  时间线  ")
        self.nb.add(self.tab_concl, text="  结论与 IOC  ")
        self.nb.add(self.tab_rule, text="  规则说明  ")
        self._build_overview()
        self._build_profiles()
        self._build_alerts()
        self._build_timeline()
        self._build_conclusions()
        self._build_rules()

        self._bind_shortcuts()

    # ---------- 交互辅助 ----------
    def _bind_shortcuts(self):
        def bind(seq, fn):
            try:
                self.bind_all(seq, fn)
            except Exception:
                pass

        bind("<Control-o>", lambda e: self.open_files())
        bind("<Control-O>", lambda e: self.open_files())
        bind("<F5>", lambda e: self.run_analysis())
        bind("<Control-e>", lambda e: self.do_export("html"))
        bind("<Control-E>", lambda e: self.do_export("html"))
        bind("<Control-f>", lambda e: self._focus_search())
        bind("<Control-F>", lambda e: self._focus_search())
        bind("<Escape>", self._on_escape)
        for i in range(6):
            bind(f"<Control-Key-{i + 1}>", lambda e, idx=i: self.nb.select(idx))

    def _focus_search(self):
        self.nb.select(2)
        self.ent_q.focus_set()
        self.ent_q.selection_range(0, "end")

    def _on_escape(self, event=None):
        if self.var_q.get():
            self.var_q.set("")
            self.fill_alerts()
        elif self.alert_mode != "all":
            self._set_alert_mode("all")
        elif self.cb_sev.current() != 0:
            self.cb_sev.current(0)
            self.fill_alerts()

    def _on_search_key(self, event):
        if event.keysym in ("Return", "KP_Enter"):
            if getattr(self, "_search_tid", None):
                try:
                    self.after_cancel(self._search_tid)
                except Exception:
                    pass
                self._search_tid = None
            self.fill_alerts()
            return
        # 输入防抖：每敲一键就重扫全部记录会卡，延迟 220ms 再筛
        if getattr(self, "_search_tid", None):
            try:
                self.after_cancel(self._search_tid)
            except Exception:
                pass
        self._search_tid = self.after(220, self.fill_alerts)

    def _set_alert_mode(self, key, redraw=True):
        self.alert_mode = key
        for k, w in getattr(self, "_chips", {}).items():
            on = (k == key)
            w.configure(bg=SEL if on else CARD,
                        fg="#ffffff" if on else MUT,
                        highlightbackground=SEL if on else LINE)
        if redraw and getattr(self, "result", None) is not None:
            self.fill_alerts()

    def _jump_alert_tab(self, mode):
        if self.result is None:
            self.lbl_status.configure(text="还没有分析结果，先打开日志吧（Ctrl+O）")
            return
        self._set_alert_mode(mode, redraw=False)
        self.nb.select(2)
        self.fill_alerts()

    def _show_help(self):
        messagebox.showinfo(
            "快捷键与用法",
            "Ctrl+O    打开日志\n"
            "F5        重新分析\n"
            "Ctrl+E    导出 HTML 报告\n"
            "Ctrl+F    聚焦搜索框\n"
            "Esc       清空搜索 / 复位筛选\n"
            "Ctrl+1~6  切换页签\n\n"
            "提示：\n"
            "· 双击告警行 → 看原始日志与命中规则\n"
            "· 双击画像行 → 按该 IP 下钻\n"
            "· 点 KPI 卡片 → 跳到对应筛选\n"
            "· 点表头 → 排序（数字列按数值排）")

    def copy_all_alerts(self):
        if not self.result:
            messagebox.showinfo("提示", "请先分析日志")
            return
        rows = getattr(self, "alerts_filtered", [])
        if not rows:
            messagebox.showinfo("提示", "当前筛选下没有告警可复制")
            return
        lines = ["时间\t级别\t来源IP\t方法\tURI\t状态\t类别\t规则\t命中值"]
        for top, r in rows[:20000]:
            lines.append("\t".join([
                _ft(r.ts), SEV_LABEL.get(top.sev, top.sev), r.ip, r.method, r.uri[:300],
                str(r.status), CAT_LABEL.get(top.cat, top.cat), top.name, top.value[:200]]))
        self._copy("\n".join(lines))
        self.lbl_status.configure(text=f"已复制 {min(len(rows), 20000):,} 条告警到剪贴板")

    def _zebra(self, tv):
        """隔行底色，长表格更好跟行。"""
        for i, iid in enumerate(tv.get_children("")):
            tv.item(iid, tags=("odd" if i % 2 else "even",))


    # ---------- 概览页 ----------
    def _build_overview(self):
        info = tk.Frame(self.tab_over, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        info.pack(fill="x", pady=(0, 10))
        self.lbl_info = tk.Label(
            info, text="尚未加载日志。\n支持 Apache/Nginx 的 combined、common 格式与 IIS W3C 日志；"
                       "也可直接选择 .gz / .zip 压缩包。",
            bg=CARD, fg=MUT, font=F_UI_S, justify="left", anchor="w")
        self.lbl_info.pack(fill="x", padx=12, pady=9)

        grid = tk.Frame(self.tab_over, bg=BG)
        grid.pack(fill="both", expand=True)
        grid.columnconfigure(0, weight=3)
        grid.columnconfigure(1, weight=2)
        grid.rowconfigure(0, weight=1)
        grid.rowconfigure(1, weight=1)

        def card(parent, title, kind, r, c, cs=1, height=200):
            f = tk.Frame(parent, bg=CARD, highlightbackground=LINE, highlightthickness=1)
            f.grid(row=r, column=c, columnspan=cs, sticky="nsew", padx=(0, 8), pady=(0, 8))
            tk.Label(f, text=title, bg=CARD, fg="#c9d1d9", font=F_UI_S, anchor="w").pack(
                fill="x", padx=10, pady=(7, 0))
            ch = Chart(f, kind, height)          # canvas 必须挂在卡片内部
            ch.widget().pack(fill="both", expand=True, padx=6, pady=(2, 6))
            return ch

        self.ch_line = card(grid, "请求量趋势（蓝=总请求，红=告警请求）", "line", 0, 0)
        self.ch_donut = card(grid, "攻击类型分布", "donut", 0, 1)
        self.ch_bar = card(grid, "状态码分布", "bar", 1, 0)
        self.ch_ip = card(grid, "攻击命中 TOP IP", "hbar", 1, 1)

    # ---------- 攻击者画像 ----------
    def _build_profiles(self):
        cols = [("ip", "来源 IP", 140, "w"), ("n", "请求", 56, "e"), ("hits", "命中", 56, "e"),
                ("succ", "疑似成功", 62, "center"), ("pend", "待确认", 56, "center"),
                ("blocked", "拦截", 56, "e"), ("sev", "最高级别", 62, "center"),
                ("cats", "攻击类型", 200, "w"), ("status", "状态码", 130, "w"),
                ("ua", "User-Agent（Top1）", 210, "w"), ("time", "首次 ~ 末次", 200, "w")]
        self.tv_prof = self._make_tree(self.tab_prof, cols,
                                       numeric=("n", "hits", "succ", "pend", "blocked"))
        self.tv_prof.bind("<Double-1>", lambda e: self._drill_ip())

        foot = tk.Frame(self.tab_prof, bg=BG)
        foot.pack(fill="x", pady=(6, 0))
        tk.Label(foot, text="双击某行 → 查看该 IP 的全部命中请求；表头可排序",
                 bg=BG, fg=DIM, font=F_UI_S).pack(side="left")

    def _make_tree(self, parent, cols, height=20, numeric=()):
        numeric = set(numeric)
        frame = tk.Frame(parent, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        frame.pack(fill="both", expand=True)
        keys = [c[0] for c in cols]
        tv = ttk.Treeview(frame, columns=keys, show="headings", height=height)
        for k, label, w, anchor in cols:
            tv.heading(k, text=label,
                       command=lambda kk=k, nu=(k in numeric): self._sort_tree(tv, kk, nu))
            tv.column(k, width=w, anchor=anchor, stretch=(k in ("cats", "ua", "time")))
        tv.tag_configure("odd", background="#12171f")
        tv.tag_configure("even", background=CARD)
        vs = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        hs = ttk.Scrollbar(frame, orient="horizontal", command=tv.xview)
        tv.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        tv.grid(row=0, column=0, sticky="nsew")
        vs.grid(row=0, column=1, sticky="ns")
        hs.grid(row=1, column=0, sticky="ew")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tv

    def _sort_tree(self, tv, col, numeric=False):
        items = [(tv.set(k, col), k) for k in tv.get_children("")]
        prev = getattr(tv, "_desc_" + col, None)
        # 数字列第一次点按降序（最大值在前），文本列第一次按升序
        desc = bool(numeric) if prev is None else (not prev)
        setattr(tv, "_desc_" + col, desc)

        def as_num(t):
            try:
                return float(str(t[0]).replace(",", "").replace("+", "").strip() or 0)
            except ValueError:
                return float("-inf")

        if numeric:
            items.sort(key=as_num, reverse=desc)
        else:
            items.sort(key=lambda t: str(t[0]).lower(), reverse=desc)
        for idx, (_, k) in enumerate(items):
            tv.move(k, "", idx)
        self._zebra(tv)

    # ---------- 告警明细 ----------
    def _build_alerts(self):
        top = tk.Frame(self.tab_alert, bg=BG)
        top.pack(fill="x", pady=(0, 6))
        self.lbl_alert_cnt = tk.Label(top, text="", bg=BG, fg=MUT, font=F_UI_S)
        self.lbl_alert_cnt.pack(side="left")
        tk.Label(top, text="双击查看原始日志行", bg=BG, fg=DIM, font=F_UI_S).pack(side="right")
        # 重要列靠前，避免在 1366 宽屏上需要横向滚动才能看到“判定”
        cols = [("t", "时间", 132, "w"), ("sev", "级别", 56, "center"),
                ("judge", "判定", 70, "center"), ("ip", "来源 IP", 116, "w"),
                ("m", "方法", 52, "center"), ("uri", "URI", 340, "w"),
                ("st", "状态", 46, "center"), ("sz", "字节", 56, "e"),
                ("cat", "类别", 82, "w"), ("rule", "命中规则", 170, "w"),
                ("val", "命中值", 220, "w")]
        self.tv_alert = self._make_tree(self.tab_alert, cols, numeric=("st", "sz"))
        self.tv_alert.bind("<Double-1>", lambda e: self._show_raw())

    # ---------- 时间线 ----------
    def _build_timeline(self):
        info = tk.Frame(self.tab_time, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        info.pack(fill="x", pady=(0, 8))
        self.txt_chain = tk.Text(info, height=7, bg=CARD, fg="#c9d1d9", font=F_UI_S,
                                 relief="flat", wrap="word", bd=0, padx=10, pady=8,
                                 insertbackground=FG)
        self.txt_chain.pack(fill="x")
        self.txt_chain.configure(state="disabled")
        cols = [("t", "时间", 140, "w"), ("sev", "级别", 62, "center"),
                ("cat", "类别", 92, "w"), ("ip", "来源 IP", 128, "w"),
                ("m", "方法", 60, "center"), ("uri", "URI", 560, "w"),
                ("st", "状态", 55, "center"), ("rule", "规则", 220, "w")]
        self.tv_time = self._make_tree(self.tab_time, cols, numeric=("st",))
        self.tv_time.bind("<Double-1>", lambda e: self._show_raw(from_tree=self.tv_time))

    # ---------- 结论与 IOC ----------
    def _build_conclusions(self):
        pw = ttk.Panedwindow(self.tab_concl, orient="vertical")
        pw.pack(fill="both", expand=True)
        self.pw_concl = pw
        top = tk.Frame(pw, bg=CARD, highlightbackground=LINE, highlightthickness=1)
        txt_wrap = tk.Frame(top, bg=CARD)
        txt_wrap.pack(fill="both", expand=True)
        # height 必须显式给一个较小的值：tk.Text 默认 24 行，
        # 会把 Panedwindow 的初始空间几乎吃光，下面 IOC 表只剩一条缝。
        self.txt_concl = tk.Text(txt_wrap, bg=CARD, fg="#c9d1d9", font=F_UI, relief="flat",
                                 wrap="word", bd=0, padx=14, pady=10, insertbackground=FG,
                                 spacing1=2, spacing3=4, height=9)
        vs = ttk.Scrollbar(txt_wrap, orient="vertical", command=self.txt_concl.yview)
        self.txt_concl.configure(yscrollcommand=vs.set)
        self.txt_concl.pack(side="left", fill="both", expand=True)
        vs.pack(side="right", fill="y")
        self.txt_concl.configure(state="disabled")
        for sev in ("critical", "high", "medium", "low", "info"):
            self.txt_concl.tag_configure("h_" + sev, foreground=SEV_COLOR[sev],
                                         font=("Microsoft YaHei UI", 10, "bold"),
                                         spacing1=8, spacing3=3)
        self.txt_concl.tag_configure("body", foreground="#a9b4c0")
        self.txt_concl.tag_configure("ev", foreground="#8b949e", font=F_MONO_S,
                                     lmargin1=18, lmargin2=18)
        pw.add(top, weight=3)

        bot = tk.Frame(pw, bg=BG)
        bar = tk.Frame(bot, bg=BG)
        bar.pack(fill="x", pady=(8, 4))
        tk.Label(bar, text="IOC 清单", bg=BG, fg=FG, font=F_UI_B).pack(side="left")
        ttk.Button(bar, text="复制全部", command=lambda: self._copy_ioc(False)).pack(
            side="right", padx=(6, 0))
        ttk.Button(bar, text="复制选中", command=lambda: self._copy_ioc(True)).pack(side="right")
        cols = [("cat", "类别", 170, "w"), ("val", "值", 900, "w")]
        self.tv_ioc = self._make_tree(bot, cols, height=9)
        pw.add(bot, weight=2)
        # 窗口映射后再定分割线，避免初始按 Text 请求高度把 IOC 表压扁
        self.after(150, self._init_concl_sash)

    def _init_concl_sash(self):
        try:
            h = self.pw_concl.winfo_height()
            if h > 200:
                self.pw_concl.sashpos(0, int(h * 0.58))
        except Exception:
            pass

    # ---------- 规则页 ----------
    def _build_rules(self):
        top = tk.Frame(self.tab_rule, bg=BG)
        top.pack(fill="x", pady=(0, 6))
        tk.Label(top, text="规则即判定标准：命中规则 → 计算级别 → 结合状态码/响应大小/耗时判定成功与否。"
                           "可在源码 RULES 列表中增删。",
                 bg=BG, fg=MUT, font=F_UI_S, anchor="w").pack(side="left")
        self.var_rule_q = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.var_rule_q, width=20)
        ent.pack(side="right")
        ent.bind("<KeyRelease>", lambda e: self._fill_rules())
        tk.Label(top, text="过滤规则", bg=BG, fg=MUT, font=F_UI_S).pack(side="right", padx=(0, 5))

        cols = [("id", "编号", 100, "w"), ("name", "规则名称", 240, "w"),
                ("cat", "类别", 100, "w"), ("sev", "级别", 70, "center"),
                ("pat", "匹配模式（正则）", 560, "w"), ("desc", "说明", 330, "w")]
        self.tv_rule = self._make_tree(self.tab_rule, cols, height=22)
        self._fill_rules()

    def _rule_rows(self):
        rows = [(r.rid, r.name, CAT_LABEL.get(r.cat, r.cat), SEV_LABEL[r.sev], r.pattern, r.desc)
                for r in RULES]
        rows += [(rid, name, "UE/方法", SEV_LABEL[sev], "—", "非正则规则，代码内置")
                 for rid, name, sev in [
                     ("SCAN-UA", "扫描器 UA 指纹（%d 种工具）" % len(_SCANNER_UA), "medium"),
                     ("UA-001", "可疑UA-空", "medium"),
                     ("UA-002", "可疑UA-裸 Mozilla（伪造）", "medium"),
                     ("UA-003", "可疑UA-极短", "low"),
                     ("UA-004", "UA 注入 XSS 载荷", "high"),
                     ("SQLI-SLOW", "含注入特征且响应 ≥3s（盲注迹象）", "critical")]]
        rows += [(m, name, "异常方法", SEV_LABEL[sev], m, "非常规 HTTP 动词")
                 for m, (rid, name, sev) in _METHOD_RULES.items()]
        return rows

    def _fill_rules(self):
        q = self.var_rule_q.get().strip().lower()
        tv = self.tv_rule
        tv.delete(*tv.get_children(""))
        n = 0
        for row in self._rule_rows():
            if q and not any(q in str(c).lower() for c in row):
                continue
            tv.insert("", "end", values=row)
            n += 1
        self._zebra(tv)
        if q:
            self.lbl_status.configure(text=f"规则过滤「{q}」：{n} 条")

    # ================= 交互 =================
    def open_files(self):
        paths = filedialog.askopenfilenames(
            title="选择访问日志（可多选）",
            filetypes=[("日志文件", "*.log *.txt *.gz *.zip"), ("所有文件", "*.*")])
        if paths:
            self.paths = list(paths)
            self.run_analysis()

    def clear_all(self):
        self.paths = []
        self.result = None
        self._gen = getattr(self, "_gen", 0) + 1      # 让在途的分析结果作废
        self._busy = False
        try:
            self.pb.stop()
        except Exception:
            pass
        self.alerts_filtered = []
        for _, v, cls in self.kpi_widgets:
            v.configure(text="—", fg=DIM)
        for tv in (self.tv_prof, self.tv_alert, self.tv_time, self.tv_ioc):
            tv.delete(*tv.get_children(""))
        self.lbl_info.configure(text="尚未加载日志。")
        self.lbl_status.configure(text="就绪")
        if hasattr(self, "lbl_alert_cnt"):
            self.lbl_alert_cnt.configure(text="")
        if hasattr(self, "lbl_filter_hint"):
            self.lbl_filter_hint.configure(text="")
        for ch in (self.ch_line, self.ch_donut, self.ch_bar, self.ch_ip):
            ch.set_data(None)
        self.txt_concl.configure(state="normal")
        self.txt_concl.delete("1.0", "end")
        self.txt_concl.configure(state="disabled")
        self.txt_chain.configure(state="normal")
        self.txt_chain.delete("1.0", "end")
        self.txt_chain.configure(state="disabled")

    def _selected_type(self) -> str:
        i = self.cb_type.current()
        return {1: "web_apache", 2: "web_iis"}.get(i, "")

    def run_analysis(self):
        if getattr(self, "_closing", False):
            return
        if self._busy:
            self.lbl_status.configure(text="正在分析中，请稍候…")
            return
        if not self.paths:
            self.open_files()
            return
        # 本工具把整个文件读进内存解析，超大文件先提醒
        try:
            total_mb = sum(os.path.getsize(p) for p in self.paths if os.path.exists(p)) / 1048576.0
        except Exception:
            total_mb = 0
        if total_mb > 800:
            if not messagebox.askyesno(
                    "文件较大",
                    f"所选日志约 {total_mb:,.0f} MB。\n"
                    "本工具会在内存中一次性解析，超大文件可能占用数 GB 内存。\n\n"
                    "建议先 gzip 压缩（工具直接支持 .gz，读盘量小很多），或拆分后分批分析。\n"
                    "仍要继续吗？"):
                return
        self._busy = True
        self._gen = getattr(self, "_gen", 0) + 1
        gen = self._gen
        self.lbl_status.configure(text="正在解析与检测…")
        try:
            self.pb.configure(mode="indeterminate", value=0)
            self.pb.start(12)
        except Exception:
            pass
        forced = self._selected_type()
        paths = list(self.paths)
        threading.Thread(target=self._work, args=(paths, forced, gen), daemon=True).start()
        self.after(120, self._poll, gen)

    def _work(self, paths, forced, gen=None):
        try:
            res = analyze_files(paths, forced)
            self._q.put(("ok", gen, res))
        except Exception:
            self._q.put(("err", gen, traceback.format_exc()))

    def _poll(self, gen=None):
        if getattr(self, "_closing", False):
            return
        try:
            if not self.winfo_exists():
                return
        except Exception:
            return
        try:
            kind, g, payload = self._q.get_nowait()
        except queue.Empty:
            self.after(120, self._poll, gen)
            return
        if gen is not None and g is not None and g != gen:
            # 过期结果（期间点了「清空」或重新发起分析），直接丢弃
            return
        try:
            self.pb.stop()
            self.pb.configure(mode="determinate", value=0)  # 停掉后清零，否则残留一小段蓝色
        except Exception:
            pass
        self._busy = False
        if kind == "err":
            messagebox.showerror("分析失败", payload[-1500:])
            self.lbl_status.configure(text="分析失败")
            return
        self.result = payload
        self._render(payload)
        self.lbl_status.configure(
            text=f"完成 — {', '.join(i['file'] for i in payload.infos)} | "
                 f"{payload.stats.get('n', 0):,} 条记录 | "
                 f"告警 {payload.stats.get('alerts', 0):,} 条 | "
                 f"耗时 {payload.stats.get('elapsed', 0):.2f}s")

    # ================= 渲染 =================
    def _render(self, res: Result):
        st = res.stats
        if not st.get("n"):
            self.lbl_info.configure(
                text="未能从所选文件中解析出任何访问日志记录。\n"
                     + "\n".join(f"{i['file']}：{i['note']}，{i['lines']:,} 行 / 异常 {i['bad']} 行"
                                 for i in res.infos)
                     + "\n请确认是 Apache/Nginx 的 access.log 或 IIS W3C 日志（可用「类型」下拉强制指定）。")
            for key, lbl, cls in self.kpi_widgets:
                lbl.configure(text="—", fg=DIM)
            # 关键：解析失败时把旧图表/表格一起清掉，避免看到上一份文件的残留
            self.alerts_filtered = []
            for ch in (self.ch_line, self.ch_donut, self.ch_bar, self.ch_ip):
                ch.set_data(None)
            for tv in (self.tv_prof, self.tv_alert, self.tv_time, self.tv_ioc):
                tv.delete(*tv.get_children(""))
            return
        vals = {
            "n": f"{st.get('n', 0):,}",
            "ips": f"{st.get('ips', 0):,}",
            "atkip": f"{sum(1 for p in res.profiles if p['hits']):,}",
            "succ": f"{len(res.attack_success):,}",
            "weak": f"{len(res.attack_weak):,}",
            "blocked": f"{st.get('blocked', 0):,}",
            "bad": f"{st.get('bad', 0):,}",
        }
        for key, lbl, cls in self.kpi_widgets:
            lbl.configure(text=vals.get(key, "—"),
                          fg=SEV_COLOR.get(cls, FG) if vals.get(key) not in ("0", "—") else DIM)

        # 文件信息
        infos = []
        for i in res.infos:
            infos.append(f"{i['file']} — {i['note']}（置信 {i['conf']}%），"
                         f"{i['lines']:,} 行 / 异常 {i['bad']} 行")
        rng = f"{_ft(st.get('t0', 0))} ~ {_ft(st.get('t1', 0))}"
        peak = f"，峰值 {st.get('peak_sec', 0):,} 次/秒（{_ft(st.get('peak_sec_at', 0))}）"
        self.lbl_info.configure(text="\n".join(infos) + f"\n时间范围：{rng}{peak}")

        # 图表
        self.ch_line.set_data(self._line_data(res))
        cat = [(CAT_LABEL.get(c, c), n, CAT_COLOR.get(c, "#94a3b8"))
               for c, n in list(st.get("cat", {}).items())[:8]]
        self.ch_donut.set_data(cat)
        self.ch_bar.set_data(list(st.get("status", {}).items())[:10])
        self.ch_ip.set_data([(p["ip"], p["hits"]) for p in sorted(
            [p for p in res.profiles if p["hits"]], key=lambda x: -x["hits"])[:9]])

        self.fill_profiles()
        self.fill_alerts()
        self.fill_timeline(res)
        self.fill_conclusions(res)
        self.nb.select(0)

    def _line_data(self, res):
        ts = [r.ts for r in res.recs if r.ts]
        if not ts:
            return {"series": [], "attack": []}
        t0, t1 = min(ts), max(ts)
        span = max(1, t1 - t0)
        step = max(1, int(span / 80))
        total, atk = Counter(), Counter()
        for r in res.recs:
            if not r.ts:
                continue
            b = t0 + (r.ts - t0) // step * step
            total[b] += 1
            if r.alerts:
                atk[b] += 1
        return {"series": sorted(total.items()), "attack": sorted(atk.items()), "step": step}

    def fill_profiles(self):
        if not self.result:
            return
        tv = self.tv_prof
        tv.delete(*tv.get_children(""))
        for p in self.result.profiles:
            cats = "、".join(f"{CAT_LABEL.get(c, c)}×{n}" for c, n in p["cats"][:3]) or "-"
            st = " ".join(f"{k}:{v:,}" for k, v in p["status"][:3])
            tv.insert("", "end", values=(
                p["ip"] + (" (内网)" if p["private"] else ""),
                f"{p['n']:,}", f"{p['hits']:,}",
                p["succ"] if p["succ"] else "-", p.get("pend") or "-",
                f"{p['blocked']:,}" if p["blocked"] else "-",
                SEV_LABEL.get(p["sev"], "-") if p["sev"] else "-",
                cats, st, p["ua"][:56],
                _ft_span(p["first"], p["last"])))
        if not tv.get_children(""):
            tv.insert("", "end", values=("（未发现可疑来源）", "", "", "", "", "", "", "", "", "", ""))
        self._zebra(tv)

    def fill_alerts(self):
        self._search_tid = None
        if not self.result:
            return
        sev_map = {"全部": "", "严重": "critical", "高危": "high", "中危": "medium",
                   "低危": "low", "信息": "info"}
        want_sev = sev_map.get(self.cb_sev.get(), "")
        q = self.var_q.get().strip().lower()
        mode = getattr(self, "alert_mode", "all")
        rows = []
        for r in self.result.recs:
            if not r.alerts:
                continue
            top = max(r.alerts, key=lambda a: SEV_RANK.get(a.sev, 0))
            if mode == "succ" and not r.is_success:
                continue
            if mode == "weak" and not (r.weak and not r.is_success):
                continue
            if mode == "high" and SEV_RANK.get(top.sev, 0) < SEV_RANK["high"]:
                continue
            if want_sev and not any(a.sev == want_sev for a in r.alerts):
                continue
            if q and q not in (r.raw + r.ip + r.uri + r.ua).lower():
                continue
            rows.append((top, r))
        rows.sort(key=lambda t: (-SEV_RANK.get(t[0].sev, 0), t[1].ts))
        self.alerts_filtered = rows
        tv = self.tv_alert
        tv.delete(*tv.get_children(""))
        for top, r in rows[:3000]:
            judge = "疑似成功" if r.is_success else ("待确认" if r.weak else "")
            tv.insert("", "end", iid=str(id(r)), values=(
                _ft(r.ts), SEV_LABEL.get(top.sev, top.sev), judge,
                r.ip, r.method, r.uri[:260], r.status,
                f"{r.bytes:,}" if r.bytes else "-",
                CAT_LABEL.get(top.cat, top.cat), top.name, top.value[:200]))
        self._zebra(tv)
        mode_txt = {"succ": "　|　筛选：疑似成功", "weak": "　|　筛选：待确认",
                    "high": "　|　筛选：高危以上"}.get(mode, "")
        self.lbl_alert_cnt.configure(
            text=f"共 {len(rows):,} 条告警记录"
                 + (f"（显示前 3000 条）" if len(rows) > 3000 else "")
                 + f"　|　高置信成功 {len(self.result.attack_success)} 条 · "
                   f"待确认 {len(self.result.attack_weak)} 条" + mode_txt)
        if hasattr(self, "lbl_filter_hint"):
            active = (mode != "all") + bool(want_sev) + bool(q)
            self.lbl_filter_hint.configure(
                text=(f"筛选中（{active} 项条件）· Esc 复位" if active else ""),
                fg=ACC if active else DIM)

    def fill_timeline(self, res):
        tv = self.tv_time
        tv.delete(*tv.get_children(""))
        for r in res.timeline[:2000]:
            top = max(r.alerts, key=lambda a: SEV_RANK.get(a.sev, 0))
            tv.insert("", "end", iid=str(id(r)), values=(
                _ft(r.ts), SEV_LABEL.get(top.sev, top.sev), CAT_LABEL.get(top.cat, top.cat),
                r.ip, r.method, r.uri[:300], r.status, top.name))
        # 攻击链
        chain = next((c for c in res.conclusions if c.kind == "chain"), None)
        self.txt_chain.configure(state="normal")
        self.txt_chain.delete("1.0", "end")
        if chain:
            self.txt_chain.insert("end", chain.title + "\n", ("t",))
            self.txt_chain.tag_configure("t", foreground=SEV_COLOR[chain.sev],
                                         font=("Microsoft YaHei UI", 10, "bold"))
            for line in chain.ev:
                self.txt_chain.insert("end", "  " + line + "\n", ("e",))
            self.txt_chain.tag_configure("e", foreground="#a9b4c0", font=F_MONO_S)
        else:
            self.txt_chain.insert("end", "未还原出完整的攻击链（可能是零散尝试或单点扫描）。",
                                  ("t",))
            self.txt_chain.tag_configure("t", foreground=MUT, font=F_UI_S)
        self.txt_chain.configure(state="disabled")
        if not tv.get_children(""):
            tv.insert("", "end", values=("（无攻击特征记录）", "", "", "", "", "", "", ""))
        self._zebra(tv)

    def fill_conclusions(self, res):
        t = self.txt_concl
        t.configure(state="normal")
        t.delete("1.0", "end")
        if res.soft200:
            t.insert("end", "⚠ " + res.soft200_note + "\n", ("warn",))
            t.tag_configure("warn", foreground="#fdba74", spacing1=4, spacing3=8)
        for c in res.conclusions:
            t.insert("end", f"【{SEV_LABEL[c.sev]}】{c.title}\n", ("h_" + c.sev,))
            if c.text:
                t.insert("end", c.text + "\n", ("body",))
            for ev in c.ev[:20]:
                t.insert("end", "  · " + ev + "\n", ("ev",))
        if res.insights:
            t.insert("end", "\n──────────────── 聚合研判 ────────────────\n",
                     ("body",))
            for i in res.insights:
                t.insert("end", f"【{SEV_LABEL[i.sev]}】{i.title}\n", ("h_" + i.sev,))
                t.insert("end", i.text + "\n", ("body",))
                for ev in i.ev[:12]:
                    t.insert("end", "  · " + ev + "\n", ("ev",))
        t.configure(state="disabled")

        tv = self.tv_ioc
        tv.delete(*tv.get_children(""))
        ioc = res.ioc
        groups = [
            ("攻击来源 IP", ioc.get("atk_ips", [])),
            ("扫描器/工具 UA", ioc.get("scanners", [])),
            ("敏感路径（2xx）", ioc.get("sensitive_2xx", [])),
            ("典型攻击载荷", ioc.get("payloads", [])),
            ("涉及账号", ioc.get("users", [])),
        ]
        for name, items in groups:
            if not items:
                tv.insert("", "end", values=(name, "（无）"))
            for v in items:
                tv.insert("", "end", values=(name, v))
        self._zebra(tv)

    # ---------- 弹窗：原始日志 ----------
    def _show_raw(self, from_tree=None):
        tv = from_tree or self.tv_alert
        sel = tv.selection()
        if not sel or not self.result:
            return
        rid = int(sel[0])
        rec = next((r for r in self.result.recs if id(r) == rid), None)
        if not rec:
            return
        win = tk.Toplevel(self)
        win.title("原始日志 / 命中详情")
        win.geometry("980x560")
        win.configure(bg=BG)
        head = tk.Label(win, text=f"{_ft(rec.ts)}   {rec.ip}   {rec.method} {rec.uri[:120]}   "
                                  f"状态 {rec.status}   字节 {rec.bytes}   "
                                  f"{'疑似成功' if rec.is_success else ('待确认' if rec.weak else '')}",
                        bg=BG, fg=FG, font=F_UI_B, anchor="w", justify="left", wraplength=940)
        head.pack(fill="x", padx=12, pady=(10, 4))
        if rec.reason:
            tk.Label(win, text="判定依据：" + rec.reason, bg=BG, fg="#fdba74", font=F_UI_S,
                     anchor="w", wraplength=940, justify="left").pack(fill="x", padx=12)
        txt = tk.Text(win, bg=CARD, fg="#c9d1d9", font=F_MONO, relief="flat", wrap="word",
                      padx=12, pady=10)
        txt.pack(fill="both", expand=True, padx=12, pady=8)
        txt.insert("end", "【命中规则】\n")
        for a in rec.alerts:
            txt.insert("end", f"  [{SEV_LABEL.get(a.sev, a.sev)}] {a.rid} {a.name}"
                              f"  →  {a.value[:200]}\n")
        txt.insert("end", "\n【原始日志行】\n" + rec.raw + "\n")
        txt.configure(state="disabled")
        tk.Button(win, text="复制原始行", bg="#21262d", fg="#c9d1d9", relief="flat",
                  font=F_UI_S, command=lambda: self._copy(rec.raw)).pack(anchor="e",
                                                                        padx=12, pady=(0, 10))

    def _drill_ip(self):
        sel = self.tv_prof.selection()
        if not sel or not self.result:
            return
        ip = self.tv_prof.set(sel[0], "ip").split(" ")[0]
        self.var_q.set(ip)
        self.cb_sev.current(0)
        self.nb.select(2)
        self.fill_alerts()

    # ---------- 剪贴板 ----------
    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)
        self.lbl_status.configure(text="已复制到剪贴板")

    def _copy_ioc(self, only_sel):
        if not self.result:
            return
        tv = self.tv_ioc
        if only_sel:
            vals = [f"{tv.set(k, 'cat')}\t{tv.set(k, 'val')}" for k in tv.selection()]
        else:
            vals = [f"{tv.set(k, 'cat')}\t{tv.set(k, 'val')}" for k in tv.get_children("")]
        if vals:
            self._copy("\n".join(vals))

    # ---------- 导出 ----------
    def do_export(self, kind):
        if not self.result:
            messagebox.showinfo("提示", "请先分析日志")
            return
        base = os.path.splitext(os.path.basename(self.paths[0]))[0] if self.paths else "log"
        if kind == "html":
            p = filedialog.asksaveasfilename(defaultextension=".html",
                                             initialfile=f"{base}-分析报告.html",
                                             filetypes=[("HTML 报告", "*.html")])
            if p:
                export_html(self.result, p, ", ".join(self.paths))
                self._ask_open(p)
        elif kind == "csv":
            p = filedialog.asksaveasfilename(defaultextension=".csv",
                                             initialfile=f"{base}-告警明细.csv",
                                             filetypes=[("CSV", "*.csv")])
            if p:
                n = export_csv(self.result, p)
                messagebox.showinfo("导出完成", f"已导出 {n:,} 条告警到：\n{p}")
        else:
            p = filedialog.asksaveasfilename(defaultextension=".json",
                                             initialfile=f"{base}-分析结果.json",
                                             filetypes=[("JSON", "*.json")])
            if p:
                export_json(self.result, p)
                messagebox.showinfo("导出完成", f"已导出结构化结果：\n{p}")

    def _ask_open(self, path):
        if messagebox.askyesno("报告已生成", f"已生成 HTML 报告：\n{path}\n\n是否立即打开？"):
            abs_path = os.path.abspath(path)
            try:
                # as_uri 会正确转义中文/空格，直接拼 "file://" 在中文路径下会打不开
                from pathlib import Path
                uri = Path(abs_path).as_uri()
            except Exception:
                uri = "file:///" + abs_path.replace("\\", "/")
            webbrowser.open(uri)


def main():
    ap = argparse.ArgumentParser(description=f"{APP_NAME} v{APP_VER}")
    ap.add_argument("logs", nargs="*", help="启动时自动分析的日志文件")
    ap.add_argument("--html", help="无界面模式：只生成 HTML 报告后退出")
    ap.add_argument("--csv", help="无界面模式：导出告警 CSV")
    ap.add_argument("--json", help="无界面模式：导出 JSON")
    ap.add_argument("--type", default="", help="强制日志类型：web_apache / web_iis")
    a = ap.parse_args()

    if a.logs and (a.html or a.csv or a.json):
        res = analyze_files(a.logs, a.type)
        if a.html:
            export_html(res, a.html, ", ".join(a.logs))
            print("HTML 报告 →", os.path.abspath(a.html))
        if a.csv:
            n = export_csv(res, a.csv)
            print(f"CSV 告警 {n} 条 →", os.path.abspath(a.csv))
        if a.json:
            export_json(res, a.json)
            print("JSON →", os.path.abspath(a.json))
        return 0

    enable_dpi_awareness()          # 必须在创建 Tk 窗口之前
    app = App(initial=a.logs or None)
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
