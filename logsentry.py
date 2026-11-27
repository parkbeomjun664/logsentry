"""LogSentry — 표준 웹서버 접근 로그를 읽어 침입 시도를 탐지·기록하는 범용 도구.

어느 프로젝트든 남기는 '표준 접근 로그'(nginx/apache combined)만 있으면 붙는다.
대상 앱 코드를 고치지 않는다. 읽기 전용. (막기는 다음 단계)

탐지(로그로 가능한 것):
  P1 경로 탐색   한 IP 가 없는 주소(404)를 여러 번 → 탐색 스캔
  P2 인증 두드림 한 IP 가 401/403 을 여러 번 → 무차별·권한 밖
  P3 과속        한 IP 가 짧은 시간에 많은 요청 → 사람 아님
  P4 도구 지문   User-Agent 가 curl/python/scanner 등
  P5 IP 종합     위 신호를 IP 로 합산·점수화(분산·저속 공격)
  (계정 단위 스프레이·잠금은 앱 연동 단계에서)

사용:
  python logsentry.py access.log
  python logsentry.py access.log --format nginx --window 60 --probe-threshold 5
"""
from __future__ import annotations

import argparse
import base64
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta, timezone
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# Windows 콘솔(cp949 등)에서 한글·이모지 출력이 깨지거나 터지지 않도록 UTF-8 로 맞춘다.
# MES 서버도 Windows 라, 설정 파일 로드 시 이모지(⚙) 출력에서 죽는 일을 막는 안전장치.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 — 재설정이 안 되는 환경이면 조용히 넘어간다
        pass

# nginx/apache combined 로그 한 줄 파서
_NGINX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# 공격 도구 지문(User-Agent) — 구체적인 도구 이름만.
# ("bot","agent","scan" 같은 일반 조각은 Googlebot 등 정상 크롤러를 오탐해 뺐다)
_TOOL_UA = ("curl", "python-requests", "python-urllib", "wget", "go-http",
            "nikto", "sqlmap", "nmap", "masscan", "zgrab", "httpx")
# 흔한 탐침 경로(있으면 가중)
_PROBE_PATHS = ("/.env", "/.git", "/wp-login", "/wp-admin", "/phpmyadmin",
                "/admin", "/actuator", "/config", "/backup", "/.aws",
                "/server-status", "/.ssh", "/vendor", "/shell",
                # Nmap 서비스 탐지가 늘 보내는 고정 문자열(/nice ports,/Trinity.txt.bak)
                "/nice%20ports", "/nice ports")
# 정상 소음(제외)
_SKIP = ("/favicon.ico", "/robots.txt", "/health")
# 인증 실패로 볼 상태코드 — 401 비번틀림·403 권한없음·423 계정잠금(무차별의 결정적 증거).
# 서버마다 로그인 실패를 400·422 등으로 주기도 해서 설정 파일로 넓힐 수 있다.
_AUTH_STATUSES = (401, 403, 423)
# 화면에 보일 도구 이름(상황판 제목·헤더·꼬리말). 설정 "brand" 로 회사별로 바꾼다(예: InfoGuard).
_BRAND = "LogSentry"
# 화면 로고(선택) — 설정 "brand_logo" = 이미지 파일 경로 또는 data: URI. 비우면 기본 방패.
# 회사 로고는 설정 파일로만 넣는다(공개 저장소엔 안 올라감).
_BRAND_LOGO = ""
# 공격 IP 출처 조회(RDAP·역방향 이름) — 외부로 IP 를 묻는 기능이라 설정 "ip_lookup": true 일 때만 켠다
_IP_LOOKUP = False
# 신뢰 IP(회사·사내 공유 IP 등) — 경보에서 제외해 오탐을 줄인다. "192.168.10.0/24" 같은 대역도 된다.
# ⚠ 통신사(LTE) IP 는 여러 사람이 함께 쓰므로 넣지 말 것.
_TRUSTED_IPS = ()
# 로그인 경로(설정 시) — 여기서 난 401/403/423 만 '로그인 실패'로 센다. 다른 경로의 401 은
# '권한 밖 경로 훑기(정찰)'로 분류한다. 로그인 안 한 요청에 전부 401 을 주는 API 에서
# 스캐너가 '무차별 대입'으로 잘못 보이는 것을 막는다. 비어 있으면 모든 경로의 401 이 로그인 실패.
_AUTH_PATHS = ()
# 의심 요청 헤더(소문자) — 한 번만 와도 위험. Next-Action = Next.js 서버 액션 헤더,
# React2Shell(CVE-2025-55182) 류 원격 코드 실행 공격에 쓰인다. 서버 액션을 실제로 쓰는 앱이면 비울 것.
_SUSPICIOUS_HEADERS = ("next-action",)
# 표준 HTTP 메서드 — 이 밖의 메서드(EXDW 등)는 스캐너의 서버 종류 떠보기로 본다
_STD_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
# 문턱 기본값 — logsentry.json 의 "thresholds" 로 덮어쓸 수 있다
DEFAULT_THRESHOLDS = {"window": 60, "probe": 5, "auth": 5, "rate": 20,
                      "score": 6, "dist_ip": 5}


def load_config(path):
    """설정 파일(logsentry.json)이 있으면 목록·신뢰IP 를 덮어쓰고 문턱을 돌려준다.

    코드를 고치지 않고 회사마다 탐침 경로·도구 지문·신뢰 IP·문턱을 바꾸게 한다.
    파일이 없거나 읽기 실패하면 조용히 기본값을 쓴다(도구가 멈추지 않게).
    """
    global _TOOL_UA, _PROBE_PATHS, _SKIP, _TRUSTED_IPS, _AUTH_STATUSES, _AUTH_PATHS, _SUSPICIOUS_HEADERS, _BRAND, _BRAND_LOGO, _IP_LOOKUP, _SECRET_PATHS, _NOTIFY, _HEALTH
    thresholds = dict(DEFAULT_THRESHOLDS)
    thresholds["webhook"] = ""   # 알림 웹훅 주소(선택) — 설정 파일로 덮어씀
    if not path or not os.path.exists(path):
        return thresholds
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"⚠ 설정 파일 {path} 를 못 읽어 기본값으로 진행합니다: {e}")
        return thresholds
    if "tool_ua" in cfg:
        _TOOL_UA = tuple(cfg["tool_ua"])
    if "probe_paths" in cfg:
        _PROBE_PATHS = tuple(cfg["probe_paths"])
    if "skip" in cfg:
        _SKIP = tuple(cfg["skip"])
    if "trusted_ips" in cfg:
        _TRUSTED_IPS = tuple(cfg["trusted_ips"])
    if "auth_statuses" in cfg:
        _AUTH_STATUSES = tuple(cfg["auth_statuses"])
    if "auth_paths" in cfg:
        _AUTH_PATHS = tuple(cfg["auth_paths"])
    if "secret_paths" in cfg:
        _SECRET_PATHS = tuple(str(x) for x in cfg["secret_paths"])
    if "suspicious_headers" in cfg:
        _SUSPICIOUS_HEADERS = tuple(str(h).lower() for h in cfg["suspicious_headers"])
    # *_extra 키는 기본 목록을 덮지 않고 '덧붙인다' — 덮어쓰기 키 다음에 처리(기본 탐침·소음·도구 목록을 그대로 두고 한두 개만 추가할 때)
    for key, name in (("tool_ua_extra", "_TOOL_UA"), ("probe_paths_extra", "_PROBE_PATHS"), ("skip_extra", "_SKIP"),
                      ("secret_paths_extra", "_SECRET_PATHS")):
        if key in cfg:
            globals()[name] = tuple(globals()[name]) + tuple(x for x in cfg[key] if x not in globals()[name])
    if "brand" in cfg and str(cfg["brand"]).strip():
        _BRAND = str(cfg["brand"]).strip()
    if "brand_logo" in cfg:
        _BRAND_LOGO = str(cfg["brand_logo"]).strip()
    if "ip_lookup" in cfg:
        _IP_LOOKUP = bool(cfg["ip_lookup"])
    if isinstance(cfg.get("notify"), dict):          # 알림 채널(텔레그램·이메일·웹훅)·매일 요약 시각
        _NOTIFY = dict(cfg["notify"])
    if isinstance(cfg.get("health"), dict):          # 사이트 응답·로그 멈춤 감시
        _HEALTH = dict(cfg["health"])
    if "webhook" in cfg:
        thresholds["webhook"] = cfg["webhook"]
    thresholds.update(cfg.get("thresholds", {}))
    print(f"⚙ 설정 파일 {path} 적용")
    return thresholds


def parse_line(line, fmt="auto"):
    """로그 한 줄 → 공통 형태 dict. fmt 로 양식을 고르거나 auto 로 자동 감지(입구만 양식을 탄다)."""
    line = line.strip()
    if not line:
        return None
    if fmt == "json" or (fmt == "auto" and line.startswith("{")):
        return _parse_json(line)       # JSON 로그
    if fmt in ("nginx", "apache", "auto"):
        return _parse_nginx(line)      # nginx/apache combined
    return None


def _parse_nginx(line):
    m = _NGINX.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("time"), _TIME_FMT)
    except ValueError:
        ts = None
    return {
        "ip": m.group("ip"),
        "ts": ts,
        "method": m.group("method"),
        "path": m.group("path").split("?")[0],  # 쿼리스트링 제거
        "status": int(m.group("status")),
        "ua": m.group("ua"),
    }


def _parse_caddy(o):
    """Caddy 접근 로그(JSON, 값이 request 안에 겹쳐 있는 구조) → 공통 형태.

    {"ts":1764000000.12,"request":{"client_ip":..,"remote_ip":..,"method":..,"uri":..,
     "headers":{"User-Agent":["..."]}},"status":404, ...}
    client_ip 를 먼저 쓴다(신뢰 프록시 설정 시 진짜 IP), 없으면 remote_ip.
    """
    req = o.get("request") or {}
    ip = req.get("client_ip") or req.get("remote_ip")
    status = o.get("status")
    if not ip or status is None:
        return None
    headers = req.get("headers") or {}
    ua = headers.get("User-Agent") or ""
    if isinstance(ua, list):
        ua = ua[0] if ua else ""
    raw_ts = o.get("ts")
    ts = None
    try:
        if isinstance(raw_ts, (int, float)):
            ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc).astimezone()   # 유닉스 초 → 이 PC 시간대
        elif isinstance(raw_ts, str) and raw_ts:
            ts = datetime.fromisoformat(raw_ts)                                 # time_format iso8601 인 경우
    except (ValueError, OverflowError, OSError):
        ts = None
    return {
        "ip": ip,
        "ts": ts,
        "method": req.get("method") or "",
        "path": str(req.get("uri") or "").split("?")[0],
        "status": int(status),
        "ua": str(ua),
        "hdrs": tuple(str(k).lower() for k in headers),   # 헤더 이름만(값은 안 씀) — 의심 헤더 탐지용
    }


def _parse_json(line):
    try:
        o = json.loads(line)
    except ValueError:
        return None
    if not isinstance(o, dict):
        return None
    if isinstance(o.get("request"), dict):   # Caddy 접근 로그
        return _parse_caddy(o)
    # 흔한 필드 이름들을 두루 받아 준다
    ip = o.get("remote_addr") or o.get("ip") or o.get("client_ip")
    status = o.get("status")
    if not ip or status is None:
        return None
    path = o.get("uri") or o.get("path") or ""
    tstr = o.get("time") or o.get("time_iso8601") or o.get("timestamp")
    try:
        ts = datetime.fromisoformat(tstr) if tstr else None
    except ValueError:
        ts = None
    return {
        "ip": ip,
        "ts": ts,
        "method": o.get("method") or "",
        "path": str(path).split("?")[0],
        "status": int(status),
        "ua": o.get("user_agent") or o.get("http_user_agent") or "",
    }


def is_tool(ua):
    ua = (ua or "").lower()
    return any(t in ua for t in _TOOL_UA)


def is_probe_path(path):
    return any(path.startswith(p) for p in _PROBE_PATHS)


_TRUSTED_CACHE = {"key": None, "exact": frozenset(), "nets": ()}


def _is_trusted(ip):
    """신뢰 IP 인가 — 정확한 주소 또는 대역(CIDR, 예: 192.168.10.0/24)."""
    t = _TRUSTED_IPS
    if not t or not ip:
        return False
    if _TRUSTED_CACHE["key"] is not t:          # 목록이 바뀌었을 때만 다시 해석
        exact, nets = set(), []
        for x in t:
            x = str(x).strip()
            if "/" in x:
                try:
                    nets.append(ipaddress.ip_network(x, strict=False))
                except ValueError:
                    pass
            else:
                exact.add(x)
        _TRUSTED_CACHE.update(key=t, exact=frozenset(exact), nets=tuple(nets))
    if ip in _TRUSTED_CACHE["exact"]:
        return True
    if _TRUSTED_CACHE["nets"]:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in _TRUSTED_CACHE["nets"])
    return False


def _on_auth_path(path):
    return any(path.startswith(p) for p in _AUTH_PATHS)


def _is_auth_fail(e):
    """로그인 실패인가 — 로그인 경로를 지정했으면 그 경로의 401/403/423 만."""
    return e["status"] in _AUTH_STATUSES and (not _AUTH_PATHS or _on_auth_path(e["path"]))


def _is_offlimits(e):
    """권한 밖 경로 훑기 — 로그인 경로가 지정됐고, 그 밖의 경로에서 401/403/423."""
    return bool(_AUTH_PATHS) and e["status"] in _AUTH_STATUSES and not _on_auth_path(e["path"])


def _is_nf(e):
    """정찰성 실패 — 없는 주소(404) 또는 권한 밖 경로(위)."""
    return e["status"] == 404 or _is_offlimits(e)


def _odd_flags(e):
    """의심 헤더·비표준 메서드 — 한 번만 와도 의심할 요청의 특징 목록."""
    flags = []
    hdrs = e.get("hdrs") or ()
    for h in _SUSPICIOUS_HEADERS:
        if h in hdrs:
            flags.append(f"의심 헤더 {h}")
    m = (e.get("method") or "").upper()
    if m and m not in _STD_METHODS:
        flags.append(f"비표준 메서드 {m}")
    return flags


def analyze(events, window, probe_threshold, auth_threshold, rate_threshold, score_threshold):
    agg = defaultdict(lambda: {
        "reqs": 0, "nf": 0, "auth": 0, "paths": set(), "probes": 0,
        "tool": False, "first": None, "last": None, "times": [],
        "odd": 0, "odd_kinds": set(), "off": 0,
    })
    for e in events:
        if _is_trusted(e["ip"]):   # 신뢰 IP 는 경보 대상에서 제외(오탐 감소)
            continue
        if any(e["path"].startswith(s) for s in _SKIP):
            continue
        d = agg[e["ip"]]
        d["reqs"] += 1
        if _is_nf(e):              # 없는 주소 · 권한 밖 경로(정찰)
            d["nf"] += 1
            if _is_offlimits(e):
                d["off"] += 1      # 표시할 때 '없는 주소'와 나눠 보여주려고 따로 센다
        if _is_auth_fail(e):       # 로그인 실패
            d["auth"] += 1
        flags = _odd_flags(e)      # 의심 헤더 · 비표준 메서드 — 한 번만 와도 위험
        if flags:
            d["odd"] += 1
            d["odd_kinds"].update(flags)
        d["paths"].add(e["path"])
        if is_probe_path(e["path"]):
            d["probes"] += 1
        if is_tool(e["ua"]):
            d["tool"] = True
        if e["ts"]:
            d["times"].append(e["ts"])
            d["first"] = e["ts"] if d["first"] is None else min(d["first"], e["ts"])
            d["last"] = e["ts"] if d["last"] is None else max(d["last"], e["ts"])

    results = []
    for ip, d in agg.items():
        # P3 과속: window 초 안 최대 요청 수
        burst = _max_in_window(sorted(d["times"]), window)
        # P5 종합 점수
        score = (d["nf"] + 2 * d["auth"] + 2 * d["probes"]
                 + (2 if d["tool"] else 0) + (3 if burst >= rate_threshold else 0)
                 + score_threshold * d["odd"])   # 의심 헤더·메서드는 한 건으로 경보 문턱

        reasons = []
        if d["nf"] >= probe_threshold:
            nf404 = d["nf"] - d["off"]
            parts = ([f"없는 주소 {nf404}회"] if nf404 else []) + ([f"권한 밖 경로 {d['off']}회"] if d["off"] else [])
            reasons.append(" · ".join(parts))
        if d["auth"] >= auth_threshold:
            reasons.append(f"인증거부 {d['auth']}회")
        if burst >= rate_threshold:
            reasons.append(f"과속 {burst}req/{window}s")
        if d["probes"]:
            reasons.append(f"탐침경로 {d['probes']}개")
        if d["tool"]:
            reasons.append("도구 UA")
        if d["odd"]:
            reasons.append(f"의심 헤더·메서드 {d['odd']}회 ({', '.join(sorted(d['odd_kinds']))})")

        # 개별 신호가 저마다 문턱을 못 넘어도, 서로 다른 종류의 의심 신호가 '겹치고'
        # 종합 점수(P5)가 문턱을 넘으면 경보한다. 정상 사용자는 '없는 주소 뒤지기'와
        # '로그인 실패'를 함께 하지 않는다 → 종류가 겹치는 것 자체가 공격 신호다.
        # (단일 종류만으로 점수를 넘는 것은 제외 — 비번 몇 번 틀린 정상 직원 오탐 방지.)
        if not reasons:
            kinds = sum([d["nf"] > 0, d["auth"] > 0, d["probes"] > 0,
                         d["tool"], burst >= rate_threshold])
            if score >= score_threshold and kinds >= 2:
                reasons.append(f"복합 의심(종합점수 {score}, 신호 {kinds}종)")
            else:
                continue
        # '자료'만 담는다 — 화면/파일 '보여주기'는 바깥에서(fmt_screen/fmt_file)
        results.append({
            "ip": ip, "score": score,
            "level": "alert" if score >= score_threshold else "watch",
            "distinct_paths": len(d["paths"]), "nf": d["nf"], "auth": d["auth"],
            "probes": d["probes"], "tool": d["tool"], "rate": burst, "reqs": d["reqs"],
            "first": d["first"], "last": d["last"], "reasons": reasons,
        })

    results.sort(key=lambda r: -r["score"])
    return results


def _max_in_window(times, window):
    """정렬된 시각 목록에서 window 초 안에 들어오는 최대 개수."""
    if not times:
        return 0
    q = deque()
    worst = 0
    for t in times:
        q.append(t)
        while (t - q[0]).total_seconds() > window:
            q.popleft()
        worst = max(worst, len(q))
    return worst


def _max_distinct_in_window(timed_keys, window):
    """(시각, 값) 목록에서 window 초 창 안의 '서로 다른 값 최대 수'.

    창을 미끄러뜨리며(슬라이딩) 각 순간 창 안 값 종류 수를 세고 그 최댓값을 돌려준다.
    값은 IP(분산 탐지)일 수도, 계정(스프레이 탐지)일 수도 있다 — 축만 바꿔 재사용.
    Counter 로 창에 남은 값만 센다(같은 값이 여러 번이면 1로).
    """
    q = deque()
    counts = defaultdict(int)   # 창 안에 살아있는 값별 등장 횟수
    worst = 0
    for ts, key in sorted(timed_keys, key=lambda x: x[0]):   # 시각 순
        q.append((ts, key))
        counts[key] += 1
        while (ts - q[0][0]).total_seconds() > window:   # 창 밖은 버린다
            _, old = q.popleft()
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]           # 창에서 완전히 빠진 값은 종류에서 제외
        worst = max(worst, len(counts))   # 지금 창의 '서로 다른 값 수'
    return worst


def detect_distributed(events, window, ip_threshold):
    """[v2] 서버 전체 관점 — 짧은 시간창 안에 '같은 종류 공격을 낸 서로 다른 IP 수'.

    IP 별 analyze 와 보는 축이 다르다: analyze='한 IP 가 몇 번?' / 여기='한 공격을 몇 IP 가?'.
    여러 IP 로 잘게 쪼갠 분산 무차별·분산 스캔을, 한 IP 로는 조용해도 집단으로 잡는다.
    신뢰 IP 는 제외하고, 404 는 정상 소음(_SKIP) 경로를 뺀다.
    """
    auth_hits = [(e["ts"], e["ip"]) for e in events
                 if e["ts"] and not _is_trusted(e["ip"]) and _is_auth_fail(e)]
    nf_hits = [(e["ts"], e["ip"]) for e in events
               if e["ts"] and not _is_trusted(e["ip"]) and _is_nf(e)
               and not any(e["path"].startswith(s) for s in _SKIP)]
    results = []
    auth_ips = _max_distinct_in_window(auth_hits, window)
    if auth_ips >= ip_threshold:
        results.append({"kind": "분산 무차별(인증실패)", "ips": auth_ips, "window": window})
    nf_ips = _max_distinct_in_window(nf_hits, window)
    if nf_ips >= ip_threshold:
        results.append({"kind": "분산 스캔(없는 주소)", "ips": nf_ips, "window": window})
    return results


def analyze_logins(login_events, window, spray_threshold, account_threshold,
                   repeat_threshold):
    """[v2 미들웨어] 계정 차원 로그인 분석 — 접근 로그엔 없는 '계정' 신호를 본다.

    login_events: 앱 미들웨어가 넘기는 로그인 시도 목록.
        각 항목 = {"ts": datetime, "ip": str, "account": str, "success": bool}
    실패한 시도만 본다. 세 가지를 잡는다(접근 로그 P1~P6 로는 안 보이던 것):
      - 비밀번호 스프레이: 한 IP 가 window 초 안에 '서로 다른 계정' 여럿에 실패(가로)
      - 계정 집중 공격: 한 계정에 window 초 안에 '서로 다른 IP' 여럿이 실패(분산 세로)
      - 단순 무차별: 한 (IP, 계정) 조합이 window 초 안에 '반복' 실패
        (아이디는 그대로 두고 비밀번호만 바꿔 여러 번 — 가장 전형적인 로그인 공격)
    신뢰 IP 는 제외한다.
    """
    fails = [e for e in login_events
             if not e.get("success") and e.get("ts") and not _is_trusted(e.get("ip"))]
    results = []

    # 스프레이: IP 별로 '그 IP 가 노린 서로 다른 계정 수'(시간창 안 최대)
    by_ip = defaultdict(list)
    for e in fails:
        by_ip[e["ip"]].append((e["ts"], e["account"]))
    for ip, timed_accounts in by_ip.items():
        n = _max_distinct_in_window(timed_accounts, window)
        if n >= spray_threshold:
            results.append({"kind": "비밀번호 스프레이", "ip": ip,
                            "accounts": n, "window": window})

    # 집중: 계정 별로 '그 계정을 노린 서로 다른 IP 수'(시간창 안 최대)
    by_account = defaultdict(list)
    for e in fails:
        by_account[e["account"]].append((e["ts"], e["ip"]))
    for account, timed_ips in by_account.items():
        n = _max_distinct_in_window(timed_ips, window)
        if n >= account_threshold:
            results.append({"kind": "계정 집중 공격", "account": account,
                            "ips": n, "window": window})

    # 단순 무차별: (IP, 계정) 조합별 '반복 실패 횟수'(시간창 안 최대)
    by_pair = defaultdict(list)
    for e in fails:
        by_pair[(e["ip"], e["account"])].append(e["ts"])
    for (ip, account), times in by_pair.items():
        n = _max_in_window(sorted(times), window)
        if n >= repeat_threshold:
            results.append({"kind": "단순 무차별", "ip": ip, "account": account,
                            "count": n, "window": window})

    results.sort(key=lambda r: -(r.get("accounts") or r.get("ips") or r.get("count") or 0))
    return results


class LoginTracker:
    """[v2 미들웨어] 앱에 드롭인하는 계정 차원 감시기.

    접근 로그는 '어느 계정을 노렸나'를 안 남긴다. 그래서 이 감시기는 앱 안에서
    로그인 시도를 직접 받아(record) 모아 두고, 주기적으로(check) 계정 차원 공격
    (비밀번호 스프레이·계정 집중)을 점검한다. 대상 앱은 record/check 두 줄만 꽂으면 된다.

    사용 예(FastAPI):
        tracker = LoginTracker()
        # 로그인 처리 직후
        tracker.record(ip=request.client.host, account=login_id, success=ok)
        # 주기적으로(백그라운드 작업 등)
        for hit in tracker.check():
            notify(hit)     # 슬랙/메일 등

    메모리: keep_seconds 보다 오래된 시도는 버린다(무한 증가 방지).
    """

    def __init__(self, window=300, spray_threshold=5, account_threshold=5,
                 repeat_threshold=5, keep_seconds=3600):
        self.window = window                      # 분석 시간창(초)
        self.spray_threshold = spray_threshold    # 스프레이: 한 IP 가 노린 서로 다른 계정 수
        self.account_threshold = account_threshold  # 집중: 한 계정을 노린 서로 다른 IP 수
        self.repeat_threshold = repeat_threshold  # 단순 무차별: 한 (IP,계정) 반복 실패 횟수
        self.keep_seconds = keep_seconds          # 이보다 오래된 시도는 버린다
        self._events = deque()

    def record(self, ip, account, success, ts=None):
        """로그인 시도 한 건을 기록한다(앱이 로그인 처리 직후 호출)."""
        ts = ts or datetime.now(timezone.utc)
        self._events.append({"ts": ts, "ip": ip, "account": account,
                             "success": bool(success)})
        while self._events and (ts - self._events[0]["ts"]).total_seconds() > self.keep_seconds:
            self._events.popleft()                # 오래된 것 정리
        return self

    def check(self):
        """지금까지 모인 시도에서 계정 차원 공격을 점검해 결과(목록)를 돌려준다."""
        return analyze_logins(list(self._events), self.window,
                              self.spray_threshold, self.account_threshold,
                              self.repeat_threshold)


def load_events(path, fmt):
    """로그 파일을 읽어 이벤트 목록으로. (못 읽은 줄 수도 함께)"""
    events, bad = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line, fmt)
            if e:
                events.append(e)
            elif line.strip():
                bad += 1
    return events, bad


def write_alert_log(path, results):
    """경보를 ASCII key=value 로 파일에 이어 적는다."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        for r in results:
            tag = "ALERT" if r["level"] == "alert" else "WATCH"
            f.write(f"[{stamp}] {tag} {fmt_file(r)}\n")


def send_webhook(url, results):
    """[v1] 경보를 웹훅(JSON POST)으로 보낸다. 슬랙/디스코드/범용 HTTP 수신기 호환.

    - 주소가 없거나 '경보' 등급이 없으면 아무것도 보내지 않는다.
    - 전송에 실패해도 예외를 밖으로 던지지 않는다(감시가 멈추면 안 되므로).
    """
    alerts = [r for r in results if r["level"] == "alert"]
    if not url or not alerts:
        return
    lines = [f"🔴 {r['ip']} 점수 {r['score']} — {' · '.join(r['reasons'])}" for r in alerts]
    text = f"[{_BRAND}] 경보 {len(alerts)}건\n" + "\n".join(lines)
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": _BRAND})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
    except Exception as e:  # noqa: BLE001  — 알림 실패가 도구를 멈추게 두지 않는다
        print(f"⚠ 웹훅 전송 실패(무시하고 계속): {e}")


def alert_key(r):
    """자동 감시에서 '같은 경보'를 가릴 이름표 — IP와 등급만.

    시각·점수까지 넣으면 같은 공격자가 조금만 더 움직여도 '새 경보'로 보여
    매 바퀴 재알림이 터진다. IP+등급으로 묶어, 같은 공격자는 한 번만 알리고
    관찰→경보로 '승격'될 때만 다시 알린다.
    """
    return f"{r['ip']}|{r['level']}"


def run_watch(a):
    """[v1] N초마다 로그를 다시 읽어 '새로 생기거나 바뀐 경보만' 알린다."""
    print(f"자동 감시 시작 — {a.watch}초마다 {a.logfile} 재검사 (Ctrl+C 로 중지)")
    seen = None
    seen_dist = set()           # 이미 알린 분산 신호 종류(분산 무차별/스캔)
    try:
        while True:
            events, _ = load_events(a.logfile, a.format)
            results = analyze(events, a.window, a.probe_threshold,
                              a.auth_threshold, a.rate_threshold, a.score_threshold)
            current = {alert_key(r): r for r in results}  # IP+등급을 '이름표'로
            dist = detect_distributed(events, a.window, a.dist_threshold)  # [v2] 서버 전체
            dist_now = {d["kind"] for d in dist}
            stamp = datetime.now().strftime("%H:%M:%S")
            if seen is None:                      # 첫 바퀴 = 기준선(조용)
                seen = set(current)
                seen_dist = set(dist_now)
                print(f"[{stamp}] 기준선 — 현재 경보 {len(current)}건·분산 {len(dist_now)}건 저장")
            else:
                fresh = [current[k] for k in current if k not in seen]
                fresh_dist = [d for d in dist if d["kind"] not in seen_dist]
                if fresh or fresh_dist:
                    print(f"[{stamp}] 🔔 새 경보 {len(fresh)}건·분산 {len(fresh_dist)}건")
                    for r in fresh:
                        icon = "🔴" if r["level"] == "alert" else "🟡"
                        print("  " + icon + " " + fmt_screen(r))
                    for d in fresh_dist:
                        print(f"  🌐 {d['kind']} — 서로 다른 IP {d['ips']}개 (한 {d['window']}초 창)")
                    if a.alert_log:
                        write_alert_log(a.alert_log, fresh)
                    send_webhook(a.webhook, fresh)   # 새 경보만 알림(소음 방지)
                else:
                    print(f"[{stamp}] 새 경보 없음")
                seen |= set(current)
                seen_dist |= dist_now
            time.sleep(a.watch)
    except KeyboardInterrupt:
        print("\n감시 중지.")


# ───────────────────────── 실시간 상황판(대시보드) ─────────────────────────
# 대표님 요청: 슬랙 알림 대신, 침투 시도를 '실시간 화면'으로 보여준다.
# 원칙 유지: 설치할 것 0개 — 파이썬 표준 http.server 와 순수 HTML/JS 만 쓴다.
#   (1) 백그라운드 스레드가 scan_interval 초마다 로그를 다시 읽어 최신 경보를 갱신
#   (2) 작은 웹서버가 화면(/)과 자료(/api/alerts·JSON)를 내려준다
#   (3) 화면이 3초마다 /api/alerts 를 받아와 상황판을 다시 그린다


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S") if dt else None


def _is_suspicious(e):
    """이 요청 한 건이 '수상한가' — 없는주소(404)·인증거부·탐침경로·도구 지문 중 하나라도."""
    return (_is_nf(e) or _is_auth_fail(e) or bool(_odd_flags(e))
            or is_probe_path(e["path"]) or is_tool(e["ua"]))


def _event_kind(e):
    """수상한 요청 한 건에 붙일 유형 이름
    (우선순위: 의심 헤더 > 탐침 > 비표준 메서드 > 인증거부 > 없는주소 > 권한 밖 경로 > 도구).
    이상한 메서드로 온 401 은 로그인 시도가 아니라 스캐너라서 인증거부보다 앞에 둔다."""
    flags = _odd_flags(e)
    if any(f.startswith("의심 헤더") for f in flags):
        return "의심 헤더"
    if is_probe_path(e["path"]):
        return "탐침경로"
    if flags:
        return "비표준 메서드"
    if _is_auth_fail(e):
        return "인증거부"
    if e["status"] == 404:
        return "없는 주소"
    if _is_offlimits(e):
        return "권한 밖 경로"
    if is_tool(e["ua"]):
        return "도구 접근"
    return "요청"


def _severity(kind):
    """유형 → 심각도(위험/경고). 탐침·인증거부는 명백히 악의적 → 위험."""
    return "위험" if kind in ("탐침경로", "인증거부", "의심 헤더") else "경고"


def recommend(ip, path, status, ua, kind):
    """규칙 기반 대응 추천 — 침투 유형을 보고 즉시 구체적 조치를 제시(오프라인·무료).

    진짜 LLM 호출이 아니라 '보안 전문가의 대응 규칙'을 코드로 옮긴 것.
    MES(Windows) 서버 기준의 방화벽 차단 명령까지 만들어 준다. 인터넷·API 키 불필요.
    """
    actions = []
    if kind == "탐침경로":
        headline = "민감·숨은 경로를 노린 스캐너(자동 정찰). 공개되면 안 될 주소를 찔러봄."
        actions.append(f"이 경로({path})가 실제 서버에 존재·노출되는지 확인하고, 그렇다면 즉시 비공개로.")
        actions.append("같은 IP가 여러 경로를 훑으면 스캐너로 보고 그 IP를 차단 대상에 올린다.")
    elif kind == "인증거부":
        headline = "로그인·권한 돌파 시도(무차별 대입 가능성). 반복되면 계정이 뚫릴 위험."
        actions.append("대상 계정에 로그인 실패 잠금(예: 5회 실패 시 잠금)이 걸려 있는지 확인·강화.")
        actions.append("같은 IP의 반복 실패면 IP 차단, 한 계정에 여러 IP면 그 계정 비밀번호 강제 변경.")
        if status == 423:
            actions.append("상태 423=이미 계정 잠금 발동 → 무차별 대입의 결정적 증거. 우선 대응.")
    elif kind == "의심 헤더" and status == 403:
        # 앞단(Caddy 등)이 이미 거절한 경우 — 공격 의도는 그대로지만 앱까지 가지 않았다
        headline = ("프레임워크 취약점 공격 시도(React2Shell 류) — 앞단에서 이미 거절됨(403). "
                    "요청이 앱까지 가지 않았습니다.")
        actions.append("추가 조치는 필요 없습니다. 앞단 거절 규칙이 제대로 작동하고 있다는 뜻입니다.")
        actions.append("같은 IP가 계속 반복하면 IP 차단을 고려하세요(반복 공격자).")
    elif kind == "의심 헤더":
        headline = ("프레임워크 취약점 공격 시도(예: Next.js 'Next-Action' 헤더를 쓰는 React2Shell 류). "
                    "원격 코드 실행을 노리는 위험한 요청.")
        actions.append("웹 프레임워크(Next.js/React) 버전이 해당 취약점이 고쳐진 버전인지 즉시 확인.")
        actions.append("앱이 그 기능(서버 액션)을 쓰지 않으면 앞단(Caddy/nginx)에서 이 헤더가 있는 요청을 거절.")
        actions.append("같은 IP의 다른 요청과 서버의 파일·프로세스 변경 여부를 점검(침해 흔적 확인).")
    elif kind == "비표준 메서드":
        headline = "표준이 아닌 HTTP 메서드 — 스캐너가 서버 종류를 떠볼 때 흔히 씀."
        actions.append("웹서버가 표준 메서드 외에는 거절(405)하는지 확인. 반복되면 스캐너로 보고 관찰·차단.")
    elif kind == "권한 밖 경로":
        headline = "로그인 없이 보호된 경로를 훑음(정찰). 무엇이 있는지 떠보는 단계."
        actions.append("단발이면 소음일 수 있으나, 같은 IP가 여러 경로를 훑으면 스캐너로 보고 관찰·차단.")
        actions.append("API가 아닌 경로까지 401로 답하면 404로 돌려 공격 표면을 줄이는 것도 방법.")
    elif kind == "없는 주소":
        headline = "없는 주소 훑기(정찰). 서버 구조를 떠보는 초기 단계일 수 있음."
        actions.append("단발이면 소음일 수 있으나, 같은 IP가 반복하면 스캐너로 보고 관찰·차단.")
    else:
        headline = "자동화 도구의 접근."
        actions.append("정상 트래픽인지 확인하고, 아니면 차단 대상에 올린다.")
    if is_tool(ua):
        actions.append("User-Agent 가 자동화 도구 지문(사람 아님) — 봇·스캐너 차단 정책 대상.")
    # Windows(MES) 방화벽 차단 명령 — 관리자 권한에서 실행하면 이 IP 의 인바운드를 막는다
    block_cmd = (f'netsh advfirewall firewall add rule '
                 f'name="LogSentry-block-{ip}" dir=in action=block remoteip={ip}')
    caution = ("운영 MES 서버에선 '즉시 차단'보다 먼저 '경고 모드'로 며칠 지켜보세요 — "
               "정상 직원이 실수로 막히는 오탐을 피하기 위해. 확실한 공격 IP만 위 명령으로 차단.")
    return {"headline": headline, "severity": _severity(kind),
            "actions": actions, "block_cmd": block_cmd, "caution": caution}


def _fmt_time(ts):
    """datetime → 화면용 시각. 밀리초가 있으면 밀리초까지(없으면 초 단위)."""
    if ts and ts.microsecond:
        return ts.strftime("%H:%M:%S.") + f"{ts.microsecond // 1000:03d}"
    if ts:
        return ts.strftime("%H:%M:%S")
    return "—"


def _timeline_entry(time_disp, ts_iso, ip, path, method, status, ua, kind):
    """타임라인 한 줄 + 상세·추천을 한 데 담는 공통 틀(로그에서 오든 DB에서 오든 같은 모양)."""
    return {
        "time": time_disp, "ts_iso": ts_iso or "", "ip": ip, "path": path,
        "method": method or "GET", "status": status, "ua": ua or "",
        "kind": kind, "severity": _severity(kind), "tool": is_tool(ua),
        "edge_blocked": edge_blocked(kind, status),
        "rec": recommend(ip, path, status, ua, kind),
    }


def edge_blocked(kind, status):
    """앞단(Caddy)이 문 앞에서 거절한 공격인지 — 의심 헤더 요청이 403 이면 앱까지 안 간 것."""
    return kind == "의심 헤더" and status == 403


def build_timeline(events, limit=60):
    """[DB 미사용 시] 개별 공격 요청을 '시간 순(최근 먼저)'으로 — 누적 요약이 아니라 한 건 한 건.

    신뢰 IP·정상 소음(_SKIP)은 뺀다. timestamp() 로 정렬해 aware/naive 혼용 오류를 피한다.
    """
    susp = [e for e in events
            if not _is_trusted(e["ip"])
            and not any(e["path"].startswith(s) for s in _SKIP)
            and _is_suspicious(e)]
    susp.sort(key=lambda e: e["ts"].timestamp() if e["ts"] else float("-inf"), reverse=True)
    out = []
    for e in susp[:limit]:
        iso = e["ts"].isoformat() if e["ts"] else ""
        out.append(_timeline_entry(_fmt_time(e["ts"]), iso, e["ip"], e["path"],
                                   e.get("method"), e["status"], e.get("ua"), _event_kind(e)))
    return out


# ───────────────────────── 침투 흔적 DB(SQLite, 파이썬 내장) ─────────────────────────
# 대표님 요청: 침투 흔적을 '따로 DB에도' 남긴다. SQLite 는 파이썬에 기본 내장 → '설치 0' 원칙 유지.
# 서버를 꺼도 흔적이 파일(logsentry.db)로 남아, 나중에 '언제 누가 몇 번' 조회·집계가 된다.

def open_db(path):
    """DB 파일을 열고(없으면 만들고) 침투 기록 표를 준비한다."""
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS intrusion("
        "ts TEXT, ip TEXT, path TEXT, status INTEGER, method TEXT, ua TEXT,"
        "kind TEXT, severity TEXT, seen_at TEXT,"
        "UNIQUE(ts, ip, path, status))")   # 같은 요청 중복 저장 방지
    # 차단한 IP 목록(되돌리기용 active 플래그 포함)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blocklist("
        "ip TEXT PRIMARY KEY, reason TEXT, blocked_at TEXT, rule_name TEXT,"
        "active INTEGER DEFAULT 1)")
    # 차단·해제 시도 감사기록(언제·어느 IP·무엇을·결과) — 이력/책임 추적
    conn.execute(
        "CREATE TABLE IF NOT EXISTS block_audit("
        "ts TEXT, ip TEXT, action TEXT, result TEXT, detail TEXT)")
    # 신뢰 IP(오탐 처리) — 여기 든 IP 는 공격으로 세지도 보여주지도 않는다
    conn.execute(
        "CREATE TABLE IF NOT EXISTS trusted("
        "ip TEXT PRIMARY KEY, added_at TEXT)")
    # 공격 IP 출처 조회 결과(나라·기관·종류) — 한 번 물은 IP 는 다시 안 묻게 저장
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_info("
        "ip TEXT PRIMARY KEY, data TEXT, looked_at TEXT)")
    # 사고 의심('뚫렸나?') — 확인함(ack) 표시로 처리, 지우지 않음
    conn.execute(
        "CREATE TABLE IF NOT EXISTS incident("
        "key TEXT PRIMARY KEY, ts TEXT, ip TEXT, type TEXT, data TEXT,"
        "ack INTEGER DEFAULT 0, ack_at TEXT, found_at TEXT)")
    # 작은 상태 저장소(매일 요약을 오늘 보냈는지 등 — 재시작해도 두 번 안 보내게)
    conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
    # 소프트 삭제 — 화면에서 지워도 바로 안 없애고 '삭제함'으로 옮겨 복구할 수 있게.
    # 이미 쓰던 DB 에도 칸을 더한다(없을 때만). 기존 행은 deleted=0(안 지움).
    cols = {r[1] for r in conn.execute("PRAGMA table_info(intrusion)")}
    if "deleted" not in cols:
        conn.execute("ALTER TABLE intrusion ADD COLUMN deleted INTEGER DEFAULT 0")
    if "deleted_at" not in cols:
        conn.execute("ALTER TABLE intrusion ADD COLUMN deleted_at TEXT")
    conn.commit()
    return conn


def store_events(conn, events):
    """수상한 요청만 DB 에 영구 저장(중복은 UNIQUE 로 자동 무시). 새로 저장된 건수를 돌려준다."""
    now = datetime.now().isoformat(timespec="seconds")
    saved = 0
    for e in events:
        if _is_trusted(e["ip"]):
            continue
        if any(e["path"].startswith(s) for s in _SKIP):
            continue
        if not _is_suspicious(e):
            continue
        kind = _event_kind(e)
        ts_iso = e["ts"].isoformat() if e["ts"] else ""
        cur = conn.execute(
            "INSERT OR IGNORE INTO intrusion"
            "(ts, ip, path, status, method, ua, kind, severity, seen_at)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (ts_iso, e["ip"], e["path"], e["status"], e.get("method") or "GET",
             e.get("ua") or "", kind, _severity(kind), now))
        saved += cur.rowcount
    conn.commit()
    return saved


def recent_intrusions(conn, limit=60):
    """DB 에서 최근 침투 흔적을 시간 순(최근 먼저)으로 꺼내 타임라인 모양으로."""
    cur = conn.execute(
        "SELECT ts, ip, path, status, method, ua, kind FROM intrusion"
        " WHERE COALESCE(deleted,0)=0 ORDER BY ts DESC LIMIT ?", (limit,))
    out = []
    for ts, ip, path, status, method, ua, kind in cur.fetchall():
        try:
            dt = datetime.fromisoformat(ts) if ts else None
        except ValueError:
            dt = None
        out.append(_timeline_entry(_fmt_time(dt), ts, ip, path, method, status, ua, kind))
    return out


# ──────────────────────────────────────────────────────────────────────────
# IP 차단 엔진 — 상황판의 '이 IP 차단' 버튼이 호출. 실제 Windows 방화벽을 조작한다.
#   안전장치: ① IP 형식 엄격 검증(명령어 주입 차단)  ② 자기자신·링크로컬 거부
#            ③ 모든 시도를 감사기록(block_audit)에 남김  ④ 되돌리기(차단 해제) 지원
# ──────────────────────────────────────────────────────────────────────────
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _valid_ipv4(ip):
    """엄격한 IPv4 검사 — 숫자·점 외의 것은 전부 거부(그래서 명령어 주입이 불가능)."""
    m = _IPV4.match(ip or "")
    return bool(m) and all(0 <= int(g) <= 255 for g in m.groups())


def _is_private(ip):
    """사설망 IP(10/172.16~31/192.168)인가 — 차단 시 '사내 직원일 수 있음' 경고용."""
    o = [int(x) for x in ip.split(".")]
    return o[0] == 10 or (o[0] == 172 and 16 <= o[1] <= 31) or (o[0] == 192 and o[1] == 168)


def _block_refusal(ip):
    """차단하면 안 되는 IP 면 거부 사유(문자열), 괜찮으면 None 을 돌려준다."""
    if not _valid_ipv4(ip):
        return "IP 형식이 올바르지 않습니다 (IPv4 가 아님) — 차단하지 않습니다."
    o = [int(x) for x in ip.split(".")]
    if o[0] == 127:
        return "로컬(127.x)은 '당신 자신'입니다 — 차단하면 스스로를 막습니다. 거부합니다."
    if o[0] == 169 and o[1] == 254:
        return "링크-로컬(169.254.x)은 차단 대상이 아닙니다 — 거부합니다."
    if o == [0, 0, 0, 0] or o[0] == 0:
        return "0.x 주소는 차단할 수 없습니다 — 거부합니다."
    return None


def _rule_name(ip):
    return f"LogSentry-block-{ip}"


def _subnet24(ip):
    """IP → 그 /24 대역 문자열(예: 203.0.113.77 → 203.0.113.0/24)."""
    a, b, c, _ = ip.split(".")
    return f"{a}.{b}.{c}.0/24"


def _target_rule(ip, scope):
    """차단 대상·규칙이름·표시키를 scope(ip|subnet)에 맞게 돌려준다."""
    if scope == "subnet":
        net = _subnet24(ip)                       # 203.0.113.0/24
        base = net.split("/")[0].replace(".", "-")
        return net, f"LogSentry-block-{base}_24", net
    return ip, _rule_name(ip), ip


def _run_netsh(args):
    """netsh 를 '셸 없이' 실행(리스트 인자 → 명령어 주입 불가). (종료코드, 메시지) 반환."""
    if os.name != "nt":
        return 1, "이 기능은 Windows 방화벽(netsh)에서만 동작합니다."
    try:
        r = subprocess.run(["netsh", *args], capture_output=True, timeout=10)
    except FileNotFoundError:
        return 1, "netsh 를 찾을 수 없습니다."
    except subprocess.TimeoutExpired:
        return 1, "netsh 응답 시간 초과."
    raw = (r.stdout or b"") + b"\n" + (r.stderr or b"")
    msg = raw.decode("cp949", "replace").strip() if os.name == "nt" else raw.decode("utf-8", "replace").strip()
    return r.returncode, msg


def _audit(db_path, ip, action, result, detail):
    """차단·해제 시도를 감사기록 표에 남긴다(실패해도 본 기능은 멈추지 않음)."""
    if not db_path:
        return
    try:
        conn = open_db(db_path)
        conn.execute(
            "INSERT INTO block_audit(ts, ip, action, result, detail) VALUES(?,?,?,?,?)",
            (datetime.now().isoformat(timespec="seconds"), ip, action, result, (detail or "")[:300]))
        conn.commit()
        conn.close()
    except Exception:  # noqa: BLE001
        pass


def block_ip(db_path, ip, reason="", scope="ip"):
    """IP(또는 /24 대역)를 실제로 차단(Windows 방화벽 inbound 규칙 추가). 결과 dict 반환.

    scope="subnet" 이면 그 IP 의 /24 대역 전체를 막는다(공격자가 IP 를 바꿔가며 올 때).
    표시키(key)=실제 막은 대상(IP 또는 'a.b.c.0/24') — 되돌릴 때 이 키를 쓴다.
    """
    refuse = _block_refusal(ip)                   # 대상 IP 로 자기자신·형식 검증(대역도 동일)
    if refuse:
        _audit(db_path, ip, "block", "refused", refuse)
        return {"ok": False, "ip": ip, "status": "refused", "message": refuse}
    target, rule, key = _target_rule(ip, scope)
    rc, msg = _run_netsh(["advfirewall", "firewall", "add", "rule",
                          f"name={rule}", "dir=in", "action=block",
                          f"remoteip={target}"])
    if rc == 0:
        if db_path:
            try:
                conn = open_db(db_path)
                conn.execute(
                    "INSERT OR REPLACE INTO blocklist(ip, reason, blocked_at, rule_name, active)"
                    " VALUES(?,?,?,?,1)",
                    (key, reason, datetime.now().isoformat(timespec="seconds"), rule))
                conn.commit()
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        _audit(db_path, key, "block", "ok", msg)
        what = f"대역 {key} 전체(약 254개 IP)" if scope == "subnet" else f"{key} 의 들어오는 연결"
        return {"ok": True, "ip": ip, "key": key, "status": "blocked", "private": _is_private(ip),
                "message": f"차단 완료 — {what}을 방화벽에서 막았습니다."
                           + ("  ⚠ 사설 IP라 사내 직원일 수 있으니 확인하세요." if _is_private(ip) else "")}
    low = msg.lower()
    if any(k in msg for k in ("권한", "액세스", "관리자")) or any(k in low for k in ("elevat", "administrator", "denied", "requires")):
        hint = "실제 차단 실패 — 상황판을 '관리자 권한'으로 실행해야 방화벽을 바꿀 수 있습니다."
    else:
        hint = "방화벽 명령 실행에 실패했습니다."
    _audit(db_path, key, "block", "failed", msg)
    return {"ok": False, "ip": ip, "key": key, "status": "failed", "message": hint, "detail": msg[:200]}


def unblock_ip(db_path, key):
    """차단했던 대상을 되돌린다(방화벽 규칙 삭제). key=IP 또는 'a.b.c.0/24'."""
    if "/" in key:                                 # 대역 해제
        base = key.split("/")[0]
        if not _valid_ipv4(base):
            return {"ok": False, "ip": key, "status": "refused", "message": "대역 형식이 올바르지 않습니다."}
        a, b, c, _ = base.split(".")
        rule = f"LogSentry-block-{a}-{b}-{c}-0_24"
    elif _valid_ipv4(key):                          # 단일 IP 해제
        rule = _rule_name(key)
    else:
        return {"ok": False, "ip": key, "status": "refused", "message": "IP 형식이 올바르지 않습니다."}
    rc, msg = _run_netsh(["advfirewall", "firewall", "delete", "rule", f"name={rule}"])
    ok = rc == 0
    if db_path:
        try:
            conn = open_db(db_path)
            conn.execute("UPDATE blocklist SET active=0 WHERE ip=?", (key,))
            conn.commit()
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    _audit(db_path, key, "unblock", "ok" if ok else "failed", msg)
    return {"ok": ok, "ip": key, "key": key, "status": "unblocked" if ok else "failed",
            "message": "차단 해제 완료 — 다시 연결을 허용합니다." if ok
                       else "해제 실패(관리자 권한이 필요할 수 있습니다)."}


def export_evidence(db_path, ip):
    """그 IP 의 침투 기록을 텍스트 파일로 내보낸다(보고·신고용 증거). 결과 dict 반환."""
    if not _valid_ipv4(ip):
        return {"ok": False, "message": "IP 형식이 올바르지 않습니다."}
    if not db_path or not os.path.exists(db_path):
        return {"ok": False, "message": "저장된 기록(DB)이 없어 내보낼 수 없습니다."}
    try:
        conn = open_db(db_path)
        rows = conn.execute(
            "SELECT ts, path, status, method, ua, kind, severity FROM intrusion"
            " WHERE ip=? ORDER BY ts", (ip,)).fetchall()
        conn.close()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"DB 읽기 실패: {e}"}
    if not rows:
        return {"ok": False, "message": f"{ip} 관련 기록이 없습니다."}
    outdir = os.path.dirname(os.path.abspath(db_path)) or "."
    fname = f"evidence_{ip.replace('.', '-')}_{datetime.now():%Y%m%d_%H%M%S}.txt"
    path = os.path.join(outdir, fname)
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# LogSentry 증거 — 공격자 {ip}\n")
            f.write(f"# 생성 {datetime.now().isoformat(timespec='seconds')} · 총 {len(rows)}건\n")
            f.write("# 시각\t심각도\t유형\t상태\t요청\t도구지문\n\n")
            for ts, pth, status, method, ua, kind, sev in rows:
                f.write(f"{ts}\t{sev}\t{kind}\t{status}\t{method} {pth}\t{ua}\n")
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"파일 저장 실패: {e}"}
    _audit(db_path, ip, "evidence", "ok", path)
    return {"ok": True, "count": len(rows), "path": path,
            "message": f"{ip} 관련 {len(rows)}건을 저장했습니다:\n{path}"}


def load_blocked(db_path):
    """현재 차단 중인 IP 집합(상황판 켤 때 DB 에서 복원)."""
    if not db_path or not os.path.exists(db_path):
        return set()
    try:
        conn = open_db(db_path)
        rows = conn.execute("SELECT ip FROM blocklist WHERE active=1").fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:  # noqa: BLE001
        return set()


def trust_ip(db_path, ip):
    """IP 를 신뢰 목록에 넣는다(오탐 처리) — 이후 공격으로 세지도 보여주지도 않는다."""
    if not _valid_ipv4(ip):
        return {"ok": False, "ip": ip, "message": "IP 형식이 올바르지 않습니다."}
    if db_path:
        try:
            conn = open_db(db_path)
            conn.execute("INSERT OR REPLACE INTO trusted(ip, added_at) VALUES(?,?)",
                         (ip, datetime.now().isoformat(timespec="seconds")))
            conn.commit()
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    _audit(db_path, ip, "trust", "ok", "신뢰 IP 추가(오탐 처리)")
    return {"ok": True, "ip": ip, "message": f"{ip} 를 신뢰 IP로 표시했습니다 — 더는 공격으로 보이지 않습니다."}


def untrust_ip(db_path, ip):
    """신뢰 목록에서 뺀다(되돌리기) — 다시 탐지 대상이 된다."""
    if db_path:
        try:
            conn = open_db(db_path)
            conn.execute("DELETE FROM trusted WHERE ip=?", (ip,))
            conn.commit()
            conn.close()
        except Exception:  # noqa: BLE001
            pass
    _audit(db_path, ip, "untrust", "ok", "신뢰 IP 해제")
    return {"ok": True, "ip": ip, "message": f"{ip} 신뢰를 해제했습니다 — 다시 탐지합니다."}


def load_trusted(db_path):
    """현재 신뢰(오탐 처리) IP 집합."""
    if not db_path or not os.path.exists(db_path):
        return set()
    try:
        conn = open_db(db_path)
        rows = conn.execute("SELECT ip FROM trusted").fetchall()
        conn.close()
        return {r[0] for r in rows}
    except Exception:  # noqa: BLE001
        return set()


def load_history(db_path, limit=200):
    """'조치 기록' 화면용 — 지금 차단 중인 대상 · 신뢰 IP · 조치 이력(최근 먼저)."""
    empty = {"blocked": [], "trusted": [], "audit": [], "db": bool(db_path)}
    if not db_path or not os.path.exists(db_path):
        return empty
    try:
        conn = open_db(db_path)
        blocked = [{"ip": ip, "reason": reason or "", "blocked_at": at or ""}
                   for ip, reason, at in conn.execute(
                       "SELECT ip, reason, blocked_at FROM blocklist"
                       " WHERE active=1 ORDER BY blocked_at DESC").fetchall()]
        trusted = [{"ip": ip, "added_at": at or ""}
                   for ip, at in conn.execute(
                       "SELECT ip, added_at FROM trusted ORDER BY added_at DESC").fetchall()]
        audit = [{"ts": ts or "", "ip": ip or "", "action": action or "",
                  "result": result or "", "detail": (detail or "")[:200]}
                 for ts, ip, action, result, detail in conn.execute(
                     "SELECT ts, ip, action, result, detail FROM block_audit"
                     " ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]
        conn.close()
        return {"blocked": blocked, "trusted": trusted, "audit": audit, "db": True}
    except Exception:  # noqa: BLE001
        return empty


# ──────────────────────────────────────────────────────────────────────────
# 공격 내역 삭제·복구 (소프트 삭제) — 화면에서 지워도 '삭제함'으로 옮겨 복구 가능.
#   scope="one": 한 건(ts·ip·path·status 로 특정)  ·  scope="ip": 그 IP 전체
# ──────────────────────────────────────────────────────────────────────────
def _intrusion_filter(data):
    """요청 → (SQL 조건, 값들). 한 건이면 네 값 모두, IP 전체면 ip 만."""
    ip = (data.get("ip") or "").strip()
    if not ip:
        return None, None
    if data.get("scope") == "ip":
        return "ip=?", [ip]
    return "ts=? AND ip=? AND path=? AND status=?", [
        data.get("ts") or "", ip, data.get("path") or "", int(data.get("status") or 0)]


def _set_deleted(db_path, data, flag):
    """공격 내역을 삭제 표시(flag=1) 또는 복구(flag=0). 바뀐 건수를 돌려준다."""
    where, params = _intrusion_filter(data)
    if not db_path or not where:
        return {"ok": False, "count": 0, "message": "대상이 올바르지 않습니다."}
    try:
        conn = open_db(db_path)
        now = datetime.now().isoformat(timespec="seconds") if flag else None
        cur = conn.execute(
            f"UPDATE intrusion SET deleted=?, deleted_at=? WHERE {where} AND COALESCE(deleted,0)=?",
            [flag, now] + params + [0 if flag else 1])
        conn.commit()
        n = cur.rowcount
        conn.close()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "count": 0, "message": f"처리 실패: {e}"}
    act = "log_delete" if flag else "log_restore"
    _audit(db_path, (data.get("ip") or ""), act, "ok", f"{n}건 {'삭제' if flag else '복구'}")
    return {"ok": True, "count": n,
            "message": (f"{n}건을 삭제했습니다(삭제함에서 복구 가능)." if flag
                        else f"{n}건을 복구했습니다.")}


def delete_logs(db_path, data):
    if data.get("scope") == "all":            # 타임라인 전체를 삭제함으로
        if not db_path or not os.path.exists(db_path):
            return {"ok": False, "count": 0, "message": "DB 없음"}
        try:
            conn = open_db(db_path)
            now = datetime.now().isoformat(timespec="seconds")
            cur = conn.execute(
                "UPDATE intrusion SET deleted=1, deleted_at=? WHERE COALESCE(deleted,0)=0", [now])
            conn.commit(); n = cur.rowcount; conn.close()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "count": 0, "message": f"처리 실패: {e}"}
        _audit(db_path, "", "log_delete", "ok", f"{n}건 전체 삭제")
        return {"ok": True, "count": n, "message": f"{n}건을 모두 삭제했습니다(삭제함에서 복구 가능)."}
    return _set_deleted(db_path, data, 1)


def delete_many(db_path, items, flag=1):
    """선택한 여러 건을 한 번에 삭제(flag=1) 또는 복구(flag=0). 바뀐 건수 반환."""
    if not db_path or not os.path.exists(db_path):
        return {"ok": False, "count": 0, "message": "DB 없음"}
    rows = [i for i in (items or []) if isinstance(i, dict)][:3000]   # 과도한 요청 방지
    if not rows:
        return {"ok": False, "count": 0, "message": "선택한 항목이 없습니다."}
    try:
        conn = open_db(db_path)
        now = datetime.now().isoformat(timespec="seconds") if flag else None
        n = 0
        for it in rows:
            cur = conn.execute(
                "UPDATE intrusion SET deleted=?, deleted_at=?"
                " WHERE ts=? AND ip=? AND path=? AND status=? AND COALESCE(deleted,0)=?",
                [flag, now, it.get("ts") or "", it.get("ip") or "", it.get("path") or "",
                 int(it.get("status") or 0), 0 if flag else 1])
            n += cur.rowcount
        conn.commit()
        conn.close()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "count": 0, "message": f"처리 실패: {e}"}
    _audit(db_path, "", "log_delete" if flag else "log_restore", "ok",
           f"선택 {n}건 {'삭제' if flag else '복구'}")
    return {"ok": True, "count": n,
            "message": (f"선택한 {n}건을 삭제했습니다(삭제함에서 복구 가능)." if flag
                        else f"선택한 {n}건을 복구했습니다.")}


def restore_logs(db_path, data):
    if data.get("scope") == "all":            # 삭제함 전체 복구
        data = {"ip": "*", "scope": "allrows"}
    if data.get("scope") == "allrows":
        if not db_path:
            return {"ok": False, "count": 0, "message": "DB 없음"}
        try:
            conn = open_db(db_path)
            cur = conn.execute("UPDATE intrusion SET deleted=0, deleted_at=NULL WHERE deleted=1")
            conn.commit(); n = cur.rowcount; conn.close()
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "count": 0, "message": f"처리 실패: {e}"}
        _audit(db_path, "", "log_restore", "ok", f"{n}건 전체 복구")
        return {"ok": True, "count": n, "message": f"{n}건을 모두 복구했습니다."}
    return _set_deleted(db_path, data, 0)


def purge_logs(db_path, data):
    """삭제함을 영구 삭제(복구 불가). scope='all' 이면 삭제함 비우기."""
    if not db_path or not os.path.exists(db_path):
        return {"ok": False, "count": 0, "message": "DB 없음"}
    try:
        conn = open_db(db_path)
        if data.get("scope") == "all":
            cur = conn.execute("DELETE FROM intrusion WHERE deleted=1")
        else:
            where, params = _intrusion_filter(data)
            if not where:
                conn.close()
                return {"ok": False, "count": 0, "message": "대상이 올바르지 않습니다."}
            cur = conn.execute(f"DELETE FROM intrusion WHERE {where} AND deleted=1", params)
        conn.commit(); n = cur.rowcount; conn.close()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "count": 0, "message": f"처리 실패: {e}"}
    _audit(db_path, (data.get("ip") or ""), "log_purge", "ok", f"{n}건 영구삭제")
    return {"ok": True, "count": n, "message": f"{n}건을 영구 삭제했습니다(복구 불가)."}


def load_deleted(db_path, limit=300):
    """'삭제함' 화면용 — 삭제 표시된 공격 내역(삭제 시각 최근 먼저)."""
    out = {"rows": [], "db": bool(db_path)}
    if not db_path or not os.path.exists(db_path):
        return out
    try:
        conn = open_db(db_path)
        rows = conn.execute(
            "SELECT ts, ip, path, status, kind, severity, deleted_at FROM intrusion"
            " WHERE deleted=1 ORDER BY deleted_at DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
    except Exception:  # noqa: BLE001
        return out
    out["rows"] = [{"ts": ts or "", "ip": ip or "", "path": path or "", "status": status,
                    "kind": kind or "", "severity": severity or "", "deleted_at": da or ""}
                   for ts, ip, path, status, kind, severity, da in rows]
    return out


def _logo_html():
    """헤더 로고 HTML — 설정 brand_logo(파일 경로 또는 data: URI)가 있으면 이미지, 없으면 기본 방패."""
    v = _BRAND_LOGO
    shield = '<span class="brand-emoji">🛡️</span>'
    if not v:
        return shield
    if not v.startswith("data:"):
        try:
            with open(v, "rb") as f:
                raw = f.read()
            ext = os.path.splitext(v)[1].lower().lstrip(".")
            mime = {"png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
                    "svg": "image/svg+xml", "gif": "image/gif", "webp": "image/webp"}.get(ext, "image/png")
            v = f"data:{mime};base64," + base64.b64encode(raw).decode()
        except Exception:  # noqa: BLE001
            return shield
    return '<img class="brand-logo-img" alt="" src="' + v.replace('"', "") + '">'


def esc_html(t):
    return (t or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _host_ok(host):
    """DNS 리바인딩 방지 — Host 의 이름이 localhost 이거나 IP 숫자 주소일 때만 받는다.

    악성 사이트가 자기 도메인을 127.0.0.1 로 가리키게 해서 상황판을 읽는 수법은
    언제나 '도메인 이름'을 쓰므로, 이름이 IP 숫자 또는 localhost 가 아니면 거절한다.
    """
    h = (host or "").strip()
    if not h:
        return False
    if h.startswith("["):                           # [::1]:8790
        name = h[1:h.find("]")] if "]" in h else ""
    elif h.count(":") == 1:                         # 127.0.0.1:8790 / localhost:8790
        name = h.rsplit(":", 1)[0]
    else:
        name = h
    if name.lower() == "localhost":
        return True
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def _post_allowed(headers, token):
    """조치 요청(POST)이 진짜 상황판 화면에서 왔는지 — (허용 여부, 거절 이유).

    ① Host 가 이 PC 주소  ② Origin 이 있으면 Host 와 같은 출처  ③ 화면에 심어 둔 비밀 표(토큰) 일치.
    다른 사이트는 이 표를 읽을 수 없고(같은 출처 정책), 사용자 지정 헤더도 마음대로 못 붙인다.
    """
    host = headers.get("Host") or ""
    if not _host_ok(host):
        return False, "Host"
    origin = headers.get("Origin")
    if origin is not None:
        if origin == "null" or urllib.parse.urlsplit(origin).netloc.lower() != host.strip().lower():
            return False, "Origin"
    sent = headers.get("X-LogSentry-Token") or ""
    if not (sent and token and hmac.compare_digest(sent, token)):
        return False, "token"
    return True, ""


def print_db(path, limit):
    """쌓인 침투 흔적 DB 를 표로 출력 — 상황판을 켜지 않고도 터미널에서 바로 조회."""
    if not os.path.exists(path):
        print(f"DB 파일이 없습니다: {path}\n(아직 저장된 침투 흔적이 없거나, 상황판을 한 번도 안 켰어요)")
        return
    conn = open_db(path)
    total = conn.execute("SELECT COUNT(*) FROM intrusion").fetchone()[0]
    rows = conn.execute(
        "SELECT ts, ip, status, kind, severity, path FROM intrusion"
        " ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    print(f"\n📁 침투 흔적 DB: {path} — 총 {total}건 (최근 {len(rows)}건)\n")
    print(f"{'시각':<20}  {'IP':<16}  상태  {'유형':<10}  {'심각도':<6}  경로")
    print("-" * 96)
    for ts, ip, status, kind, severity, pth in rows:
        t = ts.replace("T", " ")[:19] if ts else "-"
        print(f"{t:<20}  {ip:<16}  {status:<4}  {kind:<10}  {severity:<6}  {pth}")
    agg = conn.execute(
        "SELECT ip, COUNT(*) c FROM intrusion GROUP BY ip ORDER BY c DESC LIMIT 5").fetchall()
    if agg:
        print("\n공격 많은 IP(상위 5):")
        for ip, c in agg:
            print(f"  {ip:<16} {c}건")
    conn.close()


# ──────────────────────────────────────────────────────────────────────────
# 공격 IP 출처 분석 — "어디서 왔고, 어떤 종류의 IP 인가"
#   · 출처: 인터넷 주소 공식 등록기관(RIR: APNIC·ARIN·RIPE…)의 RDAP 조회 → 나라·기관·네트워크 이름
#   · 종류: 기관 이름 + 역방향 이름(rDNS)을 규칙으로 분류(클라우드·호스팅 / 보안 검색엔진 / 통신사·가정)
#   · 외부로 IP 를 묻는 기능이라 설정 "ip_lookup": true 일 때만. 사내·사설·신뢰 IP 는 절대 조회 안 함.
#   · 등록 정보는 IP 주인이 적는 글이라 믿으면 안 됨 → 길이 자르고, 화면에선 반드시 이스케이프.
# ──────────────────────────────────────────────────────────────────────────
_RDAP_BOOTSTRAP = {"v4": "https://data.iana.org/rdap/ipv4.json",
                   "v6": "https://data.iana.org/rdap/ipv6.json"}
_RDAP_FALLBACK = "https://rdap.org/"       # 부트스트랩을 못 받으면 쓰는 중계(알맞은 RIR 로 넘겨 줌)
_IPINFO_OK_TTL = 30 * 86400                # 조회 성공 결과는 30일 재사용
_IPINFO_FAIL_TTL = 3600                    # 실패는 1시간 뒤 다시 시도

_COUNTRY_KO = {
    "KR": "한국", "US": "미국", "CN": "중국", "JP": "일본", "RU": "러시아", "DE": "독일", "NL": "네덜란드",
    "GB": "영국", "FR": "프랑스", "IN": "인도", "SG": "싱가포르", "HK": "홍콩", "TW": "대만", "VN": "베트남",
    "BR": "브라질", "CA": "캐나다", "AU": "호주", "ID": "인도네시아", "TH": "태국", "PH": "필리핀",
    "MY": "말레이시아", "UA": "우크라이나", "PL": "폴란드", "RO": "루마니아", "BG": "불가리아", "TR": "튀르키예",
    "IR": "이란", "IT": "이탈리아", "ES": "스페인", "SE": "스웨덴", "CH": "스위스", "FI": "핀란드", "LT": "리투아니아",
    "LV": "라트비아", "MD": "몰도바", "SC": "세이셸", "BZ": "벨리즈", "PA": "파나마", "ZA": "남아프리카공화국",
    "MX": "멕시코", "AR": "아르헨티나", "CL": "칠레", "EG": "이집트", "IL": "이스라엘", "AE": "아랍에미리트",
    "SA": "사우디아라비아", "PK": "파키스탄", "BD": "방글라데시", "KZ": "카자흐스탄", "CZ": "체코", "AT": "오스트리아",
    "BE": "벨기에", "DK": "덴마크", "NO": "노르웨이", "IE": "아일랜드", "PT": "포르투갈", "GR": "그리스", "HU": "헝가리",
    "EE": "에스토니아", "NG": "나이지리아", "KE": "케냐", "MN": "몽골", "KH": "캄보디아", "NZ": "뉴질랜드",
}
# ARIN 은 나라 코드를 따로 안 주고 주소 글(label) 마지막 줄에 영어 나라 이름을 적는다
_COUNTRY_EN = {"united states": "US", "canada": "CA", "puerto rico": "PR", "jamaica": "JM", "bahamas": "BS"}

# 분류 규칙 — 앞에서부터 먼저 맞는 것으로. (키, 화면 이름, 짧은 이름, 설명)
_IP_KINDS = {
    "scanner": ("보안 검색엔진", "검색엔진",
                "인터넷 전체를 훑는 연구·검색 서비스(Censys·Shodan 등). 대체로 무해한 정찰 — 무시하거나 막아도 됨."),
    "cloud": ("클라우드·호스팅", "호스팅",
              "돈 내고 빌린 서버. 공격 봇·스캐너가 가장 많이 쓰는 곳 — 같은 IP 가 반복하면 차단 1순위."),
    "isp": ("통신사·가정 회선", "통신사",
            "일반 가정·휴대폰 인터넷. 감염된 PC·공유기일 수 있음 — 같은 통신사 고객(직원 포함)이 섞이므로 대역 차단은 금지."),
    "unknown": ("분류 안 됨", "미분류",
                "등록 정보만으로는 판단이 어려움 — 무엇을 노렸는지(행동)로 판단하세요."),
}
_SCANNER_WORDS = ("censys", "shodan", "shadowserver", "binaryedge", "rapid7", "onyphe", "leakix", "criminalip",
                  "stretchoid", "internet-measurement", "internet measurement", "recyber", "netsystemsresearch",
                  "internettl", "alphastrike", "scanner", "security research", "intrinsec", "bitsight",
                  "internet intelligence", "intelligence data", "infrawatch", "driftnet", "palo alto networks",
                  "expanse", "modat", "fofa", "zoomeye", "quadmetrics", "cyber security research")
_CLOUD_WORDS = ("amazon", "aws", "google", "microsoft", "azure", "digitalocean", "digital ocean", "ovh", "hetzner",
                "linode", "akamai", "vultr", "choopa", "contabo", "alibaba", "aliyun", "tencent", "oracle", "scaleway",
                "leaseweb", "m247", "hostinger", "ionos", "kamatera", "hosting", "datacenter", "data center",
                "data-center", "colocation", "dedicated", "vps", "cloud", "server", "web services", "compute",
                "host ", "hostroyale", "pfcloud", "frantech", "buyvm", "psychz", "quadranet", "servers",
                "youstable", "qloudin", "hostwinds", "netcup", "ponynet", "colocrossing", "racknerd",
                "dedipath", "aeza", "stark industries", "serverion", "hostkey", "cloud innovation",
                "tencent cloud", "huawei cloud", "ucloud", "kaopu", "gcore", "zenlayer")
_ISP_WORDS = ("telecom", "telekom", "telecommunication", "broadband", "mobile", "cellular", "wireless",
              "kt corp", "korea telecom", "sk broadband", "lg dacom", "lg uplus", "lg powercomm", "comcast",
              "verizon", "at&t", "charter", "spectrum", "cable", "dsl", "fiber", "fibre", "internet service",
              "vodafone", "orange", "telefonica", "chinanet", "china unicom", "china telecom", "china mobile",
              "reliance jio", "airtel", "bsnl", "viettel", "vnpt", "telkom", "pldt", "rostelecom",
              "dynamic", "dhcp", "pool", "ppp", "residential", "customer")


def _ip_lookupable(ip):
    """밖에 물어봐도 되는 IP 인가 — 인터넷 공인 주소만(사설·루프백·예약·신뢰 IP 는 절대 안 물음)."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    return addr.is_global and not _is_trusted(str(addr))


def _clip(v, n=120):
    """등록 정보 글은 IP 주인이 아무렇게나 적을 수 있다 → 문자열로, 줄바꿈 없애고, 길이 제한."""
    return " ".join(str(v or "").split())[:n]


def _vcard_get(entity, field):
    """RDAP entity 의 vCard 에서 필드 하나(fn·adr 등)를 꺼낸다. 없으면 None."""
    try:
        for item in entity.get("vcardArray", [None, []])[1]:
            if item and item[0] == field:
                return item
    except (AttributeError, IndexError, TypeError):
        return None
    return None


def _walk_entities(obj, depth=0):
    """entities 는 안에 entities 를 또 품을 수 있다(2단계까지만 훑음)."""
    for ent in (obj.get("entities") or []):
        if isinstance(ent, dict):
            yield ent
            if depth < 1:
                yield from _walk_entities(ent, depth + 1)


def parse_rdap(obj):
    """RDAP 응답(JSON) → {country, org, net, cidr, descr}. RIR 마다 모양이 조금씩 달라 여러 곳을 본다."""
    if not isinstance(obj, dict):
        return {"country": "", "org": "", "net": "", "cidr": "", "descr": "", "extra": ""}
    country = str(obj.get("country") or "").upper()[:2]
    net = _clip(obj.get("name") or obj.get("handle"), 60)
    # 대역: cidr0 확장(있으면) → 아니면 시작~끝 주소
    cidr = ""
    for c in (obj.get("cidr0_cidrs") or []):
        if isinstance(c, dict) and (c.get("v4prefix") or c.get("v6prefix")):
            cidr = f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
            break
    if not cidr and obj.get("startAddress"):
        cidr = f"{obj.get('startAddress')} ~ {obj.get('endAddress')}"
    # 설명(RIPE·APNIC 의 descr 가 remarks 로 옴) — 기관 이름이 여기 있을 때가 많다
    descr = ""
    for r in (obj.get("remarks") or []):
        if isinstance(r, dict) and r.get("description"):
            lines = [str(x).strip() for x in r["description"] if any(ch.isalnum() for ch in str(x))]
            if lines:
                descr = _clip(" · ".join(lines[:2]), 120)
                break
    # 기관: 등록자(registrant) 역할의 이름이 우선, 없으면 아무 entity 의 이름
    org_kind, registrant, group, extra = "", "", "", []
    for ent in _walk_entities(obj):
        fn = _vcard_get(ent, "fn")
        name = _clip(fn[3], 100) if fn and len(fn) > 3 else ""
        kind_item = _vcard_get(ent, "kind")
        vkind = str(kind_item[3]).lower() if kind_item and len(kind_item) > 3 else ""
        roles = ent.get("roles") or []
        handle = str(ent.get("handle") or "")
        # 신고 창구(abuse)·관리자 코드(-MNT)는 쓰지 않는다. 개인(individual) 표시 이름은
        # 화면·저장에 절대 안 쓰고 '종류 분류'에만 참고(AFRINIC 은 회사 창구도 individual 로 적음).
        if not name or "abuse" in roles or handle.upper().endswith("-MNT"):
            continue
        extra.append(name)
        if vkind == "individual":
            continue
        if vkind == "org" and not org_kind:
            org_kind = name
        elif "registrant" in roles and not registrant:
            registrant = name
        elif not group:
            group = re.sub(r"\s+(administrator|admin|technical|tech|noc)$", "", name, flags=re.I)
        if not country:   # vCard 주소에서 나라 찾기(cc 매개변수 또는 ARIN 의 label 마지막 줄)
            adr = _vcard_get(ent, "adr")
            if adr and isinstance(adr[1], dict):
                cc = str(adr[1].get("cc") or "").upper()
                label = str(adr[1].get("label") or "")
                if cc:
                    country = cc[:2]
                elif label:
                    country = _COUNTRY_EN.get(label.strip().splitlines()[-1].strip().lower(), "")
    org = org_kind or registrant or descr or group
    return {"country": country, "org": org, "net": net, "cidr": _clip(cidr, 60), "descr": descr,
            "extra": _clip(" ".join(extra), 200)}


def classify_ip(org="", net="", descr="", rdns=""):
    """등록 정보·역방향 이름 → 종류 키(scanner/cloud/isp/unknown). 검색엔진 > 클라우드 > 통신사 순."""
    text = " " + " ".join([org, net, descr, rdns]).lower().replace("_", " ") + " "
    if any(w in text for w in _SCANNER_WORDS):
        return "scanner"
    if any(w in text for w in _CLOUD_WORDS):
        return "cloud"
    if any(w in text for w in _ISP_WORDS):
        return "isp"
    return "unknown"


def _http_json(url, timeout=8):
    """RDAP·부트스트랩 JSON 받기. 신원은 일반 이름만 보냄(회사·사람 정보 없음)."""
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json",
                                               "User-Agent": "InfoGuard-IDS/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 — https 고정 주소만
        return json.loads(r.read(2_000_000).decode("utf-8", "replace"))


def _rdns(ip, timeout=3):
    """역방향 이름(예: scanner-01.censys-scanner.com). 느린 DNS 에 묶이지 않게 시간 제한."""
    import socket
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _TO
    ex = ThreadPoolExecutor(max_workers=1)
    fut = ex.submit(socket.gethostbyaddr, ip)
    try:
        return _clip(fut.result(timeout=timeout)[0], 100)
    except (_TO, OSError, IndexError, UnicodeError):
        return ""
    finally:
        ex.shutdown(wait=False)


def rdap_base(ip, bootstrap):
    """IANA 부트스트랩(어느 대역을 어느 RIR 이 관리하는지) → 이 IP 를 물어볼 RDAP 주소."""
    try:
        addr = ipaddress.ip_address(ip)
        for entry in (bootstrap or {}).get("services", []):
            prefixes, urls = entry[0], entry[1]
            for pfx in prefixes:
                try:
                    if addr in ipaddress.ip_network(pfx, strict=False):
                        https = [u for u in urls if u.startswith("https://")]
                        return (https or urls)[0]
                except ValueError:
                    continue
    except (ValueError, TypeError, IndexError, AttributeError):
        pass
    return _RDAP_FALLBACK


def lookup_ip(ip, bootstrap=None, fetch=_http_json, resolver=_rdns):
    """IP 하나의 출처·종류. 네트워크 함수는 바꿔 끼울 수 있게(시험은 오프라인으로)."""
    now = datetime.now().isoformat(timespec="seconds")
    info = {"ip": ip, "ok": False, "country": "", "country_ko": "", "org": "", "net": "", "cidr": "",
            "rdns": "", "kind": "unknown", "looked_at": now, "error": ""}
    if not _ip_lookupable(ip):
        info["error"] = "조회 대상 아님(사설·신뢰·잘못된 주소)"
        return info
    ip = str(ipaddress.ip_address(ip))            # 정규화된 주소만 URL 에 넣는다
    try:
        base = rdap_base(ip, bootstrap)
        parsed = parse_rdap(fetch(base.rstrip("/") + "/ip/" + urllib.parse.quote(ip, safe=":.")))
        info.update({k: parsed[k] for k in ("country", "org", "net", "cidr")})
        info["ok"] = True
    except Exception as e:  # noqa: BLE001 — 조회 실패는 표시만 하고 넘어간다
        parsed = {"descr": "", "extra": ""}
        info["error"] = _clip(f"{type(e).__name__}: {e}", 100)
    info["rdns"] = resolver(ip) if resolver else ""
    info["country_ko"] = _COUNTRY_KO.get(info["country"], info["country"])
    info["kind"] = classify_ip(info["org"], info["net"],
                               parsed.get("descr", "") + " " + parsed.get("extra", ""), info["rdns"])
    if info["rdns"] and not info["ok"]:
        info["ok"] = True                          # RDAP 은 실패해도 rDNS 로 종류는 알 수 있음
    return info


def ipinfo_view(info):
    """화면에 보낼 모양 — 종류 이름·설명을 붙인다."""
    kind = info.get("kind") or "unknown"
    label, short, note = _IP_KINDS.get(kind, _IP_KINDS["unknown"])
    out = {k: info.get(k, "") for k in ("ip", "ok", "country", "country_ko", "org", "net", "cidr", "rdns",
                                        "looked_at")}
    out.update({"kind": kind, "kind_label": label, "kind_short": short, "kind_note": note})
    return out


def _ipinfo_fresh(info, now_ts):
    """다시 물을 필요가 없는가 — 성공은 30일, 실패는 1시간 동안 재사용."""
    try:
        age = now_ts - datetime.fromisoformat(info.get("looked_at", "")).timestamp()
    except (ValueError, TypeError):
        return False
    return age < (_IPINFO_OK_TTL if info.get("ok") else _IPINFO_FAIL_TTL)


def payload_ips(payload):
    """화면에 보이는 IP 들(타임라인 최근 순 → 경보 → Top). 조회 우선순위 그대로."""
    seen, out = set(), []
    for src in (payload.get("logins") or [], payload.get("incidents") or [],
                payload.get("timeline") or [], payload.get("alerts") or [], payload.get("top_ips") or []):
        for row in src:
            ip = row.get("ip")
            if ip and ip not in seen:
                seen.add(ip)
                out.append(ip)
    return out


def pick_lookup_targets(payload, cache, now_ts, limit=5):
    """이번 차례에 조회할 IP — 화면에 보이고, 물어도 되고, 저장된 결과가 오래됐거나 없는 것."""
    out = []
    for ip in payload_ips(payload):
        if len(out) >= limit:
            break
        if not _ip_lookupable(ip):
            continue
        if ip in cache and _ipinfo_fresh(cache[ip], now_ts):
            continue
        out.append(ip)
    return out


def save_ipinfo(conn, info):
    conn.execute("INSERT OR REPLACE INTO ip_info(ip, data, looked_at) VALUES(?,?,?)",
                 (info["ip"], json.dumps(info, ensure_ascii=False), info.get("looked_at", "")))
    conn.commit()


def load_ipinfo(conn):
    out = {}
    for ip, data in conn.execute("SELECT ip, data FROM ip_info").fetchall():
        try:
            out[ip] = json.loads(data)
        except (ValueError, TypeError):
            continue
    return out


# ──────────────────────────────────────────────────────────────────────────
# '뚫렸나?' — 막힌 시도 수천 건이 아니라, 실제 사고일 수 있는 것만 골라낸다.
#   ① 노출: 절대 200 이 나오면 안 되는 비밀 파일·관리 주소가 성공 응답을 받음
#           (탐침 경로 목록과 따로 둔다 — /actuator/health·/admin 처럼 정상 200 인 주소가 섞여 있어서)
#   ② 공격 성공: 취약점 공격 요청(의심 헤더)이 앱에서 성공 응답을 받음
#   ③ 수상한 로그인 성공: 공인 IP 에서 로그인 성공인데 — 실패 여러 번 뒤 / 공격 신호를 보낸 IP /
#      호스팅·검색엔진 IP / 해외 IP. (401·404 는 공격 근거로 안 친다: 세션 만료된 직원도 401 을 받음)
# ──────────────────────────────────────────────────────────────────────────
_SECRET_PATHS = ("/.env", "/.git/", "/.aws/", "/.ssh/", "/.svn/", "/.htpasswd", "/wp-config.php",
                 "/phpinfo.php", "/server-status", "/actuator/env", "/actuator/heapdump",
                 "/actuator/configprops", "/actuator/mappings", "/actuator/prometheus",
                 "/actuator/threaddump", "/actuator/loggers", "/backup.", "/dump.sql", "/db.sql",
                 "/.vscode/sftp.json", "/.ds_store")

_INCIDENT_ADVICE = {
    "exposure": ("브라우저로 그 주소를 직접 열어 실제 내용(비밀번호·설정·소스)이 보이는지 확인하세요. "
                 "보이면 즉시 웹서버(Caddy)에서 그 주소를 막고, 그 안에 있던 비밀번호·키를 전부 바꾸세요. "
                 "내용 없이 일반 화면만 나오면(앱이 모든 주소에 200 화면을 주는 구조) 오탐입니다."),
    "attack_ok": ("취약점 공격이 앱까지 들어가 성공 응답을 받았습니다. 앱 버전이 패치됐는지, 서버에 새 파일·"
                  "프로세스가 생겼는지 즉시 점검하고, 이 IP 를 차단하세요."),
    "login": ("그 시각에 로그인한 직원이 있는지 먼저 확인하세요(해외 출장·VPN 일 수 있음). 아니라면 해당 계정 "
              "비밀번호를 바로 바꾸고, 로그인 상태를 강제로 끊고, 이 IP 를 차단한 뒤 그 계정으로 한 작업 기록을 보세요."),
}
_INCIDENT_TITLE = {
    "exposure": "숨겨야 할 파일·관리 주소가 성공 응답(2xx)을 받음",
    "attack_ok": "취약점 공격 요청이 앱에서 성공 응답(2xx)을 받음",
    "login": "의심스러운 곳에서 로그인 성공",
}


def is_secret_path(path):
    """절대 밖으로 열리면 안 되는 파일·관리 주소인가(경로 중간에 있어도: /admin/.env 등)."""
    p = str(path or "").split("?")[0].lower()
    return any(s.lower() in p for s in _SECRET_PATHS) or p.endswith("/.git")


def _is_internal(ip):
    """사내·사설·루프백 등 인터넷 공인 주소가 아닌가(IPv6 포함). 이상한 값은 안전하게 '내부'로."""
    try:
        return not ipaddress.ip_address(str(ip).strip()).is_global
    except ValueError:
        return True


def _login_success(e):
    """로그인 성공인가 — 로그인 경로를 지정했고, 그 경로에 POST 해서 2xx."""
    return (bool(_AUTH_PATHS) and _on_auth_path(e["path"]) and 200 <= e["status"] < 300
            and (e.get("method") or "GET").upper() == "POST")


def detect_incidents(events, ipinfo=None, fail_threshold=5):
    """요청 목록 → 사고 의심 목록. 같은 요청은 늘 같은 key 라서 DB 에 한 번만 쌓인다."""
    ipinfo = ipinfo or {}
    fails, bad = defaultdict(int), set()
    out = []
    evs = sorted((e for e in events if e.get("ts")), key=lambda e: e["ts"].timestamp())
    for e in evs:
        ip, path, st = e["ip"], e["path"], e["status"]
        if any(path.startswith(s) for s in _SKIP):
            continue
        odd = _odd_flags(e)
        if _is_auth_fail(e):
            fails[ip] += 1
        if is_probe_path(path) or odd or is_tool(e.get("ua")):
            bad.add(ip)                       # 명백한 공격 신호를 보낸 IP(401·404 만으로는 안 넣음)
        typ, reasons = None, []
        ok = 200 <= st < 300
        if ok and is_secret_path(path):
            typ, reasons = "exposure", [f"{e.get('method') or 'GET'} {path} → {st}"]
        elif ok and any(f.startswith("의심 헤더") for f in odd):
            typ, reasons = "attack_ok", [f"{', '.join(odd)} → {st}"]
        elif _login_success(e) and not _is_internal(ip):
            info = ipinfo.get(ip) or {}
            if fails[ip] >= fail_threshold:
                reasons.append(f"같은 IP 의 로그인 실패 {fails[ip]}회 뒤 성공(무차별 대입 성공 의심 — 직원이 여러 번 틀렸을 수도)")
            if ip in bad:
                reasons.append("탐침·취약점 공격·도구 접근을 보낸 IP 에서 로그인 성공")
            if info.get("kind") in ("cloud", "scanner"):
                reasons.append(("호스팅(빌린 서버)" if info["kind"] == "cloud" else "검색엔진")
                               + " IP 에서 로그인 성공 — 일반 직원 회선이 아님(VPN 일 수 있음)")
            c = str(info.get("country") or "")
            if c and c != "KR":
                reasons.append(f"해외({_COUNTRY_KO.get(c, c)}) IP 에서 로그인 성공")
            if reasons:
                typ = "login"
        if typ:
            ts_iso = e["ts"].isoformat()
            out.append({"key": f"{typ}|{ts_iso}|{ip}|{path}|{st}", "type": typ, "ts": ts_iso, "ip": ip,
                        "path": _clip(path, 200), "method": e.get("method") or "GET", "status": st,
                        "title": _INCIDENT_TITLE[typ], "reasons": reasons, "advice": _INCIDENT_ADVICE[typ]})
    return out


def recent_logins(events, limit=20):
    """최근 로그인 성공(공인 IP) — 출처 조회를 먼저 하도록 우선순위에 쓴다."""
    seen, out = set(), []
    for e in sorted((x for x in events if x.get("ts")), key=lambda x: x["ts"].timestamp(), reverse=True):
        if _login_success(e) and not _is_internal(e["ip"]) and e["ip"] not in seen:
            seen.add(e["ip"])
            out.append({"ip": e["ip"], "ts_iso": e["ts"].isoformat()})
            if len(out) >= limit:
                break
    return out


def store_incidents(conn, incidents):
    """새 사고만 저장하고, 새로 들어간 것만 돌려준다(알림은 새것만 보내야 하니까)."""
    now = datetime.now().isoformat(timespec="seconds")
    fresh = []
    for inc in incidents:
        cur = conn.execute(
            "INSERT OR IGNORE INTO incident(key, ts, ip, type, data, ack, found_at) VALUES(?,?,?,?,?,0,?)",
            (inc["key"], inc["ts"], inc["ip"], inc["type"], json.dumps(inc, ensure_ascii=False), now))
        if cur.rowcount:
            fresh.append(inc)
    conn.commit()
    return fresh


def load_incidents(conn, open_only=True, limit=100):
    q = "SELECT data, ack, ack_at, found_at FROM incident"
    if open_only:
        q += " WHERE ack=0"
    q += " ORDER BY ts DESC LIMIT ?"
    out = []
    for data, ack, ack_at, found_at in conn.execute(q, (limit,)).fetchall():
        try:
            d = json.loads(data)
        except (ValueError, TypeError):
            continue
        d.update({"ack": bool(ack), "ack_at": ack_at or "", "found_at": found_at or ""})
        out.append(d)
    return out


def ack_incident(db_path, key, ack=True):
    """사고를 '확인함'(처리 완료)으로 — 지우지 않고 표시만(되돌릴 수 있게, 감사기록 남김)."""
    if not db_path or not key:
        return {"ok": False, "message": "대상이 없습니다."}
    try:
        conn = open_db(db_path)
        cur = conn.execute("UPDATE incident SET ack=?, ack_at=? WHERE key=?",
                           (1 if ack else 0, datetime.now().isoformat(timespec="seconds") if ack else None, key))
        conn.commit()
        n = cur.rowcount
        ip = (conn.execute("SELECT ip FROM incident WHERE key=?", (key,)).fetchone() or [""])[0]
        conn.close()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "message": f"처리 실패: {e}"}
    if not n:
        return {"ok": False, "message": "해당 사고 기록이 없습니다."}
    _audit(db_path, ip, "incident_ack" if ack else "incident_reopen", "ok", key[:120])
    return {"ok": True, "message": "확인함으로 표시했습니다(사고 기록에서 다시 열 수 있음)." if ack
            else "다시 '확인 필요'로 돌렸습니다."}


def today_summary(conn=None, events=None, today=None):
    """오늘(서버 시각) 공격 시도 수와 그중 차단·거절(4xx, 499 제외) 수 — 신호등 한 줄용."""
    day = today or datetime.now().strftime("%Y-%m-%d")
    if conn is not None:
        row = conn.execute(
            "SELECT COUNT(*), SUM(CASE WHEN status BETWEEN 400 AND 498 THEN 1 ELSE 0 END) FROM intrusion"
            " WHERE COALESCE(deleted,0)=0 AND ts LIKE ?", (day + "%",)).fetchone()
        return {"date": day, "attempts": row[0] or 0, "blocked": row[1] or 0}
    n = b = 0
    for e in events or []:
        if e.get("ts") and e["ts"].strftime("%Y-%m-%d") == day and _is_suspicious(e) \
                and not any(e["path"].startswith(s) for s in _SKIP):
            n += 1
            b += 1 if 400 <= e["status"] <= 498 else 0
    return {"date": day, "attempts": n, "blocked": b}


# ──────────────────────────────────────────────────────────────────────────
# 알림 · 매일 요약 · 감시 상태 — "화면을 안 봐도 안심할 수 있게"
#   · 즉시 알림: 사고 의심('뚫렸나?'), 사이트 응답 없음/복구, 로그 멈춤
#   · 매일 요약: 어제 공격 시도·차단·많이 온 IP·확인 필요 건수 + "InfoGuard 정상 작동" (안 오면 감시가 멈춘 것)
#   · 채널: 텔레그램 봇 / 이메일(SMTP) / 웹훅 — 설정 "notify" 에 넣은 것만. 하나가 실패해도 다른 건 보냄.
#   · 비밀값(봇 토큰·메일 비밀번호)은 화면·로그·오류 문구에 절대 안 찍는다.
# ──────────────────────────────────────────────────────────────────────────
_NOTIFY = {}          # 설정 "notify": {"telegram": {...}, "email": {...}, "webhook": "...", "daily_at": "08:30"}
_HEALTH = {}          # 설정 "health": {"urls": [...], "interval": 300, "fail_after": 2, "log_stall_minutes": 90}
_HEALTH_UA = "InfoGuard-health/1.0"     # 도구 지문(curl·python-urllib 등)에 안 걸리는 이름 — 감시 요청이 공격으로 안 잡히게
_TG_TOKEN_RE = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")


def notify_channels(cfg=None):
    """설정된 알림 채널 이름들(화면 표시용 — 값은 안 내보냄)."""
    cfg = _NOTIFY if cfg is None else cfg
    out = []
    tg = cfg.get("telegram") or {}
    if tg.get("bot_token") and tg.get("chat_id"):
        out.append("텔레그램")
    em = cfg.get("email") or {}
    if em.get("smtp_host") and em.get("to"):
        out.append("이메일")
    if cfg.get("webhook"):
        out.append("웹훅")
    return out


def _scrub(msg, cfg):
    """오류 문구에 비밀값이 섞여 나오지 않게 가린다."""
    text = str(msg)
    for secret in ((cfg.get("telegram") or {}).get("bot_token"), (cfg.get("email") or {}).get("password")):
        if secret:
            text = text.replace(str(secret), "***")
    return _clip(text, 160)


def _send_telegram(tg, text):
    token = str(tg.get("bot_token") or "")
    if not _TG_TOKEN_RE.match(token):            # 이상한 토큰이 주소에 섞여 엉뚱한 곳으로 가지 않게
        raise ValueError("텔레그램 bot_token 형식이 올바르지 않습니다")
    body = json.dumps({"chat_id": tg.get("chat_id"), "text": text[:3900],
                       "disable_web_page_preview": True}).encode("utf-8")
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": _BRAND})
    with urllib.request.urlopen(req, timeout=10) as r:   # noqa: S310 — 고정 https 주소
        r.read()


def _send_email(em, subject, text):
    import smtplib
    import ssl
    from email.message import EmailMessage
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = em.get("from") or em.get("username")
    to = em.get("to")
    msg["To"] = ", ".join(to) if isinstance(to, (list, tuple)) else str(to)
    msg.set_content(text)
    port = int(em.get("smtp_port") or 587)
    ctx = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(em["smtp_host"], port, timeout=15, context=ctx)
    else:
        server = smtplib.SMTP(em["smtp_host"], port, timeout=15)
        server.starttls(context=ctx)              # 비밀번호가 평문으로 가지 않게 항상 암호화
    try:
        if em.get("username"):
            try:
                server.login(em["username"], em.get("password") or "")
            except (smtplib.SMTPAuthenticationError, smtplib.SMTPServerDisconnected):
                # 가장 흔한 실패 — 사람이 읽을 말로(Gmail 원문 코드 대신)
                raise RuntimeError("메일 로그인 실패 — 보내는 주소와 앱 비밀번호가 같은 계정 것인지, "
                                   "그 계정에 2단계 인증이 켜져 있고 16자리가 맞는지 확인하세요") from None
        server.send_message(msg)
    finally:
        try:
            server.quit()
        except (smtplib.SMTPException, OSError):
            pass       # 이미 끊긴 연결 — 정리 중 오류가 위의 '진짜 원인'을 가리지 않게


def _send_webhook_text(url, text):
    req = urllib.request.Request(url, data=json.dumps({"text": text}).encode("utf-8"), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": _BRAND})
    with urllib.request.urlopen(req, timeout=8) as r:   # noqa: S310 — 운영자가 설정한 주소
        r.read()


_SENDERS = {"telegram": _send_telegram, "email": _send_email, "webhook": _send_webhook_text}


def send_notification(text, subject=None, cfg=None, senders=None):
    """설정된 모든 채널로 보낸다. 실패해도 예외를 밖으로 안 던지고 채널별 결과만 돌려준다."""
    cfg = _NOTIFY if cfg is None else cfg
    senders = senders or _SENDERS
    subject = subject or text.splitlines()[0][:80]
    results = {}
    tg, em, wh = cfg.get("telegram") or {}, cfg.get("email") or {}, cfg.get("webhook")
    jobs = []
    if tg.get("bot_token") and tg.get("chat_id"):
        jobs.append(("텔레그램", lambda: senders["telegram"](tg, text)))
    if em.get("smtp_host") and em.get("to"):
        jobs.append(("이메일", lambda: senders["email"](em, subject, text)))
    if wh:
        jobs.append(("웹훅", lambda: senders["webhook"](wh, text)))
    for name, job in jobs:
        try:
            job()
            results[name] = "ok"
        except Exception as e:  # noqa: BLE001 — 알림 실패가 감시를 멈추게 두지 않는다
            results[name] = "실패: " + _scrub(f"{type(e).__name__}: {e}", cfg)
            print(f"⚠ {name} 알림 실패(무시하고 계속): {results[name]}")
    return results


def _where_text(ip, ipinfo):
    i = (ipinfo or {}).get(ip) or {}
    if _is_internal(ip):
        return "사내"
    if not i.get("ok"):
        return ""
    label = _IP_KINDS.get(i.get("kind") or "unknown", _IP_KINDS["unknown"])[1]
    c = _COUNTRY_KO.get(i.get("country", ""), i.get("country", ""))
    return " · ".join(x for x in (c, label) if x)


def fmt_incident_msg(inc, ipinfo=None):
    """사고 의심 즉시 알림 — 폰 화면 한 장에 '무엇·어디서·왜·할 일'."""
    kind = {"exposure": "노출 의심", "attack_ok": "공격 성공 의심", "login": "수상한 로그인"}.get(inc["type"], inc["type"])
    where = _where_text(inc["ip"], ipinfo)
    lines = [f"[{_BRAND}] 🔴 확인 필요 — {kind}",
             inc["title"],
             f"시각: {str(inc['ts'])[:19].replace('T', ' ')}",
             f"IP: {inc['ip']}" + (f" ({where})" if where else ""),
             f"요청: {inc['method']} {inc['path']} → {inc['status']}"]
    lines += [f"· {r}" for r in inc.get("reasons") or []]
    lines.append(f"할 일: {inc['advice']}")
    lines.append("상황판에서 확인 후 [확인함]을 눌러 주세요.")
    return "\n".join(lines)


def daily_report(conn, day, ipinfo=None, health=None):
    """하루치 요약 자료(DB 기준)."""
    s = today_summary(conn=conn, today=day)
    top = conn.execute(
        "SELECT ip, COUNT(*) c FROM intrusion WHERE COALESCE(deleted,0)=0 AND ts LIKE ?"
        " GROUP BY ip ORDER BY c DESC LIMIT 3", (day + "%",)).fetchall()
    kinds = conn.execute(
        "SELECT kind, COUNT(*) c FROM intrusion WHERE COALESCE(deleted,0)=0 AND ts LIKE ?"
        " GROUP BY kind ORDER BY c DESC", (day + "%",)).fetchall()
    new_inc = conn.execute("SELECT COUNT(*) FROM incident WHERE ts LIKE ?", (day + "%",)).fetchone()[0]
    open_inc = conn.execute("SELECT COUNT(*) FROM incident WHERE ack=0").fetchone()[0]
    return {"date": day, "attempts": s["attempts"], "blocked": s["blocked"],
            "top": [(ip, c, _where_text(ip, ipinfo)) for ip, c in top],
            "kinds": [(k or "기타", c) for k, c in kinds], "new_incidents": new_inc,
            "open_incidents": open_inc, "health": health or {}}


def fmt_daily_msg(r):
    """매일 아침 요약 — 대표님이 10초에 읽게. 마지막 줄은 '감시가 살아 있다'는 신호."""
    d = r["date"][5:].replace("-", "/")
    lamp = (f"🔴 확인 필요 {r['open_incidents']}건 — 상황판에서 확인해 주세요" if r["open_incidents"]
            else "🟢 조치 필요 없음")
    lines = [f"[{_BRAND}] {d} 보안 요약", lamp,
             f"공격 시도 {r['attempts']}건 · 그중 차단·거절 {r['blocked']}건 · 새 사고 의심 {r['new_incidents']}건"]
    if r["top"]:
        lines.append("많이 온 IP: " + ", ".join(
            f"{ip}{'(' + w + ')' if w else ''} {c}건" for ip, c, w in r["top"]))
    if r["kinds"]:
        lines.append("종류: " + ", ".join(f"{k} {c}" for k, c in r["kinds"][:5]))
    h = r.get("health") or {}
    if h.get("problems"):
        lines.append("⚠ 감시 이상: " + "; ".join(h["problems"]))
    else:
        lines.append("감시 상태: 정상")
    lines.append(f"— {_BRAND} 정상 작동 중 (이 요약이 오지 않으면 감시가 멈춘 것이니 서버를 확인하세요)")
    return "\n".join(lines)


def check_url(url, timeout=6):
    """사이트가 살아 있나 — 5xx·연결 실패·시간 초과면 죽은 것. 401·404 처럼 답이라도 하면 산 것."""
    req = urllib.request.Request(url, headers={"User-Agent": _HEALTH_UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310 — 운영자가 설정한 내부 주소
            return True, f"{r.status}"
    except urllib.error.HTTPError as e:
        return e.code < 500, (f"{e.code}" if e.code < 500 else f"서버 오류 {e.code}")
    except Exception as e:  # noqa: BLE001 — 폰에서 읽을 말로(윈도 오류 문구 그대로 보내지 않음)
        reason = getattr(e, "reason", e)
        if isinstance(reason, ConnectionRefusedError):
            return False, "연결 거부(꺼져 있음)"
        if isinstance(reason, TimeoutError) or isinstance(e, TimeoutError):
            return False, "응답 시간 초과"
        return False, _clip(f"연결 실패: {type(reason).__name__}", 60)


class HealthMonitor:
    """연속 실패 N번이면 '응답 없음', 다시 되면 '복구' — 상태가 바뀔 때만 알림(같은 알림 반복 금지)."""

    def __init__(self, urls, fail_after=2, checker=check_url):
        self.urls, self.fail_after, self.checker = list(urls or []), max(1, int(fail_after)), checker
        self.fails = {u: 0 for u in self.urls}
        self.down = {u: False for u in self.urls}
        self.detail = {u: "" for u in self.urls}

    def run(self):
        """한 번 점검 → 바뀐 것 목록 [(url, 'down'|'up', detail)]."""
        changes = []
        for u in self.urls:
            ok, detail = self.checker(u)
            self.detail[u] = detail
            if ok:
                self.fails[u] = 0
                if self.down[u]:
                    self.down[u] = False
                    changes.append((u, "up", detail))
            else:
                self.fails[u] += 1
                if not self.down[u] and self.fails[u] >= self.fail_after:
                    self.down[u] = True
                    changes.append((u, "down", detail))
        return changes

    def problems(self):
        return [f"사이트 응답 없음: {u} ({self.detail[u]})" for u in self.urls if self.down[u]]


def log_stall_problem(logfile, minutes, now_ts=None):
    """로그가 너무 오래 안 늘었나 — Caddy 가 멈췄거나 로그 경로가 바뀐 신호."""
    if not minutes or not logfile:
        return ""
    try:
        age = ((now_ts or time.time()) - os.path.getmtime(logfile)) / 60
    except OSError:
        return f"로그 파일을 읽을 수 없음: {logfile}"
    return f"로그가 {int(age)}분째 새 기록 없음(Caddy 멈춤 또는 매우 조용한 시간)" if age >= minutes else ""


def daily_due(now, daily_at, last_sent):
    """오늘 요약을 보낼 때인가 — 설정 시각이 지났고, 오늘 아직 안 보냈으면."""
    if not daily_at:
        return False
    try:
        hh, mm = (int(x) for x in str(daily_at).split(":"))
    except ValueError:
        return False
    return (now.hour, now.minute) >= (hh, mm) and last_sent != now.strftime("%Y-%m-%d")


def get_meta(conn, key, default=""):
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row[0] if row else default


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES(?,?)", (key, str(value)))
    conn.commit()


def build_dashboard_payload(results, dist, timeline=None):
    """탐지 결과(dict) → 화면이 읽을 JSON-안전 자료. '자료/보여주기 분리' 원칙 그대로.

    datetime 은 그대로는 JSON 이 못 되므로 문자열(_iso)로 바꾼다.
    timeline(개별 공격 시간 순 목록)은 바깥에서 만들어(로그 또는 DB) 넘겨준다.
    """
    alerts = [r for r in results if r["level"] == "alert"]
    watches = [r for r in results if r["level"] == "watch"]
    rows = []
    for r in results:
        rows.append({
            "ip": r["ip"], "score": r["score"], "level": r["level"],
            "distinct_paths": r["distinct_paths"], "nf": r["nf"],
            "auth": r["auth"], "probes": r["probes"], "tool": r["tool"],
            "rate": r["rate"], "reasons": r["reasons"], "reqs": r.get("reqs", 0),
            "first": _iso(r["first"]), "last": _iso(r["last"]),
            "time": r["last"].strftime("%H:%M:%S") if r["last"] else "—",
        })
    # Top 패널 (GoAccess 식) — 한눈에 '누가·어디를' 가장 많이 노렸는지.
    top_ips = sorted(
        ({"ip": r["ip"], "count": r.get("reqs") or (r["nf"] + r["auth"] + r["probes"]),
          "level": r["level"], "score": r["score"]} for r in rows),
        key=lambda x: (x["count"], x["score"]), reverse=True)[:6]
    top_paths = [{"path": p, "count": c}
                 for p, c in Counter(t["path"] for t in (timeline or [])).most_common(6)]
    return {
        "generated": datetime.now().strftime("%H:%M:%S"),
        "ip_count": len(results),                 # 공격 의심 IP 수
        "alert_count": len(alerts),               # 위험(경보)
        "watch_count": len(watches),              # 경고(관찰)
        # '공격 요청(건)' = 탐지된 공격자 IP 들이 보낸 요청 수(reqs).
        # 상태코드와 무관 — 리다이렉트(307) 서버에서도 실제 공격량이 숫자로 잡힌다.
        # (reqs 는 _SKIP·신뢰 IP 를 뺀 수라, 소음은 세지 않고 한 요청을 한 번만 센다.)
        "attempt_count": sum(r["reqs"] for r in results),
        "alerts": rows,
        "dist": dist,
        "timeline": timeline or [],   # 개별 공격 시간 순(최근 먼저) — 바깥에서 만들어 넘김
        "top_ips": top_ips,           # 가장 많이 공격한 IP (Top 6)
        "top_paths": top_paths,       # 가장 많이 노린 경로 (Top 6)
    }


# 상황판 화면 — 순수 HTML/CSS/JS 한 장(외부 라이브러리 0). 자료는 /api/alerts 로 받아온다.
_DASHBOARD_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__LS_BRAND__ 실시간 침입 감시</title>
<style>
  :root {
    color-scheme: dark;
    --bg:#0d1117; --panel:#161b22; --inset:#0d1117; --codebg:#010409;
    --border:#222b36; --border2:#30363d; --rowline:#1c232c;
    --text:#e6edf3; --muted:#8b949e; --faint:#6e7681;
    --hover:#1c2330; --stripe:#12171e; --accent:#58a6ff; --mono:#adbac7;
    --dist-bg:#1b1120; --dist-bd:#3d2340; --dist-fg:#e6b3ff;
    --danger:#f85149; --warn:#d29922; --green:#2ea043;
    --bdg-d-bg:#3d1518; --bdg-d-fg:#ff7b72; --bdg-w-bg:#3a2d10; --bdg-w-fg:#e3b341;
    --disc-bg:#1b1813; --disc-bd:#3a2d10; --disc-fg:#e3b341;
    --cmd-fg:#7ee787; --btn-bg:#21262d; --btn-fg:#c9d1d9; --overlay:rgba(0,0,0,.6);
  }
  :root[data-theme="light"] {
    color-scheme: light;
    --bg:#ffffff; --panel:#f6f8fa; --inset:#f6f8fa; --codebg:#f6f8fa;
    --border:#d0d7de; --border2:#d0d7de; --rowline:#eaeef2;
    --text:#1f2328; --muted:#656d76; --faint:#8c959f;
    --hover:#eaf2ff; --stripe:#f6f8fa; --accent:#0969da; --mono:#424a53;
    --dist-bg:#faf2ff; --dist-bd:#e5c8ff; --dist-fg:#8250df;
    --danger:#cf222e; --warn:#9a6700; --green:#1a7f37;
    --bdg-d-bg:#ffe3e1; --bdg-d-fg:#cf222e; --bdg-w-bg:#fff3cd; --bdg-w-fg:#7a5900;
    --disc-bg:#fff8e6; --disc-bd:#f0d98c; --disc-fg:#7a5900;
    --cmd-fg:#116329; --btn-bg:#eaeef2; --btn-fg:#24292f; --overlay:rgba(27,31,36,.35);
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
         font-family:"Segoe UI",system-ui,sans-serif; }
  header { padding:16px 20px; border-bottom:1px solid var(--border);
           display:flex; align-items:center; justify-content:space-between; }
  header h1 { font-size:18px; margin:0; font-weight:600; display:flex; align-items:center; gap:10px; }
  .brand-emoji { font-size:20px; }
  .brand-logo-img { height:30px; background:#fff; border-radius:7px; padding:3px 8px;
                    box-shadow:0 0 0 1px rgba(0,0,0,.08); flex:none; }
  .hr { display:flex; align-items:center; gap:14px; }
  .tbtn { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2);
          border-radius:6px; padding:5px 11px; font-size:12px; cursor:pointer; }
  .tbtn:hover { border-color:var(--accent); }
  #status { font-size:12px; color:var(--muted); }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%;
         background:var(--green); margin-right:6px; vertical-align:middle; animation:pulse 2s infinite; }
  @keyframes pulse { 0%{ box-shadow:0 0 0 0 rgba(46,160,67,.5); }
                     70%{ box-shadow:0 0 0 5px rgba(46,160,67,0); }
                     100%{ box-shadow:0 0 0 0 rgba(46,160,67,0); } }
  .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; padding:20px; }
  @media (max-width:640px){ .tiles{ grid-template-columns:repeat(2,1fr); } }
  .tile { background:var(--panel); border:1px solid var(--border); border-top:3px solid var(--border2);
          border-radius:10px; padding:15px 16px; }
  .tile.danger { border-top-color:var(--danger); }
  .tile.warn { border-top-color:var(--warn); }
  .tile .n { font-size:32px; font-weight:700; line-height:1; font-variant-numeric:tabular-nums; }
  .tile .l { font-size:12px; color:var(--muted); margin-top:8px; letter-spacing:.02em; }
  .tile.danger .n { color:var(--danger); }
  .tile.warn .n { color:var(--warn); }
  .tile.clk { cursor:pointer; transition:border-color .15s, transform .15s; }
  .tile.clk:hover { border-color:var(--accent); transform:translateY(-1px); }
  .tile .more { float:right; color:var(--faint); font-size:11px; }
  .tile.clk:hover .more { color:var(--accent); }
  /* IP 목록 · 조치 기록 화면 (상세창 재사용) */
  .modal.wide { max-width:1040px; }
  .ltab { width:100%; border-collapse:collapse; font-size:13.5px; }
  .ltab th { text-align:left; color:var(--muted); font-weight:500; font-size:12px;
             padding:8px 10px; border-bottom:1px solid var(--border2); white-space:nowrap; }
  .ltab td { padding:9px 10px; border-bottom:1px solid var(--rowline); vertical-align:top; }
  .ltab tbody tr:nth-child(even) td { background:var(--stripe); }
  .ltab .mono { font-family:ui-monospace,Consolas,monospace; }
  .ltab .why { color:var(--muted); font-size:12.5px; }
  .ltab .det { color:var(--faint); font-size:12px; max-width:320px; word-break:break-all; }
  .lbtn { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2);
          border-radius:7px; padding:3px 9px; font-size:12px; cursor:pointer; white-space:nowrap; }
  .lbtn:hover { border-color:var(--accent); }
  .lv { padding:2px 9px; border-radius:20px; font-size:11.5px; font-weight:600; white-space:nowrap; }
  .lv.alert, .lv.failed { background:var(--bdg-d-bg); color:var(--bdg-d-fg); }
  .lv.watch, .lv.refused { background:var(--bdg-w-bg); color:var(--bdg-w-fg); }
  .lv.ok { background:rgba(46,160,67,.15); color:var(--green); }
  .lv.na { background:var(--btn-bg); color:var(--muted); }
  .hsec { font-size:13px; font-weight:600; color:var(--muted); margin:18px 0 8px;
          display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  .hsec:first-child { margin-top:0; }
  .hsec .cnt { color:var(--faint); font-weight:400; }
  .hfil { display:flex; gap:6px; flex-wrap:wrap; margin-left:auto; }
  .hempty { color:var(--faint); font-size:13px; padding:10px 2px; }
  .hscroll { max-height:46vh; overflow:auto; border:1px solid var(--border); border-radius:8px; }
  #dist { padding:0 20px; }
  #dist .d { background:var(--dist-bg); border:1px solid var(--dist-bd); color:var(--dist-fg);
             border-radius:8px; padding:10px 12px; margin-bottom:10px; font-size:14px; }
  .wrap { padding:8px 20px 28px; }
  h2 { font-size:12px; color:var(--faint); font-weight:600; letter-spacing:.04em;
       text-transform:uppercase; margin:18px 4px 10px; }
  h2 .h2sub { font-weight:400; letter-spacing:0; margin-left:8px; opacity:.85; }
  table { width:100%; border-collapse:collapse; font-size:14px; }
  th,td { text-align:left; padding:11px 12px; border-bottom:1px solid var(--rowline); }
  th { color:var(--muted); font-weight:500; font-size:12px; }
  tbody tr:nth-child(even) td { background:var(--stripe); }      /* 줄무늬로 행 구분 */
  tr.alert td:first-child { border-left:3px solid var(--danger); }
  tr.watch td:first-child { border-left:3px solid var(--warn); }
  .ip { font-family:ui-monospace,Consolas,monospace; }
  .path { font-family:ui-monospace,Consolas,monospace; color:var(--mono); font-size:13px; word-break:break-all; }
  td.st { color:var(--muted); }
  .badge { padding:2px 10px; border-radius:20px; font-size:12px; font-weight:600;
           white-space:nowrap; }
  .badge.alert { background:var(--bdg-d-bg); color:var(--bdg-d-fg); }
  .badge.watch { background:var(--bdg-w-bg); color:var(--bdg-w-fg); }
  .empty { padding:44px; text-align:center; color:var(--faint); }
  footer { padding:0 20px 24px; color:var(--faint); font-size:12px; }
  tr.clk { cursor:pointer; }
  tr.clk:hover td { background:var(--hover); }                   /* 마우스 올린 행 강조 */
  /* 상세창(모달) */
  #overlay { position:fixed; inset:0; background:var(--overlay); display:none;
             align-items:flex-start; justify-content:center; padding:28px 16px; z-index:50; }
  #overlay.on { display:flex; }
  .modal { background:var(--panel); border:1px solid var(--border2); border-radius:14px;
           max-width:820px; width:100%; max-height:90vh; overflow:auto; }
  .modal .mh { padding:18px 26px; border-bottom:1px solid var(--border);
               display:flex; align-items:center; justify-content:space-between; position:sticky; top:0;
               background:var(--panel); z-index:1; }
  .modal .mh h3 { margin:0; font-size:19px; }
  .modal .mx { cursor:pointer; color:var(--muted); font-size:22px; background:none; border:none; }
  .modal .mb { padding:22px 26px 26px; }
  .kv { display:grid; grid-template-columns:120px 1fr; gap:11px 18px; font-size:15px; margin-bottom:22px; }
  .kv .k { color:var(--muted); }
  .kv .v { word-break:break-all; }
  .rec { background:var(--inset); border:1px solid var(--border); border-radius:10px; padding:16px 18px; }
  .rec h4 { margin:0 0 10px; font-size:15px; color:var(--accent);
            display:flex; align-items:center; gap:8px; }
  .rec h4 .rtag { font-size:11.5px; font-weight:500; color:var(--faint); letter-spacing:.02em; }
  .disc { background:var(--disc-bg); border:1px solid var(--disc-bd); color:var(--disc-fg);
          border-radius:8px; padding:10px 13px; font-size:13px; line-height:1.55; margin-bottom:13px; }
  .rec ul { margin:10px 0 0; padding-left:20px; }
  .rec li { margin:7px 0; font-size:15px; line-height:1.55; }
  .caution { margin-top:13px; font-size:13.5px; color:var(--warn); line-height:1.55; }
  .sev { padding:2px 10px; border-radius:20px; font-size:12px; font-weight:600; }
  .sev.danger { background:var(--bdg-d-bg); color:var(--bdg-d-fg); }
  .sev.warn { background:var(--bdg-w-bg); color:var(--bdg-w-fg); }
  /* 종류별 보기 탭 */
  .filters { display:flex; flex-wrap:wrap; gap:8px; margin:4px 4px 14px; }
  .fbtn { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2);
          border-radius:20px; padding:5px 13px; font-size:12.5px; cursor:pointer; }
  .fbtn:hover { border-color:var(--accent); }
  .fbtn.on { background:var(--accent); color:#fff; border-color:var(--accent); }
  .fbtn b { font-weight:700; margin-left:3px; }
  .badge.blk { background:var(--bdg-d-bg); color:var(--bdg-d-fg); margin-left:6px; }
  .badge.in { background:rgba(88,166,255,.15); color:var(--accent); margin-left:6px; font-weight:600; }
  td.when { white-space:nowrap; }
  td.when .day { color:var(--muted); margin-right:4px; }
  /* 차단된 IP 띠(되돌리기 버튼 포함) */
  #blocked { padding:0 20px; }
  .bstrip { background:var(--bdg-d-bg); border:1px solid var(--bdg-d-fg); border-radius:8px;
            padding:9px 12px; margin-bottom:10px; font-size:13px;
            display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
  .blab { color:var(--bdg-d-fg); font-weight:600; }
  .bchip { background:var(--panel); border:1px solid var(--border2); border-radius:16px;
           padding:3px 6px 3px 11px; font-family:ui-monospace,Consolas,monospace; font-size:12.5px;
           display:inline-flex; align-items:center; gap:7px; }
  .bchip button { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2);
                  border-radius:12px; padding:1px 9px; font-size:11px; cursor:pointer; }
  /* 상세창 안의 실제 조치 버튼 */
  .actions { margin-top:16px; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
  /* 차분한 위계: 주 동작(차단/해제)만 채움, 나머지는 고스트 — 색 소음을 줄인다 */
  .actbtn { border:1px solid var(--border2); background:var(--btn-bg); color:var(--btn-fg);
            border-radius:8px; padding:8px 13px; font-size:13px; font-weight:600; cursor:pointer; }
  .actbtn:hover { border-color:var(--accent); }
  .actbtn.block { background:var(--danger); color:#fff; border-color:var(--danger); }
  .actbtn.unblock { background:var(--green); color:#fff; border-color:var(--green); }
  .actbtn.temp:hover { border-color:var(--warn); color:var(--warn); }
  .actbtn.subnet:hover { border-color:#8957e5; color:#a371f7; }
  .actbtn.trust:hover { border-color:var(--accent); color:var(--accent); }
  .actbtn.del:hover { border-color:var(--danger); color:var(--danger); }
  .actbtn:hover { opacity:.9; }
  .ahint { font-size:11.5px; color:var(--faint); line-height:1.45; width:100%; margin-top:4px; }
  /* 한 번 더 묻는 확인창 */
  #confirm { position:fixed; inset:0; background:var(--overlay); display:none;
             align-items:center; justify-content:center; padding:24px; z-index:60; }
  #confirm.on { display:flex; }
  .cfbox { background:var(--panel); border:1px solid var(--border2); border-radius:12px;
           max-width:440px; width:100%; overflow:hidden; }
  .cfh { padding:15px 20px; font-size:16px; font-weight:600; border-bottom:1px solid var(--border); }
  .cfb { padding:16px 20px; font-size:14px; line-height:1.6; }
  .cfb p { margin:0 0 8px; }
  .cfb .cf-warn { color:var(--danger); font-weight:600; margin-top:10px; }
  .cff { display:flex; justify-content:flex-end; gap:10px; padding:14px 20px; border-top:1px solid var(--border); }
  .cfbtn { border:none; border-radius:8px; padding:9px 18px; font-size:13.5px; font-weight:600; cursor:pointer; }
  .cfbtn.ghost { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2); }
  .cfbtn.danger { background:var(--danger); color:#fff; }
  .cfbtn.go { background:var(--green); color:#fff; }
  /* 되돌리기(실행 취소) 토스트 */
  #toast { position:fixed; left:50%; bottom:24px; transform:translateX(-50%);
           background:var(--panel); color:var(--text); border:1px solid var(--border2);
           border-radius:10px; padding:11px 14px; font-size:13.5px; display:none;
           align-items:center; gap:14px; box-shadow:0 6px 24px rgba(0,0,0,.35); z-index:70; max-width:92vw; }
  #toast.on { display:flex; }
  #toast span { word-break:break-all; }
  #toast button { background:var(--accent); color:#fff; border:none; border-radius:7px;
                  padding:5px 12px; font-size:12.5px; font-weight:600; cursor:pointer; white-space:nowrap; }
  /* Top 패널 (가장 많이 공격한 IP·경로) */
  .toppanels { display:grid; grid-template-columns:1fr 1fr; gap:12px; padding:4px 20px 0; }
  @media (max-width:640px){ .toppanels{ grid-template-columns:1fr; } }
  .panel { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }
  .panel h3 { margin:0 0 10px; font-size:13px; color:var(--muted); font-weight:600; }
  .prow { position:relative; display:flex; justify-content:space-between; align-items:center;
          gap:10px; padding:6px 8px; border-radius:6px; cursor:pointer; font-size:13px; overflow:hidden; }
  .prow:hover { background:var(--hover); }
  .prow .bar { position:absolute; left:0; top:0; bottom:0; background:var(--stripe); z-index:0; }
  .prow.alert .bar { background:var(--bdg-d-bg); }
  .prow .lbl { position:relative; z-index:1; font-family:ui-monospace,Consolas,monospace;
               white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .prow .cnt { position:relative; z-index:1; color:var(--muted); font-weight:600; flex:none; }
  .panel .pempty { color:var(--faint); font-size:12.5px; padding:6px 8px; }
  /* 툴바(종류별 탭 + 검색) */
  .toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:center; justify-content:space-between; }
  .search { flex:1; min-width:180px; max-width:280px; background:var(--inset); color:var(--text);
            border:1px solid var(--border2); border-radius:8px; padding:7px 11px; font-size:13px; }
  .search:focus { outline:none; border-color:var(--accent); }
  /* 신뢰(오탐) IP 띠 — 차단 띠의 초록 버전 */
  #trusted { padding:0 20px; }
  .tstrip { background:var(--bdg-w-bg); border:1px solid var(--green); border-radius:8px;
            padding:9px 12px; margin-bottom:10px; font-size:13px;
            display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
  .tlab { color:var(--green); font-weight:600; }

  /* ── 보안 콘솔 디자인 다듬기 (Wazuh/Grafana/CrowdSec 참고) ── */
  :root { --radius:10px; }
  body { font-family:"Pretendard","Segoe UI",system-ui,sans-serif;
         background:
           radial-gradient(900px 500px at 88% -8%, rgba(88,166,255,.06), transparent 60%),
           var(--bg); background-attachment:fixed; }
  /* 헤더: 아래 얇은 그라데이션 포인트 라인 */
  header { position:relative; }
  header::after { content:""; position:absolute; left:0; right:0; bottom:-1px; height:2px;
                  background:linear-gradient(90deg, var(--accent), transparent 55%); opacity:.5; }
  header h1 { letter-spacing:-.01em; }
  /* 숫자 타일 */
  .tile { position:relative; overflow:hidden; transition:border-color .15s, transform .15s, box-shadow .15s; }
  .tile .n { font-size:33px; letter-spacing:-.02em; }
  .tile .l { display:flex; align-items:center; gap:7px; }
  .tile .l::before { content:""; width:7px; height:7px; border-radius:50%; background:var(--faint); flex:none; }
  .tile.danger .l::before { background:var(--danger); box-shadow:0 0 7px var(--danger); }
  .tile.warn .l::before { background:var(--warn); box-shadow:0 0 7px var(--warn); }
  .tile.clk:hover { box-shadow:0 6px 20px rgba(0,0,0,.28); }
  /* 테이블 헤더: 소형 대문자 라벨 */
  th { text-transform:uppercase; letter-spacing:.05em; font-size:10.5px; font-weight:600;
       border-bottom:1px solid var(--border2); }
  tbody tr td { transition:background .1s; }
  tr.alert td:first-child { border-left:3px solid var(--danger); }
  tr.watch td:first-child { border-left:3px solid var(--warn); }
  tbody tr.clk:hover td { background:var(--hover); }
  /* 유형 = 심각도 알약 + 상태 점 */
  .kpill { display:inline-flex; align-items:center; gap:6px; padding:2px 10px 2px 8px;
           border-radius:20px; font-size:12px; font-weight:600; white-space:nowrap;
           border:1px solid transparent; }
  .kpill .sdot { width:7px; height:7px; border-radius:50%; flex:none; }
  .kpill.alert { background:var(--bdg-d-bg); color:var(--bdg-d-fg); border-color:rgba(248,81,73,.25); }
  .kpill.alert .sdot { background:var(--danger); box-shadow:0 0 6px var(--danger); }
  .kpill.watch { background:var(--bdg-w-bg); color:var(--bdg-w-fg); border-color:rgba(210,153,34,.25); }
  .kpill.watch .sdot { background:var(--warn); }
  td.st { font-variant-numeric:tabular-nums; }
  /* Top 패널: 막대에 은은한 그라데이션 */
  .panel { box-shadow:0 1px 0 rgba(0,0,0,.15); }
  .prow .bar { background:linear-gradient(90deg, var(--stripe), transparent); }
  .prow.alert .bar { background:linear-gradient(90deg, var(--bdg-d-bg), transparent); }
  .prow:hover { background:var(--hover); }
  /* 타임라인 '전체 삭제' 작은 버튼 */
  .tlbtn { float:right; text-transform:none; letter-spacing:0; font-weight:600; font-size:11px;
           background:var(--btn-bg); color:var(--muted); border:1px solid var(--border2);
           border-radius:7px; padding:3px 10px; cursor:pointer; }
  .tlbtn:hover { border-color:var(--danger); color:var(--danger); }
  /* 모달 */
  .modal { box-shadow:0 20px 60px rgba(0,0,0,.5); }
  .kv .k { text-transform:uppercase; letter-spacing:.04em; font-size:11px; }
  .kv .v.ip, .kv .v.path { font-family:ui-monospace,Consolas,monospace; }
  /* 상단 버튼(헤더) 간격 */
  .hr { gap:8px; }
  /* 앞단(Caddy)에서 거절된 공격 표시 */
  .badge.edge { background:rgba(46,160,67,.15); color:var(--green); border:1px solid rgba(46,160,67,.4);
                font-weight:700; white-space:nowrap; }
  /* 공격 IP 출처 꼬리표 — 종류별 색 */
  .where { display:inline-block; margin-left:6px; padding:1px 8px; border-radius:10px; vertical-align:1px;
           font:600 10.5px "Pretendard","Segoe UI",system-ui,sans-serif; white-space:nowrap;
           background:var(--btn-bg); color:var(--muted); border:1px solid var(--border2); }
  .where.k-cloud   { color:#d2a8ff; background:rgba(163,113,247,.12); border-color:rgba(163,113,247,.45); }
  .where.k-scanner { color:#79c0ff; background:rgba(88,166,255,.10);  border-color:rgba(88,166,255,.40); }
  .where.k-isp     { color:#56d4dd; background:rgba(57,197,207,.10);  border-color:rgba(57,197,207,.40); }
  :root[data-theme="light"] .where.k-cloud   { color:#8250df; }
  :root[data-theme="light"] .where.k-scanner { color:#0969da; }
  :root[data-theme="light"] .where.k-isp     { color:#1b7c83; }
  .knote { color:var(--muted); font-size:12px; }
  /* 맨 위 신호등 — 초록=조치 필요 없음 / 빨강=확인 필요(사고 의심) / 주황=감시 이상 */
  .lamp { margin:16px 20px 0; border-radius:12px; padding:12px 16px; border:1px solid var(--border2); background:var(--panel); }
  .lamp:empty { display:none; }
  .lamp .lhead { display:flex; align-items:center; gap:10px; flex-wrap:wrap; font-size:14px; }
  .lamp .ldot { width:11px; height:11px; border-radius:50%; flex:none; }
  .lamp .lsub { color:var(--muted); font-size:13px; }
  .lamp .lhead .lbtn { margin-left:auto; }
  .lamp.green { border-color:rgba(46,160,67,.45); background:rgba(46,160,67,.08); }
  .lamp.green .ldot { background:var(--green); box-shadow:0 0 8px var(--green); }
  .lamp.green b { color:var(--green); }
  .lamp.red { border-color:var(--danger); background:rgba(248,81,73,.08); }
  .lamp.red .ldot { background:var(--danger); box-shadow:0 0 10px var(--danger); animation:lpulse 1.4s infinite; }
  .lamp.red b { color:var(--danger); }
  .lamp.orange { border-color:var(--warn); background:rgba(210,153,34,.08); }
  .lamp.orange .ldot { background:var(--warn); box-shadow:0 0 8px var(--warn); }
  .lamp.orange b { color:var(--warn); }
  @keyframes lpulse { 50% { opacity:.35; } }
  @media (prefers-reduced-motion: reduce) { .lamp.red .ldot { animation:none; } }
  .lamp .lrow { display:flex; align-items:center; gap:12px; flex-wrap:wrap; padding:8px 0 2px; margin-top:8px;
                border-top:1px solid var(--rowline); font-size:13px; }
  .lamp .ltag { background:var(--bdg-d-bg); color:var(--bdg-d-fg); border-radius:10px; padding:1px 9px; font-weight:700; font-size:12px; }
  .lamp .ltitle { flex:1; min-width:200px; }
  .lamp .lbtns { display:flex; gap:6px; }
  .lbtn.ok { border-color:var(--green); color:var(--green); }
  .lamp .ltag.warn { background:var(--bdg-w-bg); color:var(--bdg-w-fg); }
  .lamp .lfoot { margin-top:8px; font-size:12px; color:var(--muted); display:flex; align-items:center; gap:6px; flex-wrap:wrap; }
  /* 여러 건 선택 삭제 */
  .chkcol { width:34px; text-align:center; padding-left:12px; }
  .rchk, #selall { width:15px; height:15px; cursor:pointer; accent-color:var(--accent); vertical-align:middle; }
  tr.sel td { background:rgba(88,166,255,.10) !important; }
  tr.sel td:first-child { border-left-color:var(--accent); }
  .selbar { display:none; }
  .selbar.on { display:flex; align-items:center; gap:10px; margin:0 4px 10px;
               background:var(--panel); border:1px solid var(--accent); border-radius:9px;
               padding:8px 13px; font-size:13px; }
  .selbar b { color:var(--accent); }
  .selbtn { margin-left:2px; border:1px solid var(--border2); background:var(--btn-bg); color:var(--btn-fg);
            border-radius:7px; padding:5px 12px; font-size:12.5px; font-weight:600; cursor:pointer; }
  .selbtn:hover { border-color:var(--accent); }
  .selbtn.del { background:var(--danger); color:#fff; border-color:var(--danger); }
  .selbtn.del:hover { opacity:.9; }
</style>
</head>
<body>
  <header>
    <h1>__LS_LOGO__ <span>__LS_BRAND__ — 실시간 침입 감시</span></h1>
    <div class="hr">
      <button class="tbtn" onclick="openHistory()">📋 조치 기록</button>
      <button class="tbtn" onclick="openDeleted()">🗑 삭제함</button>
      <button id="pauseBtn" class="tbtn" onclick="togglePause()">⏸ 일시정지</button>
      <button id="themeBtn" class="tbtn" onclick="toggleTheme()">☀ 밝게</button>
      <span id="status"><span class="dot"></span>연결 중…</span>
    </div>
  </header>

  <div id="lamp" class="lamp"></div>

  <div class="tiles">
    <div class="tile clk" onclick="tileClick('attempt')" title="클릭: 공격 요청 전체를 타임라인에서 보기">
      <div class="n" id="attempt">0</div><div class="l">공격 요청(건) <span class="more">보기 ›</span></div></div>
    <div class="tile warn clk" onclick="tileClick('watch')" title="클릭: 경고 단계 IP 목록">
      <div class="n" id="warn">0</div><div class="l">경고 <span class="more">보기 ›</span></div></div>
    <div class="tile danger clk" onclick="tileClick('alert')" title="클릭: 위험 단계 IP 목록">
      <div class="n" id="danger">0</div><div class="l">위험 <span class="more">보기 ›</span></div></div>
    <div class="tile clk" onclick="tileClick('all')" title="클릭: 공격 의심 IP 전체 목록">
      <div class="n" id="ipc">0</div><div class="l">공격 의심 IP <span class="more">보기 ›</span></div></div>
  </div>

  <div id="toppanels" class="toppanels"></div>
  <div id="dist"></div>
  <div id="blocked"></div>
  <div id="trusted"></div>

  <div class="wrap">
    <h2>종류별로 보기</h2>
    <div class="toolbar">
      <div id="filters" class="filters"></div>
      <input id="search" class="search" type="search" oninput="onSearch(this.value)"
             placeholder="🔎 IP·경로·도구 검색…">
    </div>
    <h2>실시간 타임라인 <span class="h2sub">줄 클릭 → 상세·조치</span>
      <button class="tlbtn" onclick="doDeleteAll()">🗑 전체 삭제</button></h2>
    <div id="selbar" class="selbar"></div>
    <table>
      <thead><tr>
        <th class="chkcol"><input type="checkbox" id="selall" onclick="toggleSelAll(this)" title="보이는 줄 전체 선택"></th>
        <th>날짜·시각</th><th>IP</th><th>노린 경로</th><th>유형</th><th>상태</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <footer>__LS_BRAND__ · 탐지 · 기록(DB) · 차단 · 3초마다 자동 갱신</footer>

  <div id="overlay" onclick="if(event.target===this)closeDetail()">
    <div class="modal">
      <div class="mh"><h3 id="m-title">침투 상세</h3><button class="mx" onclick="closeDetail()">✕</button></div>
      <div class="mb" id="m-body"></div>
    </div>
  </div>

  <!-- 한 번 더 묻는 확인창 -->
  <div id="confirm">
    <div class="cfbox">
      <div class="cfh" id="cf-title">확인</div>
      <div class="cfb" id="cf-body"></div>
      <div class="cff">
        <button class="cfbtn ghost" id="cf-cancel">취소</button>
        <button class="cfbtn danger" id="cf-ok">확인</button>
      </div>
    </div>
  </div>

  <!-- 되돌리기(실행 취소) 토스트 -->
  <div id="toast"></div>

<script>
function esc(s){ return String(s).replace(/[&<>"]/g,
  function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }

// 밝게/어둡게 테마 전환 — 고른 값을 브라우저에 기억(다음에 켜도 유지)
function applyTheme(t){
  document.documentElement.setAttribute('data-theme', t);
  var b = document.getElementById('themeBtn');
  if(b){ b.textContent = (t === 'light') ? '🌙 어둡게' : '☀ 밝게'; }
  try { localStorage.setItem('ls-theme', t); } catch(e) {}
}
function toggleTheme(){
  var cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'light' ? 'dark' : 'light');
}
(function(){ try { var s = localStorage.getItem('ls-theme'); if(s){ applyTheme(s); } } catch(e) {} })();

function setStatus(ok, t){
  var el = document.getElementById('status');
  el.innerHTML = ok
    ? '<span class="dot"></span>연결됨 · 갱신 ' + esc(t)
    : '<span class="dot" style="background:#f85149"></span>연결 끊김 — 재시도 중';
}

var LAST = [];          // 최근 타임라인(상세창·필터에서 꺼내 씀)
var BLOCKED = [];       // 현재 차단 중인 IP 목록
var TRUSTED = [];       // 신뢰(오탐 처리) IP 목록
var IPINFO = {}, IP_LOOKUP = false;   // 공격 IP 출처(나라·기관·종류) — 설정 ip_lookup 일 때 서버가 채움
var FILTER = '전체';    // 지금 고른 종류별 필터
var KINDS = [];         // 탭에 뜬 종류 순서
var SEARCH = '';        // 검색어(IP·경로·도구)
var PAUSED = false;     // 자동 새로고침 일시정지
var ALERTS = [];        // IP별 탐지 결과(단계·점수·이유) — 위 숫자 칸 클릭 시 목록
var LISTROWS = [];      // 지금 띄운 IP 목록(버튼은 인덱스로 참조 — 문자열을 onclick 에 넣지 않음)
var HISTORY_OPEN = false, HIST = null, HFILTER = 0;
var DETAIL = null;                 // 지금 상세창에 띄운 공격 한 건(삭제에 사용)
var DELETED_OPEN = false, DELROWS = [];   // 삭제함 화면 상태

function render(d){
  document.getElementById('attempt').textContent = d.attempt_count;
  document.getElementById('warn').textContent    = d.watch_count;
  document.getElementById('danger').textContent  = d.alert_count;
  document.getElementById('ipc').textContent     = d.ip_count;

  var dist = d.dist || [];
  document.getElementById('dist').innerHTML = dist.map(function(x){
    return '<div class="d">🌐 ' + esc(x.kind) + ' — 서로 다른 IP '
         + x.ips + '개 (한 ' + x.window + '초 창)</div>';
  }).join('');

  LAST = d.timeline || [];
  ALERTS = d.alerts || [];
  BLOCKED = d.blocked || [];
  TRUSTED = d.trusted || [];
  IPINFO = d.ipinfo || {}; IP_LOOKUP = !!d.ip_lookup;
  renderTop(d);
  renderLamp(d);
  renderBlocked();
  renderTrusted();
  renderFilters();
  renderRows();
}

// Top 패널 — 가장 많이 공격한 IP·경로(막대 길이=횟수). 클릭하면 그 값으로 검색.
function renderTop(d){
  var ips = d.top_ips || [], paths = d.top_paths || [];
  var maxI = ips.length ? ips[0].count : 1;
  var maxP = paths.length ? paths[0].count : 1;
  var ipRows = ips.length ? ips.map(function(x){
    var w = Math.max(6, Math.round(x.count / maxI * 100));
    return '<div class="prow ' + (x.level === 'alert' ? 'alert' : '') + '" title="클릭=이 IP로 검색" '
      + 'onclick="onSearch(&#39;' + esc(x.ip) + '&#39;, true)">'
      + '<span class="bar" style="width:' + w + '%"></span>'
      + '<span class="lbl">' + esc(x.ip) + inBadge(x.ip) + whereHtml(x.ip) + '</span><span class="cnt">' + x.count + '</span></div>';
  }).join('') : '<div class="pempty">아직 없음 👍</div>';
  var pathRows = paths.length ? paths.map(function(x){
    var w = Math.max(6, Math.round(x.count / maxP * 100));
    return '<div class="prow" title="클릭=이 경로로 검색" '
      + 'onclick="onSearch(&#39;' + esc(x.path) + '&#39;, true)">'
      + '<span class="bar" style="width:' + w + '%"></span>'
      + '<span class="lbl">' + esc(x.path) + '</span><span class="cnt">' + x.count + '</span></div>';
  }).join('') : '<div class="pempty">아직 없음 👍</div>';
  document.getElementById('toppanels').innerHTML =
      '<div class="panel"><h3>🎯 가장 많이 공격한 IP</h3>' + ipRows + '</div>'
    + '<div class="panel"><h3>📂 가장 많이 노린 경로</h3>' + pathRows + '</div>';
}

// 신뢰(오탐) IP 띠 — 각 IP 옆에 '다시 탐지'(되돌리기) 버튼
function renderTrusted(){
  var el = document.getElementById('trusted');
  if(!TRUSTED.length){ el.innerHTML = ''; return; }
  el.innerHTML = '<div class="tstrip"><span class="tlab">✅ 신뢰 IP · 오탐 처리 ('
    + TRUSTED.length + ')</span>'
    + TRUSTED.map(function(ip){
        return '<span class="bchip">' + esc(ip)
          + '<button onclick="untrustIp(&#39;' + esc(ip) + '&#39;)">다시 탐지</button></span>';
      }).join('')
    + '</div>';
}

// 차단된 IP 띠 — 각 IP 옆에 '해제'(되돌리기) 버튼
function renderBlocked(){
  var el = document.getElementById('blocked');
  if(!BLOCKED.length){ el.innerHTML = ''; return; }
  el.innerHTML = '<div class="bstrip"><span class="blab">🚫 차단된 IP ('
    + BLOCKED.length + ')</span>'
    + BLOCKED.map(function(ip){
        return '<span class="bchip">' + esc(ip)
          + '<button onclick="unblockIp(&#39;' + esc(ip) + '&#39;)">해제</button></span>';
      }).join('')
    + '</div>';
}

// 종류별 보기 탭 — 현재 타임라인에서 유형별 개수를 세어 버튼으로
function renderFilters(){
  var counts = {}, order = [];
  LAST.forEach(function(e){
    if(!(e.kind in counts)){ counts[e.kind] = 0; order.push(e.kind); }
    counts[e.kind]++;
  });
  KINDS = order;
  if(FILTER !== '전체' && order.indexOf(FILTER) < 0){ FILTER = '전체'; }
  var h = '<button class="fbtn' + (FILTER === '전체' ? ' on' : '')
        + '" onclick="setFilter(-1)">전체<b>' + LAST.length + '</b></button>';
  order.forEach(function(k, idx){
    h += '<button class="fbtn' + (FILTER === k ? ' on' : '')
       + '" onclick="setFilter(' + idx + ')">' + esc(k) + '<b>' + counts[k] + '</b></button>';
  });
  document.getElementById('filters').innerHTML = h;
}
function setFilter(idx){ FILTER = (idx < 0) ? '전체' : KINDS[idx]; renderFilters(); renderRows(); }

// 검색창 입력(또는 Top 패널 클릭). focus=true면 검색창에 값을 채워 맞춰 준다.
function onSearch(v, focus){
  SEARCH = (v || '').toLowerCase().trim();
  if(focus){ var s = document.getElementById('search'); if(s){ s.value = v; } }
  renderRows();
}
function matchSearch(e){
  if(!SEARCH){ return true; }
  return (e.ip + ' ' + e.path + ' ' + (e.ua || '') + ' ' + e.kind).toLowerCase().indexOf(SEARCH) >= 0;
}

// 타임라인 표 — FILTER + 검색어로 추려 그린다(원래 인덱스를 유지해 상세창이 정확히 열림)
function renderRows(){
  var out = [], shown = 0;
  for(var i = 0; i < LAST.length; i++){
    var e = LAST[i];
    if(FILTER !== '전체' && e.kind !== FILTER){ continue; }
    if(!matchSearch(e)){ continue; }
    shown++;
    var cls = e.severity === '위험' ? 'alert' : 'watch';   // 위험=빨강, 경고=주황
    var kpill = '<span class="kpill ' + cls + '"><span class="sdot"></span>' + esc(e.kind) + '</span>';
    if(e.edge_blocked){ kpill += ' <span class="badge edge" title="앞단(Caddy)에서 거절 — 앱까지 안 감">🛡 앞단 차단</span>'; }
    var tool = e.tool ? ' <span class="badge watch">도구</span>' : '';
    var blk = (BLOCKED.indexOf(e.ip) >= 0) ? ' <span class="badge blk">차단됨</span>' : '';
    var chk = SEL[rowKey(e)] ? ' checked' : '';
    out.push('<tr class="clk ' + cls + (chk ? ' sel' : '') + '" onclick="openDetail(' + i + ')">'
      + '<td class="chkcol"><input type="checkbox" class="rchk"' + chk
      + ' onclick="event.stopPropagation();toggleSel(' + i + ')"></td>'
      + '<td class="ip when">' + whenHtml(e) + '</td>'
      + '<td class="ip">' + esc(e.ip) + inBadge(e.ip) + whereHtml(e.ip) + blk + '</td>'
      + '<td class="path">' + esc(e.path) + '</td>'
      + '<td>' + kpill + tool + '</td>'
      + '<td class="st">' + e.status + '</td>'
      + '</tr>');
  }
  document.getElementById('rows').innerHTML = out.length ? out.join('')
    : '<tr><td colspan="6" class="empty">' + (SEARCH ? '검색 결과가 없습니다' : '해당 종류의 공격 기록이 없습니다 👍') + '</td></tr>';
  renderSelBar();
  syncSelAll();
}

// ── 여러 건 선택 삭제 ── (선택은 줄 고유키로 기억 → 새로고침돼도 체크 유지)
var SEL = {};
function rowKey(e){ return (e.ip || '') + '|' + (e.ts_iso || '') + '|' + (e.path || '') + '|' + e.status; }
function selItems(){
  var out = [];
  for(var k in SEL){ var e = SEL[k]; out.push({ts: e.ts_iso || '', ip: e.ip, path: e.path, status: e.status}); }
  return out;
}
function selCount(){ return Object.keys(SEL).length; }
function toggleSel(i){
  var e = LAST[i]; if(!e){ return; }
  var k = rowKey(e);
  if(SEL[k]){ delete SEL[k]; } else { SEL[k] = e; }
  renderRows();   // 선택 표시·선택바·전체선택 체크를 한 번에 갱신
}
function toggleSelAll(box){
  // 지금 '보이는'(필터·검색 통과) 줄 전체를 선택/해제
  var any = box.checked;
  for(var i = 0; i < LAST.length; i++){
    var e = LAST[i];
    if(FILTER !== '전체' && e.kind !== FILTER){ continue; }
    if(!matchSearch(e)){ continue; }
    var k = rowKey(e);
    if(any){ SEL[k] = e; } else { delete SEL[k]; }
  }
  renderRows();
}
function syncSelAll(){
  var box = document.getElementById('selall'); if(!box){ return; }
  var vis = 0, sel = 0;
  for(var i = 0; i < LAST.length; i++){
    var e = LAST[i];
    if(FILTER !== '전체' && e.kind !== FILTER){ continue; }
    if(!matchSearch(e)){ continue; }
    vis++; if(SEL[rowKey(e)]){ sel++; }
  }
  box.checked = vis > 0 && sel === vis;
  box.indeterminate = sel > 0 && sel < vis;
}
function clearSel(){ SEL = {}; renderRows(); }
function renderSelBar(){
  var n = selCount();
  var el = document.getElementById('selbar');
  if(!n){ el.className = 'selbar'; el.innerHTML = ''; return; }
  el.className = 'selbar on';
  el.innerHTML = '<span><b>' + n + '건</b> 선택됨</span>'
    + '<button class="selbtn del" onclick="doDeleteSelected()">🗑 선택 삭제</button>'
    + '<button class="selbtn" onclick="clearSel()">선택 해제</button>';
  syncSelAll();
}
function doDeleteSelected(){
  var items = selItems(); if(!items.length){ return; }
  askConfirm({title:'선택 삭제', confirmLabel:'삭제', danger:true, twoStep:false,
    lines:[items.length + '건을 목록에서 지웁니다.', '삭제함으로 옮겨져 복구할 수 있어요.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/log/delete_many', {items: items}).then(function(res){
        SEL = {};
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
          res.ok ? function(){ postJSON('/api/log/restore_many', {items: items}).then(function(){ tick(); }); } : null);
        afterAction();
      });
    });
}

// ── 조치 공통 도구: 서버 요청 / 한 번 더 묻는 확인창 / 되돌리기 토스트 ──
var LS_TOKEN = '__LS_TOKEN__';   // 서버가 화면을 내줄 때 심는 비밀 표(조치 요청 확인용)
function postJSON(url, obj){
  return fetch(url, {method:'POST', headers:{'Content-Type':'application/json', 'X-LogSentry-Token': LS_TOKEN},
                     body: JSON.stringify(obj)})
    .then(function(r){
      if(r.status === 403){   // 상황판이 다시 켜져 비밀 표가 바뀐 경우가 대부분
        return {ok:false, message:'상황판이 다시 시작돼서 보안 표가 바뀌었어요. Ctrl+Shift+R 로 새로고침한 뒤 다시 눌러주세요.'};
      }
      return r.json();
    })
    .catch(function(){ return {ok:false, message:'요청 실패 — 서버 연결을 확인하세요.'}; });
}
// 사내·이 PC 주소인가 — 화면에 '사내' 표시(공격자로 오해하지 않게). 정규식 없이(파이썬 문자열 안이라 역슬래시 회피)
// 공격 IP 출처 표시 — IP 옆 작은 꼬리표(나라 · 종류). 등록 정보는 남이 쓴 글이라 반드시 esc.
function whereHtml(ip){
  var i = IPINFO[ip];
  if(!i || !i.ok){ return ''; }
  var c = i.country_ko || i.country || '';
  var t = (c ? c + ' · ' : '') + (i.kind_short || '');
  var tip = [i.kind_label, i.org, i.net, i.rdns].filter(function(x){ return x; }).join(' · ');
  return ' <span class="where k-' + esc(i.kind || 'unknown') + '" title="' + esc(tip) + '">' + esc(t) + '</span>';
}
// 상세창용 출처 줄들(출처·네트워크·역방향 이름·추정 유형)
function ipDetailRows(ip){
  if(isLocalIp(ip)){ return '<div class="k">출처</div><div class="v">사내·사설 주소 (밖에 조회하지 않음)</div>'; }
  if(!IP_LOOKUP){ return ''; }
  var i = IPINFO[ip];
  if(!i){ return '<div class="k">출처</div><div class="v knote">조회 중… 잠시 뒤 다시 열어 보세요</div>'; }
  if(!i.ok){ return '<div class="k">출처</div><div class="v knote">조회 실패 — 1시간 뒤 자동으로 다시 시도</div>'; }
  var c = (i.country_ko || '') + (i.country ? ' (' + i.country + ')' : '');
  return '<div class="k">출처</div><div class="v">' + esc(c || '나라 정보 없음') + (i.org ? ' · ' + esc(i.org) : '') + '</div>'
    + '<div class="k">네트워크</div><div class="v ip">' + esc(i.net || '-') + (i.cidr ? ' · ' + esc(i.cidr) : '') + '</div>'
    + (i.rdns ? '<div class="k">역방향 이름</div><div class="v ip">' + esc(i.rdns) + '</div>' : '')
    + '<div class="k">추정 유형</div><div class="v"><span class="where k-' + esc(i.kind || 'unknown') + '">'
    + esc(i.kind_label || '') + '</span> <span class="knote">' + esc(i.kind_note || '') + '</span></div>';
}
function isLocalIp(ip){
  ip = String(ip || '');
  if(ip === '::1' || ip.indexOf('fe80:') === 0 || ip.indexOf('fc') === 0 || ip.indexOf('fd') === 0){ return true; }
  var p = ip.split('.');
  if(p.length !== 4){ return false; }
  var a = parseInt(p[0], 10), b = parseInt(p[1], 10);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
}
function inBadge(ip){ return isLocalIp(ip) ? ' <span class="badge in" title="사무실 안 또는 이 PC 주소">사내</span>' : ''; }
// 타임라인 날짜·시각 — 오늘이면 '오늘', 아니면 '월-일'
function pad2(n){ return (n < 10 ? '0' : '') + n; }
function todayStr(){ var d = new Date(); return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()); }
function whenHtml(e){
  var day = String(e.ts_iso || '').slice(0, 10);
  if(day.length !== 10){ return esc(e.time); }
  var label = (day === todayStr()) ? '오늘' : day.slice(5);
  return '<span class="day">' + esc(label) + '</span>' + esc(e.time);
}
function subnet24(ip){ var p = ip.split('.'); return p[0]+'.'+p[1]+'.'+p[2]+'.0/24'; }

// 한 번 더 묻는 확인창(심각한 건 twoStep=첫 클릭은 '한 번 더'). 약속(Promise)으로 true/false 반환.
function askConfirm(opts){
  return new Promise(function(resolve){
    var ov = document.getElementById('confirm');
    var btn = document.getElementById('cf-ok');
    var cancel = document.getElementById('cf-cancel');
    document.getElementById('cf-title').textContent = opts.title || '확인';
    document.getElementById('cf-body').innerHTML =
      (opts.lines || []).map(function(l){ return '<p>' + esc(l) + '</p>'; }).join('');
    btn.className = 'cfbtn ' + (opts.danger ? 'danger' : 'go');
    btn.textContent = opts.confirmLabel || '확인';
    var armed = !opts.twoStep;
    var finish = function(v){ ov.classList.remove('on'); btn.onclick = null; cancel.onclick = null; resolve(v); };
    btn.onclick = function(){
      if(!armed){ armed = true;
        btn.textContent = '한 번 더 확인 — ' + (opts.confirmLabel || '확인');
        document.getElementById('cf-body').innerHTML +=
          '<p class="cf-warn">⚠ 되돌리려면 직접 해제해야 합니다. 정말 진행할까요?</p>';
        return; }
      finish(true);
    };
    cancel.onclick = function(){ finish(false); };
    ov.classList.add('on');
  });
}

// 조치 후 8초간 '실행 취소' 버튼을 띄운다(실수로 눌러도 되돌릴 수 있게).
var __toastTimer = null;
// ── 맨 위 신호등 + '뚫렸나?' 사고 목록 — 비전문가가 10초 안에 '괜찮은지' 알게 ──
var INCIDENTS = [], INCHIST = [], TODAY = null;
var INC_TYPE_KO = {exposure:'노출 의심', attack_ok:'공격 성공 의심', login:'수상한 로그인'};
function renderLamp(d){
  INCIDENTS = d.incidents || [];
  TODAY = d.today || null;
  var el = document.getElementById('lamp');
  if(!el){ return; }
  var H = d.health || {}, probs = H.problems || [], ch = d.notify || [];
  var hist = '<button class="lbtn" onclick="openIncidentHistory()">사고 기록</button>';
  var probRows = probs.map(function(p){
    return '<div class="lrow"><span class="ltag warn">감시 이상</span><span class="ltitle">' + esc(p) + '</span></div>';
  }).join('');
  var foot = '<div class="lfoot">'
    + (ch.length ? '🔔 알림: ' + esc(ch.join('·')) + ' <button class="lbtn" onclick="testNotify()">알림 시험</button>'
                 : '🔕 알림 미설정 — 화면을 봐야만 알 수 있어요(설정 notify)')
    + (H.watching ? ' · 🩺 사이트·로그 감시 중' + (H.at ? ' (' + esc(H.at) + ')' : '') : '')
    + '</div>';
  if(INCIDENTS.length){
    el.className = 'lamp red';
    el.innerHTML = '<div class="lhead"><span class="ldot"></span><b>확인 필요 ' + INCIDENTS.length + '건</b>'
      + '<span class="lsub">막힌 시도가 아니라 실제 사고일 수 있는 기록이에요. 하나씩 보고 [확인함]을 눌러 주세요.</span>' + hist + '</div>'
      + INCIDENTS.map(function(x, i){
          return '<div class="lrow"><span class="ltag">' + esc(INC_TYPE_KO[x.type] || x.type) + '</span>'
            + '<span class="mono">' + esc(fmtTs(x.ts)) + '</span>'
            + '<span class="mono">' + esc(x.ip) + inBadge(x.ip) + whereHtml(x.ip) + '</span>'
            + '<span class="ltitle">' + esc(x.title) + '</span>'
            + '<span class="lbtns"><button class="lbtn" onclick="openIncident(' + i + ')">자세히</button>'
            + '<button class="lbtn ok" onclick="ackIncident(' + i + ', true)">확인함</button></span></div>';
        }).join('') + probRows + foot;
  } else if(probs.length){
    el.className = 'lamp orange';
    el.innerHTML = '<div class="lhead"><span class="ldot"></span><b>감시 이상 ' + probs.length + '건</b>'
      + '<span class="lsub">공격 사고는 아니지만, 사이트나 기록이 멈췄을 수 있어요. 서버를 확인해 주세요.</span>' + hist + '</div>'
      + probRows + foot;
  } else {
    el.className = 'lamp green';
    var t = TODAY ? ('오늘 공격 시도 ' + TODAY.attempts + '건 — 사고 의심 0건'
                     + (TODAY.attempts ? ' (그중 차단·거절 ' + TODAY.blocked + '건)' : '')) : '사고 의심 0건';
    el.innerHTML = '<div class="lhead"><span class="ldot"></span><b>조치 필요 없음</b><span class="lsub">'
      + esc(t) + '</span>' + hist + '</div>' + foot;
  }
}
function testNotify(){
  postJSON('/api/notify/test', {}).then(function(res){
    showUndo((res.ok ? '✅ 알림 시험 보냄 — ' : '⚠ ') + (res.message || ''), null);
  });
}
function incidentBody(x){
  var rs = (x.reasons || []).map(function(r){ return '<li>' + esc(r) + '</li>'; }).join('');
  return '<div class="kv">'
    + '<div class="k">종류</div><div class="v">' + esc(INC_TYPE_KO[x.type] || x.type) + ' — ' + esc(x.title) + '</div>'
    + '<div class="k">시각</div><div class="v ip">' + esc(x.ts) + '</div>'
    + '<div class="k">IP</div><div class="v ip">' + esc(x.ip) + inBadge(x.ip) + '</div>'
    + ipDetailRows(x.ip)
    + '<div class="k">요청</div><div class="v path">' + esc(x.method) + ' ' + esc(x.path) + ' → ' + esc(x.status) + '</div>'
    + '</div>'
    + '<div class="rec"><h4>왜 사고로 봤나</h4><ul>' + rs + '</ul>'
    + '<h4>지금 할 일</h4><div>' + esc(x.advice) + '</div></div>';
}
function openIncident(i){
  var x = INCIDENTS[i]; if(!x){ return; }
  HISTORY_OPEN = false; DELETED_OPEN = false;
  showModal('🔴 사고 의심 — 확인 필요', incidentBody(x)
    + '<div class="actions">'
    + '<button class="actbtn unblock" onclick="ackIncident(' + i + ', true)">✅ 확인함(처리 완료)</button>'
    + (isLocalIp(x.ip) ? '' : '<button class="actbtn temp" onclick="doBlock(&#39;' + esc(x.ip) + '&#39;,&#39;ip&#39;,0)">🚫 이 IP 차단</button>')
    + '<button class="actbtn evic" onclick="doEvidence(&#39;' + esc(x.ip) + '&#39;)">💾 증거 저장</button>'
    + '<div class="ahint">확인함은 지우는 게 아니에요 — 사고 기록에서 다시 열 수 있어요</div></div>', false);
}
function ackIncident(i, flag){
  var x = INCIDENTS[i]; if(!x){ return; }
  postJSON('/api/incident/ack', {key: x.key, ack: flag}).then(function(res){
    showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
      res.ok ? function(){ postJSON('/api/incident/ack', {key: x.key, ack: !flag}).then(function(){ tick(); }); } : null);
    afterAction();
  });
}
function openIncidentHistory(){
  HISTORY_OPEN = false; DELETED_OPEN = false;
  showModal('📕 사고 기록', '<div class="hempty">불러오는 중…</div>', true);
  fetch('/api/incidents', {cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){ INCHIST = d.rows || []; renderIncidentHistory(); })
    .catch(function(){ document.getElementById('m-body').innerHTML = '<div class="hempty">불러오지 못했어요.</div>'; });
}
function renderIncidentHistory(){
  if(!INCHIST.length){
    document.getElementById('m-body').innerHTML = '<div class="hempty">사고 의심 기록이 없어요 👍 (막힌 공격은 여기 오지 않아요)</div>';
    return;
  }
  document.getElementById('m-body').innerHTML =
    '<div class="disc">성공 응답을 받은 공격과 수상한 로그인 성공만 모아요. 막힌 시도는 타임라인에 있어요.</div>'
    + '<div class="hscroll"><table class="ltab"><thead><tr><th>시각</th><th>종류</th><th>IP</th><th>내용</th><th>상태</th><th></th></tr></thead><tbody>'
    + INCHIST.map(function(x, i){
        return '<tr><td class="mono">' + esc(fmtTs(x.ts)) + '</td><td>' + esc(INC_TYPE_KO[x.type] || x.type) + '</td>'
          + '<td class="mono">' + esc(x.ip) + whereHtml(x.ip) + '</td><td class="why">' + esc(x.title) + '</td>'
          + '<td>' + (x.ack ? '<span class="lv watch">확인함</span>' : '<span class="lv alert">확인 필요</span>') + '</td>'
          + '<td style="white-space:nowrap"><button class="lbtn" onclick="histIncident(' + i + ')">자세히</button> '
          + '<button class="lbtn" onclick="histAck(' + i + ')">' + (x.ack ? '다시 열기' : '확인함') + '</button></td></tr>';
      }).join('') + '</tbody></table></div>';
}
function histIncident(i){
  var x = INCHIST[i]; if(!x){ return; }
  showModal('📕 사고 기록 — ' + esc(INC_TYPE_KO[x.type] || x.type), incidentBody(x)
    + '<div class="actions"><button class="actbtn" onclick="openIncidentHistory()">← 목록으로</button></div>', false);
}
function histAck(i){
  var x = INCHIST[i]; if(!x){ return; }
  postJSON('/api/incident/ack', {key: x.key, ack: !x.ack}).then(function(res){
    showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''), null);
    openIncidentHistory(); tick();
  });
}
function showUndo(msg, undoFn){
  var t = document.getElementById('toast');
  t.innerHTML = '<span>' + esc(msg) + '</span>' + (undoFn ? '<button id="undoBtn">실행 취소</button>' : '');
  t.classList.add('on');
  if(undoFn){ document.getElementById('undoBtn').onclick = function(){ t.classList.remove('on'); undoFn(); }; }
  clearTimeout(__toastTimer);
  __toastTimer = setTimeout(function(){ t.classList.remove('on'); }, 8000);
}

// 차단(영구 ttl=0 / 임시 ttl=초 / 대역 scope='subnet'). 심각한 건 2단계 확인, 성공 시 실행취소 제공.
function doBlock(ip, scope, ttl){
  var title, lines;
  if(scope === 'subnet'){
    title = '대역 차단 (매우 신중히)';
    lines = ['대역 ' + subnet24(ip) + ' 전체(약 254개 IP)를 막습니다.',
             '공격자가 IP를 바꿔가며 올 때 쓰는 강한 조치입니다.',
             '사내 직원 IP가 포함될 수 있으니 특히 신중하세요.'];
  } else if(ttl){
    title = '임시 차단 (' + (ttl/60) + '분)';
    lines = [ip + ' 를 ' + (ttl/60) + '분간 막고 자동으로 풉니다.',
             '실수로 눌러도 시간이 지나면 저절로 해제됩니다.'];
  } else {
    title = '영구 차단';
    lines = [ip + ' 의 들어오는 연결을 계속 막습니다(직접 해제 전까지).',
             '실제 차단은 관리자 권한이 필요합니다.'];
  }
  var severe = (scope === 'subnet') || !ttl;      // 영구·대역 = 한 번 더(2단계)
  askConfirm({title:title, lines:lines, confirmLabel:'차단', danger:true, twoStep:severe})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/block', {ip:ip, scope:scope, ttl:ttl}).then(function(res){
        if(res.ok){
          var key = res.key || ip;
          showUndo('✅ ' + (res.message || '차단됨'), function(){
            postJSON('/api/unblock', {ip:key}).then(function(){ tick(); });
          });
        } else {
          showUndo('⚠ ' + (res.message || '') + (res.detail ? ('  (' + res.detail + ')') : ''), null);
        }
        closeDetail(); tick();
      });
    });
}

// 증거 저장 — 그 IP 침투 기록을 파일로(간단·안전). 경로를 보여줘야 해서 alert 사용.
function doEvidence(ip){
  askConfirm({title:'증거 저장', confirmLabel:'저장', danger:false, twoStep:false,
    lines:[ip + ' 관련 침투 기록을 파일로 내보냅니다.', '보고·신고용 증거로 쓸 수 있어요.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/evidence', {ip:ip}).then(function(res){
        alert((res.ok ? '✅ ' : '⚠ ') + (res.message || ''));
      });
    });
}

// 차단 해제(되돌리기) — 차단된 IP 띠와 상세창에서 호출.
function unblockIp(key){
  askConfirm({title:'차단 해제', confirmLabel:'해제', danger:false, twoStep:false,
    lines:[key + ' 차단을 해제하고 다시 연결을 허용합니다.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/unblock', {ip:key}).then(function(res){
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''), null);
        afterAction();
      });
    });
}

// 오탐 처리(신뢰 IP) — 이건 공격이 아님. 이후 세지도 보여주지도 않는다. 되돌리기 제공.
function doTrust(ip){
  askConfirm({title:'오탐 처리 (신뢰 IP)', confirmLabel:'신뢰', danger:false, twoStep:false,
    lines:[ip + ' 를 신뢰 IP로 표시합니다 — 이건 공격이 아니라고 보는 거예요.',
           '이후 이 IP는 공격으로 세지도, 타임라인에 보이지도 않습니다.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/trust', {ip:ip}).then(function(res){
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
          res.ok ? function(){ postJSON('/api/untrust', {ip:ip}).then(function(){ tick(); }); } : null);
        closeDetail(); tick();
      });
    });
}
function untrustIp(ip){
  askConfirm({title:'신뢰 해제', confirmLabel:'다시 탐지', danger:false, twoStep:false,
    lines:[ip + ' 신뢰를 풀고 다시 탐지 대상으로 되돌립니다.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/untrust', {ip:ip}).then(function(res){
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''), null);
        afterAction();
      });
    });
}

// 자동 새로고침 일시정지 — 보는 중 화면이 튀지 않게(다시 누르면 즉시 갱신).
function togglePause(){
  PAUSED = !PAUSED;
  var b = document.getElementById('pauseBtn');
  if(b){ b.textContent = PAUSED ? '▶ 재생' : '⏸ 일시정지'; }
  if(!PAUSED){ tick(); }
}

// 상세창(#overlay)을 목록·기록 화면으로도 재사용 — 넓게/보통 전환
function showModal(titleHtml, bodyHtml, wide){
  document.querySelector('#overlay .modal').classList.toggle('wide', !!wide);
  document.getElementById('m-title').innerHTML = titleHtml;
  document.getElementById('m-body').innerHTML = bodyHtml;
  document.getElementById('overlay').classList.add('on');
}
// 조치 후: 보고 있던 화면(삭제함/기록)을 새로 그리고, 아니면 창을 닫는다
function afterAction(){
  if(DELETED_OPEN){ openDeleted(); }
  else if(HISTORY_OPEN){ openHistory(); }
  else { closeDetail(); }
  tick();
}
function fmtTs(s){ return s ? String(s).replace('T', ' ').slice(0, 19) : '—'; }
function scrollToTimeline(){
  var t = document.getElementById('rows');
  if(t){ t.scrollIntoView({behavior:'smooth', block:'start'}); }
}

// 위 숫자 칸 클릭
function tileClick(kind){
  if(kind === 'attempt'){            // 공격 요청 → 필터 풀고 타임라인 전체로
    closeDetail();
    FILTER = '전체'; renderFilters();
    onSearch('', true);
    scrollToTimeline();
    return;
  }
  openIpList(kind);                  // 경고 / 위험 / 전체 → IP 목록
}

var LEVEL_KO = {alert:'위험', watch:'경고'};
function openIpList(kind){
  var title = {alert:'🔴 위험 단계 IP', watch:'🟡 경고 단계 IP', all:'🎯 공격 의심 IP 전체'}[kind];
  LISTROWS = ALERTS.filter(function(r){ return kind === 'all' || r.level === kind; })
                   .sort(function(a, b){ return b.score - a.score; });
  var body = '<div class="hsec">' + LISTROWS.length + '개 IP '
    + '<span class="cnt">· 위험 = 종합 점수가 문턱 이상 · 경고 = 의심 신호는 있지만 점수가 낮음</span></div>';
  if(!LISTROWS.length){
    body += '<div class="hempty">해당 단계의 IP가 없습니다 👍</div>';
  } else {
    body += '<table class="ltab"><thead><tr><th>IP</th><th>단계</th><th>점수</th><th>요청</th>'
      + '<th>탐지 이유</th><th>마지막 공격</th><th></th></tr></thead><tbody>'
      + LISTROWS.map(function(r, i){
          var blk = BLOCKED.indexOf(r.ip) >= 0 ? ' <span class="badge blk">차단됨</span>' : '';
          return '<tr><td class="mono">' + esc(r.ip) + inBadge(r.ip) + whereHtml(r.ip) + blk + '</td>'
            + '<td><span class="lv ' + esc(r.level) + '">' + (LEVEL_KO[r.level] || esc(r.level)) + '</span></td>'
            + '<td>' + r.score + '</td><td>' + (r.reqs || 0) + '</td>'
            + '<td class="why">' + esc((r.reasons || []).join(' · ')) + '</td>'
            + '<td class="mono">' + esc(fmtTs(r.last)) + '</td>'
            + '<td><button class="lbtn" onclick="viewRow(' + i + ')">타임라인 보기 ›</button></td></tr>';
        }).join('')
      + '</tbody></table>';
  }
  HISTORY_OPEN = false;
  showModal(title, body, true);
}
function viewRow(i){
  var r = LISTROWS[i]; if(!r){ return; }
  closeDetail();
  FILTER = '전체'; renderFilters();
  onSearch(r.ip, true);
  scrollToTimeline();
}

// ── 조치 기록 화면: 지금 차단 중 · 신뢰 IP · 조치 이력 ──
var ACT_KO = {block:'차단', unblock:'해제', trust:'신뢰(오탐)', untrust:'신뢰 해제', evidence:'증거 저장',
              log_delete:'기록 삭제', log_restore:'기록 복구', log_purge:'영구 삭제'};
var RES_KO = {ok:'성공', failed:'실패', refused:'거부'};
var HTABS = [
  {name:'전체',      f:function(a){ return true; }},
  {name:'차단',      f:function(a){ return a.action === 'block'; }},
  {name:'해제',      f:function(a){ return a.action === 'unblock' || a.action === 'untrust'; }},
  {name:'신뢰',      f:function(a){ return a.action === 'trust'; }},
  {name:'증거',      f:function(a){ return a.action === 'evidence'; }},
  {name:'실패·거부', f:function(a){ return a.result !== 'ok'; }},
  {name:'삭제·복구', f:function(a){ return String(a.action).indexOf('log_') === 0; }}
];
function openHistory(){
  HISTORY_OPEN = true;
  showModal('📋 조치 기록', '<div class="hempty">불러오는 중…</div>', true);
  fetch('/api/history', {cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(h){ HIST = h; renderHistory(); })
    .catch(function(){ HIST = null;
      document.getElementById('m-body').innerHTML = '<div class="hempty">불러오지 못했어요 — 서버 연결을 확인하세요.</div>'; });
}
function setHistFilter(i){ HFILTER = i; renderHistory(); }
function histUnblock(i){ var b = HIST && HIST.blocked[i]; if(b){ unblockIp(b.ip); } }
function histUntrust(i){ var t = HIST && HIST.trusted[i]; if(t){ untrustIp(t.ip); } }
function renderHistory(){
  var h = HIST || {blocked:[], trusted:[], audit:[], db:false};
  var out = '';
  if(!h.db){
    out += '<div class="disc">※ 기록 저장(DB)이 꺼져 있어서 남은 기록이 없어요. 상황판을 --db 옵션과 함께 켜면 쌓입니다.</div>';
  }
  // 1) 지금 차단 중
  out += '<div class="hsec">🚫 지금 차단 중 <span class="cnt">' + h.blocked.length + '</span></div>';
  out += h.blocked.length
    ? '<table class="ltab"><thead><tr><th>대상</th><th>차단 시각</th><th>사유</th><th></th></tr></thead><tbody>'
      + h.blocked.map(function(b, i){
          return '<tr><td class="mono">' + esc(b.ip) + '</td><td class="mono">' + esc(fmtTs(b.blocked_at)) + '</td>'
            + '<td class="why">' + esc(b.reason || '—') + '</td>'
            + '<td><button class="lbtn" onclick="histUnblock(' + i + ')">해제</button></td></tr>';
        }).join('') + '</tbody></table>'
    : '<div class="hempty">차단 중인 IP가 없어요.</div>';
  // 2) 신뢰 IP
  out += '<div class="hsec">✅ 신뢰 IP (오탐 처리) <span class="cnt">' + h.trusted.length + '</span></div>';
  out += h.trusted.length
    ? '<table class="ltab"><thead><tr><th>IP</th><th>등록 시각</th><th></th></tr></thead><tbody>'
      + h.trusted.map(function(t, i){
          return '<tr><td class="mono">' + esc(t.ip) + '</td><td class="mono">' + esc(fmtTs(t.added_at)) + '</td>'
            + '<td><button class="lbtn" onclick="histUntrust(' + i + ')">다시 탐지</button></td></tr>';
        }).join('') + '</tbody></table>'
    : '<div class="hempty">신뢰 IP가 없어요.</div>';
  // 3) 조치 이력
  var tab = HTABS[HFILTER] || HTABS[0];
  var rows = h.audit.filter(tab.f);
  out += '<div class="hsec">🧾 조치 이력 <span class="cnt">' + rows.length + ' / ' + h.audit.length + '</span>'
    + '<div class="hfil">' + HTABS.map(function(t, i){
        return '<button class="fbtn' + (i === HFILTER ? ' on' : '') + '" onclick="setHistFilter(' + i + ')">' + t.name + '</button>';
      }).join('') + '</div></div>';
  out += rows.length
    ? '<div class="hscroll"><table class="ltab"><thead><tr><th>시각</th><th>대상</th><th>조치</th><th>결과</th><th>상세</th></tr></thead><tbody>'
      + rows.map(function(a){
          var rc = a.result === 'ok' ? 'ok' : (a.result === 'failed' ? 'failed' : (a.result === 'refused' ? 'refused' : 'na'));
          return '<tr><td class="mono">' + esc(fmtTs(a.ts)) + '</td><td class="mono">' + esc(a.ip) + '</td>'
            + '<td>' + esc(ACT_KO[a.action] || a.action) + '</td>'
            + '<td><span class="lv ' + rc + '">' + esc(RES_KO[a.result] || a.result) + '</span></td>'
            + '<td class="det" title="' + esc(a.detail) + '">' + esc(a.detail) + '</td></tr>';
        }).join('') + '</tbody></table></div>'
    : '<div class="hempty">해당하는 조치 기록이 없어요.</div>';
  document.getElementById('m-title').innerHTML =
    '📋 조치 기록 <button class="lbtn" onclick="openHistory()">↻ 새로고침</button>';
  document.getElementById('m-body').innerHTML = out;
}

function openDetail(i){
  var e = LAST[i]; if(!e) return;
  HISTORY_OPEN = false; DELETED_OPEN = false; DETAIL = e;
  document.querySelector('#overlay .modal').classList.remove('wide');
  var sc = e.severity === '위험' ? 'danger' : 'warn';
  var rec = e.rec || {};
  var ipq = esc(e.ip);                               // onclick 에 넣을 IP(검증된 IPv4)
  var isblk = BLOCKED.indexOf(e.ip) >= 0;            // 이미 차단된 IP 인가
  var acts = (rec.actions || []).map(function(a){ return '<li>' + esc(a) + '</li>'; }).join('');
  document.getElementById('m-title').innerHTML =
    '침투 상세 <span class="sev ' + sc + '">' + esc(e.severity) + '</span>'
    + (e.edge_blocked ? ' <span class="badge edge">🛡 앞단에서 차단됨(403)</span>' : '');
  document.getElementById('m-body').innerHTML =
      '<div class="kv">'
    +   '<div class="k">시각</div><div class="v ip">' + esc(e.ts_iso || e.time) + '</div>'
    +   '<div class="k">공격자 IP</div><div class="v ip">' + esc(e.ip) + '</div>'
    +   ipDetailRows(e.ip)
    +   '<div class="k">노린 경로</div><div class="v path">' + esc(e.method) + ' ' + esc(e.path) + '</div>'
    +   '<div class="k">상태코드</div><div class="v">' + e.status + '</div>'
    +   '<div class="k">유형</div><div class="v">' + esc(e.kind) + '</div>'
    +   '<div class="k">도구 지문</div><div class="v ip">' + esc(e.ua || '-') + '</div>'
    +   '</div>'
    + '<div class="rec">'
    +   '<h4>🤖 대응 추천 <span class="rtag">규칙 기반 · 참고용</span></h4>'
    +   '<div class="disc">※ <b>참고용</b>이에요 — 확정 판단이 아니니 차단 전에 로그를 직접 확인하세요.</div>'
    +   (rec.headline ? '<div>' + esc(rec.headline) + '</div>' : '')
    +   '<ul>' + acts + '</ul>'
    +   (rec.caution ? '<div class="caution">⚠ ' + esc(rec.caution) + '</div>' : '')
    + '</div>'
    + '<div class="actions">'
    +   (isblk
          ? '<button class="actbtn unblock" onclick="unblockIp(&#39;' + ipq + '&#39;)">✅ 차단 해제</button>'
          : '<button class="actbtn block" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;ip&#39;,0)">🚫 영구 차단</button>'
          + '<button class="actbtn temp" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;ip&#39;,600)">⏱️ 임시 10분</button>'
          + '<button class="actbtn subnet" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;subnet&#39;,0)">🛡️ 대역 /24</button>')
    +   '<button class="actbtn evic" onclick="doEvidence(&#39;' + ipq + '&#39;)">💾 증거 저장</button>'
    +   '<button class="actbtn trust" onclick="doTrust(&#39;' + ipq + '&#39;)">🟢 오탐(신뢰)</button>'
    +   '<button class="actbtn del" onclick="doDeleteLog()">🗑 기록 삭제</button>'
    +   '<button class="actbtn del" onclick="doDeleteLogIp()">🗑 이 IP 기록 전체</button>'
    +   '<div class="ahint">삭제해도 삭제함으로 옮겨져 복구할 수 있어요 · 조치는 누르면 한 번 더 확인</div>'
    + '</div>';
  document.getElementById('overlay').classList.add('on');
}
function closeDetail(){ HISTORY_OPEN = false; DELETED_OPEN = false; document.getElementById('overlay').classList.remove('on'); }

// 공격 내역 삭제(소프트) — 상세창의 '기록 삭제' 버튼. DETAIL(지금 띄운 한 건)을 쓴다.
function doDeleteLog(){
  var e = DETAIL; if(!e){ return; }
  askConfirm({title:'기록 삭제', confirmLabel:'삭제', danger:false, twoStep:false,
    lines:[esc(e.ip) + ' 의 이 기록 1건을 목록에서 지웁니다.', '삭제함으로 옮겨져 언제든 복구할 수 있어요.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/log/delete', {scope:'one', ip:e.ip, ts:e.ts_iso || '', path:e.path, status:e.status})
        .then(function(res){ showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
          res.ok ? function(){ postJSON('/api/log/restore', {scope:'one', ip:e.ip, ts:e.ts_iso || '', path:e.path, status:e.status}).then(function(){ tick(); }); } : null);
          afterAction(); });
    });
}
// 타임라인 전체 삭제(소프트) — 전부 삭제함으로. 되돌리기(전체 복구) 제공.
function doDeleteAll(){
  askConfirm({title:'전체 삭제', confirmLabel:'전체 삭제', danger:true, twoStep:true,
    lines:['지금 타임라인의 모든 공격 기록을 목록에서 지웁니다.',
           '삭제함으로 옮겨져 전체 복구할 수 있어요(영구 삭제 아님).']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/log/delete', {scope:'all'}).then(function(res){
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
          res.ok ? function(){ postJSON('/api/log/restore', {scope:'all'}).then(function(){ tick(); }); } : null);
        afterAction();
      });
    });
}
function doDeleteLogIp(){
  var e = DETAIL; if(!e){ return; }
  askConfirm({title:'이 IP 기록 전체 삭제', confirmLabel:'전체 삭제', danger:true, twoStep:false,
    lines:[esc(e.ip) + ' 의 공격 기록을 모두 목록에서 지웁니다.', '삭제함에서 되돌릴 수 있어요.']})
    .then(function(ok){
      if(!ok){ return; }
      postJSON('/api/log/delete', {scope:'ip', ip:e.ip}).then(function(res){
        showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''),
          res.ok ? function(){ postJSON('/api/log/restore', {scope:'ip', ip:e.ip}).then(function(){ tick(); }); } : null);
        afterAction();
      });
    });
}

// ── 삭제함 화면: 지운 공격 내역을 보고 복구/영구삭제 ──
function openDeleted(){
  DELETED_OPEN = true; HISTORY_OPEN = false;
  showModal('🗑 삭제함', '<div class="hempty">불러오는 중…</div>', true);
  fetch('/api/deleted', {cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){ DELROWS = d.rows || []; renderDeleted(); })
    .catch(function(){ document.getElementById('m-body').innerHTML = '<div class="hempty">불러오지 못했어요.</div>'; });
}
function renderDeleted(){
  var rows = DELROWS;
  var head = '🗑 삭제함 <span class="cnt" style="font-weight:400;color:var(--faint)">' + rows.length + '건</span>';
  if(rows.length){
    head += ' <button class="lbtn" onclick="delRestoreAll()">전체 복구</button>'
         +  ' <button class="lbtn" onclick="delPurgeAll()">삭제함 비우기(영구)</button>';
  }
  document.getElementById('m-title').innerHTML = head;
  var out;
  if(!rows.length){
    out = '<div class="hempty">삭제한 기록이 없어요. (타임라인에서 줄 클릭 → 🗑 기록 삭제)</div>';
  } else {
    out = '<div class="disc">삭제한 기록은 여기 보관돼요. <b>복구</b>하면 다시 타임라인에 나타나고, <b>영구 삭제</b>하면 되돌릴 수 없어요.</div>'
      + '<div class="hscroll"><table class="ltab"><thead><tr><th>삭제 시각</th><th>공격 시각</th><th>IP</th><th>노린 경로</th><th>유형</th><th></th></tr></thead><tbody>'
      + rows.map(function(r, i){
          return '<tr><td class="mono">' + esc(fmtTs(r.deleted_at)) + '</td><td class="mono">' + esc(fmtTs(r.ts)) + '</td>'
            + '<td class="mono">' + esc(r.ip) + '</td><td class="det">' + esc(r.path) + '</td>'
            + '<td>' + esc(r.kind) + '</td>'
            + '<td style="white-space:nowrap"><button class="lbtn" onclick="delRestore(' + i + ')">복구</button> '
            + '<button class="lbtn" onclick="delPurgeOne(' + i + ')">영구삭제</button></td></tr>';
        }).join('') + '</tbody></table></div>';
  }
  document.getElementById('m-body').innerHTML = out;
}
function delRestore(i){
  var r = DELROWS[i]; if(!r){ return; }
  postJSON('/api/log/restore', {scope:'one', ip:r.ip, ts:r.ts, path:r.path, status:r.status})
    .then(function(res){ showUndo((res.ok ? '✅ ' : '⚠ ') + (res.message || ''), null); afterAction(); });
}
function delRestoreAll(){
  askConfirm({title:'전체 복구', confirmLabel:'복구', danger:false, twoStep:false,
    lines:['삭제함의 모든 기록을 타임라인으로 되돌립니다.']}).then(function(ok){
    if(!ok){ return; }
    postJSON('/api/log/restore', {scope:'all'}).then(function(res){ showUndo((res.ok?'✅ ':'⚠ ')+(res.message||''), null); afterAction(); });
  });
}
function delPurgeOne(i){
  var r = DELROWS[i]; if(!r){ return; }
  askConfirm({title:'영구 삭제', confirmLabel:'영구 삭제', danger:true, twoStep:true,
    lines:[esc(r.ip) + ' 의 이 기록을 완전히 지웁니다.', '복구할 수 없습니다.']}).then(function(ok){
    if(!ok){ return; }
    postJSON('/api/log/purge', {scope:'one', ip:r.ip, ts:r.ts, path:r.path, status:r.status})
      .then(function(res){ showUndo((res.ok?'✅ ':'⚠ ')+(res.message||''), null); afterAction(); });
  });
}
function delPurgeAll(){
  askConfirm({title:'삭제함 비우기', confirmLabel:'영구 삭제', danger:true, twoStep:true,
    lines:['삭제함의 모든 기록을 완전히 지웁니다.', '복구할 수 없습니다.']}).then(function(ok){
    if(!ok){ return; }
    postJSON('/api/log/purge', {scope:'all'}).then(function(res){ showUndo((res.ok?'✅ ':'⚠ ')+(res.message||''), null); afterAction(); });
  });
}
document.addEventListener('keydown', function(e){ if(e.key === 'Escape') closeDetail(); });

function tick(){
  if(PAUSED){ return; }                               // 일시정지 중엔 갱신 안 함
  fetch('/api/alerts', {cache:'no-store'})
    .then(function(r){ return r.json(); })
    .then(function(d){ render(d); setStatus(true, d.generated); })
    .catch(function(){ setStatus(false); });
}
tick();
setInterval(tick, 3000);
</script>
</body>
</html>"""


def run_dashboard(a):
    """[v2] 실시간 상황판 — 백그라운드로 로그를 재검사하고, 작은 웹서버로 화면·자료를 제공.

    외부 라이브러리 0. 파이썬 표준 http.server 만 쓴다.
    바인드 주소 기본값은 127.0.0.1(이 PC에서만 열람) — 사내망 공유는 --host 0.0.0.0.
    """
    state = {"payload": build_dashboard_payload([], []),   # 공유 저장소
             "blocked": load_blocked(a.db),                # 현재 차단 중인 IP(재시작해도 복원)
             "trusted": load_trusted(a.db)}                # 신뢰(오탐 처리) IP — 탐지에서 제외
    lock = threading.Lock()                                # 스레드 간 안전장치
    state["ipinfo"] = {}                                   # 공격 IP 출처 조회 결과(ip → 정보)
    if a.db and os.path.exists(a.db):
        try:
            _c = open_db(a.db)
            state["ipinfo"] = load_ipinfo(_c)              # 예전에 조회한 결과 재사용
            _c.close()
        except Exception:  # noqa: BLE001
            pass

    if a.db:
        print(f"침투 흔적 DB: {a.db} (영구 저장)")
    if state["blocked"]:
        print(f"차단 중인 IP 복원: {len(state['blocked'])}개")
    if state["trusted"]:
        print(f"신뢰 IP 복원: {len(state['trusted'])}개")
    if _IP_LOOKUP:
        print(f"🌐 공격 IP 출처 조회 켜짐(RDAP·역방향 이름) — 저장된 결과 {len(state['ipinfo'])}개")

    def scanner():
        """백그라운드: scan_interval 초마다 로그를 다시 읽어 최신 경보로 갱신.

        DB 가 켜져 있으면 수상한 요청을 DB 에 쌓고(흔적 보존), 타임라인은 DB 에서 읽는다
        → 상황판을 꺼도·로그가 지워져도 과거 침투가 남는다.
        """
        # SQLite 연결은 '이 스레드 안'에서 연다 — 연 스레드만 쓸 수 있는 규칙 때문.
        conn = open_db(a.db) if a.db else None
        while True:
            try:
                events, _ = load_events(a.logfile, a.format)
                with lock:
                    trusted = set(state["trusted"])          # 신뢰 IP 스냅샷
                if trusted:
                    events = [e for e in events if e["ip"] not in trusted]  # 오탐 IP 제외
                results = analyze(events, a.window, a.probe_threshold,
                                  a.auth_threshold, a.rate_threshold, a.score_threshold)
                dist = detect_distributed(events, a.window, a.dist_threshold)
                if conn is not None:
                    store_events(conn, events)               # 흔적을 DB 에 영구 저장
                    timeline = recent_intrusions(conn, 60)   # 타임라인은 DB 에서(과거까지)
                    if trusted:
                        timeline = [t for t in timeline if t["ip"] not in trusted]  # 과거 저장분도 숨김
                else:
                    timeline = build_timeline(events, 60)     # DB 없으면 현재 로그에서
                payload = build_dashboard_payload(results, dist, timeline)
                # '뚫렸나?' — 실제 사고일 수 있는 것만(출처 정보가 오면 다음 차례에 다시 판단)
                with lock:
                    ipcache = dict(state["ipinfo"])
                incs = detect_incidents(events, ipcache, a.auth_threshold)
                if conn is not None:
                    fresh_incs = store_incidents(conn, incs)
                    payload["incidents"] = load_incidents(conn, open_only=True, limit=50)
                    payload["today"] = today_summary(conn=conn)
                else:
                    with lock:
                        mem = state.setdefault("mem_incidents", {})
                        fresh_incs = [i for i in incs if i["key"] not in mem]
                        for i in fresh_incs:
                            mem[i["key"]] = dict(i, ack=False, ack_at="", found_at=datetime.now().isoformat(timespec="seconds"))
                        payload["incidents"] = [v for v in mem.values() if not v["ack"]][-50:][::-1]
                    payload["today"] = today_summary(events=events)
                payload["logins"] = recent_logins(events)
                with lock:
                    state["fresh_incidents"] = state.get("fresh_incidents", []) + fresh_incs   # 알림용(2단계)
            except Exception as e:  # noqa: BLE001 — 한 번 실패해도 상황판은 멈추지 않는다
                print(f"⚠ 재검사 실패(무시하고 계속): {e}")
                payload = None
            if payload is not None:
                with lock:
                    state["payload"] = payload
            time.sleep(a.scan_interval)

    def enricher():
        """[출처 분석] 화면에 보이는 공격 IP 의 나라·기관·종류를 천천히 조회해 저장.

        설정 "ip_lookup": true 일 때만 돈다. 한 차례 최대 5개·1.5초 간격·시간당 300개 —
        등록기관 서버에 부담을 주지 않고, 상황판 갱신(scanner)과는 따로 돌아 화면이 느려지지 않는다.
        """
        conn = open_db(a.db) if a.db else None
        bootstrap, boot_at = {}, 0.0
        hour_start, hour_count = time.time(), 0
        while True:
            try:
                now_ts = time.time()
                if now_ts - hour_start > 3600:
                    hour_start, hour_count = now_ts, 0
                if now_ts - boot_at > 86400:                   # 어느 대역을 어느 등록기관이 맡는지(하루 1번)
                    try:
                        bootstrap = {"services": _http_json(_RDAP_BOOTSTRAP["v4"])["services"]
                                     + _http_json(_RDAP_BOOTSTRAP["v6"])["services"]}
                        boot_at = now_ts
                    except Exception as e:  # noqa: BLE001
                        print(f"⚠ RDAP 안내표 받기 실패 — 1시간 뒤 다시(그동안 rdap.org 중계 사용): {e}")
                        bootstrap, boot_at = {}, now_ts - 86400 + 3600
                with lock:
                    payload = state["payload"]
                    cache = dict(state["ipinfo"])
                for ip in pick_lookup_targets(payload, cache, now_ts, limit=5):
                    if hour_count >= 300:
                        break
                    info = lookup_ip(ip, bootstrap)
                    hour_count += 1
                    with lock:
                        state["ipinfo"][ip] = info
                    if conn is not None:
                        save_ipinfo(conn, info)
                    time.sleep(1.5)
            except Exception as e:  # noqa: BLE001 — 조회가 실패해도 상황판은 멈추지 않는다
                print(f"⚠ IP 출처 조회 실패(무시하고 계속): {e}")
            time.sleep(5)

    def notifier():
        """[알림·감시] 새 사고 즉시 알림 · 사이트/로그 감시 · 매일 요약.

        채널이 없어도 감시 결과(감시 이상)는 화면 신호등에 보인다.
        켠 시각 10분 전 이후의 사고만 알림 — 처음 켤 때 옛 로그의 사고가 한꺼번에 울리지 않게.
        """
        conn = open_db(a.db) if a.db else None
        started = time.time()
        mon = HealthMonitor(_HEALTH.get("urls") or [], _HEALTH.get("fail_after", 2))
        interval = max(60, int(_HEALTH.get("interval", 300)))
        stall_min = _HEALTH.get("log_stall_minutes", 0)
        last_check, last_stall, last_daily_try = 0.0, "", 0.0

        def _epoch(ts):
            try:
                return datetime.fromisoformat(str(ts)).timestamp()
            except (ValueError, TypeError):
                return time.time()

        while True:
            try:
                now_ts = time.time()
                channels = notify_channels()
                with lock:
                    fresh, state["fresh_incidents"] = state.get("fresh_incidents", []), []
                    ipcache = dict(state["ipinfo"])
                recent = [i for i in fresh if _epoch(i["ts"]) >= started - 600]
                if channels and recent:
                    for inc in recent[:5]:
                        send_notification(fmt_incident_msg(inc, ipcache))
                    if len(recent) > 5:
                        send_notification(f"[{_BRAND}] 🔴 사고 의심 {len(recent) - 5}건 더 — 상황판에서 확인해 주세요")
                if mon.urls and now_ts - last_check >= interval:
                    last_check = now_ts
                    for url, what, detail in mon.run():
                        if channels:
                            send_notification(f"[{_BRAND}] " + ("🟠 사이트 응답 없음" if what == "down" else "🟢 사이트 복구")
                                              + f": {url} ({detail})")
                stall = log_stall_problem(a.logfile, stall_min)
                if stall != last_stall:
                    if channels and (stall or last_stall):
                        send_notification(f"[{_BRAND}] " + (f"🟠 {stall}" if stall else "🟢 로그 기록이 다시 들어옵니다"))
                    last_stall = stall
                health = {"problems": mon.problems() + ([stall] if stall else []),
                          "watching": bool(mon.urls or stall_min), "at": datetime.now().strftime("%H:%M:%S")}
                with lock:
                    state["health"] = health
                daily_at = _NOTIFY.get("daily_at", "08:30") if channels else ""
                if conn is not None and daily_at and now_ts - last_daily_try >= 1800:
                    now = datetime.now()
                    if daily_due(now, daily_at, get_meta(conn, "last_daily")):
                        last_daily_try = now_ts          # 전부 실패하면 30분 뒤 다시(재시도 폭주 방지)
                        day = (now - timedelta(days=1)).strftime("%Y-%m-%d")
                        res = send_notification(fmt_daily_msg(daily_report(conn, day, ipcache, health)))
                        if any(v == "ok" for v in res.values()):
                            set_meta(conn, "last_daily", now.strftime("%Y-%m-%d"))
            except Exception as e:  # noqa: BLE001 — 알림·감시가 실패해도 상황판은 멈추지 않는다
                print(f"⚠ 알림·감시 실패(무시하고 계속): {e}")
            time.sleep(15)

    # 켤 때마다 새로 만드는 비밀 표 — 진짜 화면에만 심어서, 조치 요청이 그 화면에서 왔는지 확인(CSRF 방지)
    token = secrets.token_urlsafe(24)
    page = (_DASHBOARD_HTML.replace("__LS_TOKEN__", token)
            .replace("__LS_LOGO__", _logo_html())
            .replace("__LS_BRAND__", esc_html(_BRAND)).encode("utf-8"))
    deny = '{"ok":false,"message":"요청 출처를 확인할 수 없어 거절했습니다(상황판 화면에서만 조치할 수 있어요)."}'.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")   # 브라우저가 옛 화면 캐시 못하게
            self.send_header("X-Frame-Options", "DENY")      # 남의 페이지 안에 끼워 클릭 유도 방지
            self.send_header("Content-Security-Policy", "frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):   # noqa: N802 (http.server 가 정한 이름)
            if not _host_ok(self.headers.get("Host")):   # DNS 리바인딩으로 읽어 가기 방지
                self._send(403, deny, "application/json; charset=utf-8")
                return
            if self.path.startswith("/api/alerts"):
                with lock:
                    resp = dict(state["payload"])                 # 얕은 복사 후
                    resp["blocked"] = sorted(state["blocked"])    # 현재 차단 목록을 끼워 보냄
                    resp["trusted"] = sorted(state["trusted"])    # 신뢰(오탐) 목록도
                    resp["ip_lookup"] = _IP_LOOKUP                # 출처 조회 켜짐 여부
                    resp["health"] = state.get("health", {})       # 사이트·로그 감시 상태
                    resp["notify"] = notify_channels()             # 켜진 알림 채널 이름(값은 안 보냄)
                    resp["ipinfo"] = {ip: ipinfo_view(state["ipinfo"][ip])
                                      for ip in payload_ips(resp) if ip in state["ipinfo"]}
                body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/blocks"):
                with lock:
                    body = json.dumps({"blocked": sorted(state["blocked"])},
                                      ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/history"):
                # 조치 기록 화면 — 요청마다 자기 DB 연결을 열고 닫는다(SQLite 스레드 규칙)
                body = json.dumps(load_history(a.db), ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/incidents"):
                if a.db:
                    try:
                        _c = open_db(a.db)
                        rows = load_incidents(_c, open_only=False, limit=300)
                        _c.close()
                    except Exception:  # noqa: BLE001
                        rows = []
                else:
                    with lock:
                        rows = sorted(state.get("mem_incidents", {}).values(), key=lambda x: x["ts"], reverse=True)
                body = json.dumps({"rows": rows}, ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/deleted"):
                body = json.dumps(load_deleted(a.db), ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path == "/" or self.path.startswith("/?"):
                self._send(200, page, "text/html; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_POST(self):   # noqa: N802 — 조치 버튼(차단/해제/증거/신뢰)이 부르는 창구
            if self.path not in ("/api/block", "/api/unblock", "/api/evidence",
                                 "/api/trust", "/api/untrust",
                                 "/api/log/delete", "/api/log/restore", "/api/log/purge",
                                 "/api/log/delete_many", "/api/log/restore_many",
                                 "/api/incident/ack", "/api/notify/test"):
                self._send(404, b"not found", "text/plain; charset=utf-8")
                return
            allowed, why = _post_allowed(self.headers, token)
            if not allowed:
                print(f"⚠ 조치 요청 거절({why}) — 출처 확인 실패")
                self._send(403, deny, "application/json; charset=utf-8")
                return
            try:
                n = int(self.headers.get("Content-Length") or 0)
                data = json.loads(self.rfile.read(n) or b"{}")
            except Exception:  # noqa: BLE001 — 깨진 요청은 400 으로
                self._send(400, '{"ok":false,"message":"잘못된 요청입니다."}'.encode("utf-8"),
                           "application/json; charset=utf-8")
                return
            ip = (data.get("ip") or "").strip()
            if self.path == "/api/block":
                scope = "subnet" if data.get("scope") == "subnet" else "ip"
                res = block_ip(a.db, ip, data.get("reason") or "상황판에서 차단", scope)
                if res.get("ok"):
                    key = res.get("key") or ip
                    with lock:
                        state["blocked"].add(key)
                    ttl = data.get("ttl")           # 임시 차단: N초 뒤 자동 해제
                    if ttl:
                        def _auto_unblock(k=key):
                            unblock_ip(a.db, k)
                            with lock:
                                state["blocked"].discard(k)
                        threading.Timer(float(ttl), _auto_unblock).start()
                        res["message"] += f"  ⏱️ {int(float(ttl))//60}분 뒤 자동 해제됩니다."
            elif self.path == "/api/unblock":
                res = unblock_ip(a.db, ip)
                if res.get("ok"):
                    with lock:
                        state["blocked"].discard(res.get("key") or ip)
            elif self.path == "/api/trust":
                res = trust_ip(a.db, ip)
                if res.get("ok"):
                    with lock:
                        state["trusted"].add(ip)
            elif self.path == "/api/untrust":
                res = untrust_ip(a.db, ip)
                if res.get("ok"):
                    with lock:
                        state["trusted"].discard(ip)
            elif self.path == "/api/log/delete":
                res = delete_logs(a.db, data)
            elif self.path == "/api/log/restore":
                res = restore_logs(a.db, data)
            elif self.path == "/api/log/purge":
                res = purge_logs(a.db, data)
            elif self.path == "/api/notify/test":
                if not notify_channels():
                    res = {"ok": False, "message": "알림 채널이 설정되지 않았습니다(logsentry.json 의 notify)."}
                else:
                    r = send_notification(f"[{_BRAND}] 🔔 알림 시험 — 이 메시지가 보이면 알림 설정이 정상입니다.")
                    res = {"ok": all(v == "ok" for v in r.values()),
                           "message": " / ".join(f"{k}: {'성공' if v == 'ok' else v}" for k, v in r.items())}
            elif self.path == "/api/incident/ack":
                key = str(data.get("key") or "")
                if a.db:
                    res = ack_incident(a.db, key, bool(data.get("ack", True)))
                else:
                    with lock:
                        mem = state.setdefault("mem_incidents", {})
                        if key in mem:
                            mem[key]["ack"] = bool(data.get("ack", True))
                            res = {"ok": True, "message": "표시했습니다."}
                        else:
                            res = {"ok": False, "message": "해당 사고 기록이 없습니다."}
            elif self.path == "/api/log/delete_many":
                res = delete_many(a.db, data.get("items"), 1)
            elif self.path == "/api/log/restore_many":
                res = delete_many(a.db, data.get("items"), 0)
            else:                                   # /api/evidence
                res = export_evidence(a.db, ip)
            self._send(200, json.dumps(res, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def log_message(self, *args):   # 상황판 자신의 접근 로그는 콘솔에 찍지 않는다
            pass

    threading.Thread(target=scanner, daemon=True).start()   # 재검사 스레드 시작
    if _IP_LOOKUP:
        threading.Thread(target=enricher, daemon=True).start()   # 출처 조회 스레드(설정으로 켤 때만)
    threading.Thread(target=notifier, daemon=True).start()       # 알림·감시 스레드
    if notify_channels():
        print(f"🔔 알림 켜짐: {'·'.join(notify_channels())} (매일 요약 {_NOTIFY.get('daily_at', '08:30')})")
    if _HEALTH.get("urls") or _HEALTH.get("log_stall_minutes"):
        print(f"🩺 감시: 사이트 {len(_HEALTH.get('urls') or [])}곳, 로그 멈춤 {_HEALTH.get('log_stall_minutes', 0)}분")
    srv = ThreadingHTTPServer((a.host, a.dashboard), Handler)
    print(f"실시간 상황판 시작 — http://{a.host}:{a.dashboard}"
          f"  ({a.scan_interval}초마다 재검사, Ctrl+C 로 중지)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n상황판 중지.")
        srv.shutdown()


def main():
    p = argparse.ArgumentParser(description="LogSentry — 접근 로그 침입 탐지")
    p.add_argument("logfile", nargs="?", help="접근 로그 파일(nginx/apache/JSON)")
    p.add_argument("--format", default="auto",
                   choices=["auto", "nginx", "apache", "json"],
                   help="로그 형식(기본 auto=자동 감지)")
    p.add_argument("--window", type=int, default=None)
    p.add_argument("--probe-threshold", type=int, default=None)
    p.add_argument("--auth-threshold", type=int, default=None)
    p.add_argument("--rate-threshold", type=int, default=None)
    p.add_argument("--score-threshold", type=int, default=None)
    p.add_argument("--dist-threshold", type=int, default=None,
                   help="분산 경보 문턱 — 한 시간창(--window) 안 서로 다른 IP 수(기본 5)")
    p.add_argument("--alert-log", default=None, help="경보를 이어 적을 파일(간이 기록함)")
    p.add_argument("--webhook", default=None,
                   help="경보를 보낼 웹훅 주소(슬랙/디스코드/범용 HTTP). 설정 파일로도 지정 가능")
    p.add_argument("--config", default="logsentry.json",
                   help="설정 파일(JSON) — 있으면 목록·문턱·신뢰IP·웹훅 을 덮어씀")
    p.add_argument("--watch", type=int, metavar="SECONDS",
                   help="N초마다 자동 재검사(새 경보만)")
    p.add_argument("--dashboard", type=int, metavar="PORT",
                   help="실시간 상황판(웹 화면)을 이 포트로 띄운다. 예: --dashboard 8787")
    p.add_argument("--host", default="127.0.0.1",
                   help="상황판 바인드 주소(기본 127.0.0.1=이 PC에서만. 사내망 공유는 0.0.0.0)")
    p.add_argument("--scan-interval", type=int, default=5,
                   help="상황판이 로그를 다시 읽는 주기(초, 기본 5)")
    p.add_argument("--db", default="logsentry.db",
                   help="침투 흔적을 영구 저장할 SQLite DB 파일(기본 logsentry.db). 빈 값이면 끔")
    p.add_argument("--notify-test", action="store_true",
                   help="설정 파일의 알림 채널로 시험 메시지를 보내고 결과만 보여준 뒤 끝낸다")
    p.add_argument("--show-db", type=int, nargs="?", const=30, metavar="N",
                   help="쌓인 침투 흔적 DB 에서 최근 N건(기본 30)을 표로 보여주고 끝낸다")
    a = p.parse_args()

    if a.notify_test:             # 알림 설정 확인만 하고 끝
        load_config(a.config)
        if not notify_channels():
            print("알림 채널이 설정되지 않았습니다 — logsentry.json 에 notify 를 넣으세요.")
            sys.exit(1)
        r = send_notification(f"[{_BRAND}] 🔔 알림 시험 — 이 메시지가 보이면 알림 설정이 정상입니다.")
        for k, v in r.items():
            print(f"  {k}: {'성공' if v == 'ok' else v}")
        sys.exit(0 if all(v == "ok" for v in r.values()) else 1)
    if a.show_db is not None:     # DB 조회만 하고 끝(상황판 안 켜도 됨)
        print_db(a.db, a.show_db)
        return
    if not a.logfile:
        p.error("접근 로그 파일을 지정하세요. (또는 --show-db 로 쌓인 DB 조회)")

    # 설정 파일을 읽어 목록·신뢰IP 를 덮어쓰고, 문턱은 명령줄 > 설정파일 > 기본값 순으로 정한다
    th = load_config(a.config)
    if a.window is None:
        a.window = th["window"]
    if a.probe_threshold is None:
        a.probe_threshold = th["probe"]
    if a.auth_threshold is None:
        a.auth_threshold = th["auth"]
    if a.rate_threshold is None:
        a.rate_threshold = th["rate"]
    if a.score_threshold is None:
        a.score_threshold = th["score"]
    if a.dist_threshold is None:
        a.dist_threshold = th["dist_ip"]
    if not a.webhook:           # 명령줄 > 설정파일 순으로 웹훅 주소를 정한다
        a.webhook = th["webhook"]

    if a.dashboard:             # 실시간 상황판 모드(웹 화면)
        run_dashboard(a)
        return

    if a.watch:                 # 자동 감시 모드
        run_watch(a)
        return

    events, bad = load_events(a.logfile, a.format)   # 한 번만 검사
    results = analyze(events, a.window, a.probe_threshold,
                      a.auth_threshold, a.rate_threshold, a.score_threshold)
    alerts = [r for r in results if r["level"] == "alert"]
    watches = [r for r in results if r["level"] == "watch"]

    print(f"LogSentry — 로그 {len(events)}줄 분석"
          + (f" (형식 불일치 {bad}줄 건너뜀)" if bad else "") + "\n")
    print("🔴 경보" if alerts else "🔴 경보 없음")
    for r in alerts:
        print("  " + fmt_screen(r))
    print()
    print("🟡 관찰" if watches else "🟡 관찰 없음")
    for r in watches:
        print("  " + fmt_screen(r))

    # [v2] 서버 전체 관점 — 여러 IP 로 쪼갠 분산 공격
    dist = detect_distributed(events, a.window, a.dist_threshold)
    print()
    print("🌐 분산 의심" if dist else "🌐 분산 의심 없음")
    for d in dist:
        print(f"  {d['kind']} — 서로 다른 IP {d['ips']}개 (한 {d['window']}초 창)")

    if a.alert_log and results:
        write_alert_log(a.alert_log, results)
        print(f"\n📝 경보 {len(alerts)}건·관찰 {len(watches)}건을 {a.alert_log} 에 기록")

    if a.webhook and alerts:
        send_webhook(a.webhook, alerts)
        print(f"📡 경보 {len(alerts)}건을 웹훅으로 전송")


def fmt_screen(r):
    """화면용(한글) — 사람이 읽기 좋게."""
    span = f" ({r['first']:%m-%d %H:%M}~{r['last']:%H:%M})" if r["first"] and r["last"] else ""
    return (f"IP {r['ip']} — 점수 {r['score']} · 서로 다른 경로 {r['distinct_paths']}개{span}"
            f"\n       {' · '.join(r['reasons'])}")


def fmt_file(r):
    """파일 기록용(ASCII key=value) — 어떤 도구·인코딩에서도 안 깨지고 기계가 파싱 가능."""
    span = ""
    if r["first"] and r["last"]:
        span = f" first={r['first']:%Y-%m-%dT%H:%M} last={r['last']:%H:%M}"
    return (f"ip={r['ip']} score={r['score']} distinct_paths={r['distinct_paths']} "
            f"notfound={r['nf']} authfail={r['auth']} probe_paths={r['probes']} "
            f"tool_ua={int(r['tool'])} rate={r['rate']}{span}")


if __name__ == "__main__":
    main()
