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
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
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
                "/server-status", "/.ssh", "/vendor", "/shell")
# 정상 소음(제외)
_SKIP = ("/favicon.ico", "/robots.txt", "/health")
# 인증 실패로 볼 상태코드 — 401 비번틀림·403 권한없음·423 계정잠금(무차별의 결정적 증거).
# 서버마다 로그인 실패를 400·422 등으로 주기도 해서 설정 파일로 넓힐 수 있다.
_AUTH_STATUSES = (401, 403, 423)
# 신뢰 IP(회사·사내 공유 IP 등) — 경보에서 제외해 오탐을 줄인다
_TRUSTED_IPS = ()
# 문턱 기본값 — logsentry.json 의 "thresholds" 로 덮어쓸 수 있다
DEFAULT_THRESHOLDS = {"window": 60, "probe": 5, "auth": 5, "rate": 20,
                      "score": 6, "dist_ip": 5}


def load_config(path):
    """설정 파일(logsentry.json)이 있으면 목록·신뢰IP 를 덮어쓰고 문턱을 돌려준다.

    코드를 고치지 않고 회사마다 탐침 경로·도구 지문·신뢰 IP·문턱을 바꾸게 한다.
    파일이 없거나 읽기 실패하면 조용히 기본값을 쓴다(도구가 멈추지 않게).
    """
    global _TOOL_UA, _PROBE_PATHS, _SKIP, _TRUSTED_IPS, _AUTH_STATUSES
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


def _parse_json(line):
    try:
        o = json.loads(line)
    except ValueError:
        return None
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


def analyze(events, window, probe_threshold, auth_threshold, rate_threshold, score_threshold):
    agg = defaultdict(lambda: {
        "reqs": 0, "nf": 0, "auth": 0, "paths": set(), "probes": 0,
        "tool": False, "first": None, "last": None, "times": [],
    })
    for e in events:
        if e["ip"] in _TRUSTED_IPS:   # 신뢰 IP 는 경보 대상에서 제외(오탐 감소)
            continue
        if any(e["path"].startswith(s) for s in _SKIP):
            continue
        d = agg[e["ip"]]
        d["reqs"] += 1
        if e["status"] == 404:
            d["nf"] += 1
        if e["status"] in _AUTH_STATUSES:
            d["auth"] += 1
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
                 + (2 if d["tool"] else 0) + (3 if burst >= rate_threshold else 0))

        reasons = []
        if d["nf"] >= probe_threshold:
            reasons.append(f"없는 주소 {d['nf']}회")
        if d["auth"] >= auth_threshold:
            reasons.append(f"인증거부 {d['auth']}회")
        if burst >= rate_threshold:
            reasons.append(f"과속 {burst}req/{window}s")
        if d["probes"]:
            reasons.append(f"탐침경로 {d['probes']}개")
        if d["tool"]:
            reasons.append("도구 UA")

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
            "probes": d["probes"], "tool": d["tool"], "rate": burst,
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
                 if e["ts"] and e["ip"] not in _TRUSTED_IPS
                 and e["status"] in _AUTH_STATUSES]
    nf_hits = [(e["ts"], e["ip"]) for e in events
               if e["ts"] and e["ip"] not in _TRUSTED_IPS and e["status"] == 404
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
             if not e.get("success") and e.get("ts") and e.get("ip") not in _TRUSTED_IPS]
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
    text = f"[LogSentry] 경보 {len(alerts)}건\n" + "\n".join(lines)
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "LogSentry"})
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
    return (e["status"] == 404 or e["status"] in _AUTH_STATUSES
            or is_probe_path(e["path"]) or is_tool(e["ua"]))


def _event_kind(e):
    """수상한 요청 한 건에 붙일 유형 이름(우선순위: 탐침 > 인증거부 > 없는주소 > 도구)."""
    if is_probe_path(e["path"]):
        return "탐침경로"
    if e["status"] in _AUTH_STATUSES:
        return "인증거부"
    if e["status"] == 404:
        return "없는 주소"
    if is_tool(e["ua"]):
        return "도구 접근"
    return "요청"


def _severity(kind):
    """유형 → 심각도(위험/경고). 탐침·인증거부는 명백히 악의적 → 위험."""
    return "위험" if kind in ("탐침경로", "인증거부") else "경고"


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
        "rec": recommend(ip, path, status, ua, kind),
    }


def build_timeline(events, limit=60):
    """[DB 미사용 시] 개별 공격 요청을 '시간 순(최근 먼저)'으로 — 누적 요약이 아니라 한 건 한 건.

    신뢰 IP·정상 소음(_SKIP)은 뺀다. timestamp() 로 정렬해 aware/naive 혼용 오류를 피한다.
    """
    susp = [e for e in events
            if e["ip"] not in _TRUSTED_IPS
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
    conn.commit()
    return conn


def store_events(conn, events):
    """수상한 요청만 DB 에 영구 저장(중복은 UNIQUE 로 자동 무시). 새로 저장된 건수를 돌려준다."""
    now = datetime.now().isoformat(timespec="seconds")
    saved = 0
    for e in events:
        if e["ip"] in _TRUSTED_IPS:
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
        " ORDER BY ts DESC LIMIT ?", (limit,))
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
            "rate": r["rate"], "reasons": r["reasons"],
            "first": _iso(r["first"]), "last": _iso(r["last"]),
            "time": r["last"].strftime("%H:%M:%S") if r["last"] else "—",
        })
    # Top 패널 (GoAccess 식) — 한눈에 '누가·어디를' 가장 많이 노렸는지.
    top_ips = sorted(
        ({"ip": r["ip"], "count": r["nf"] + r["auth"] + r["probes"],
          "level": r["level"], "score": r["score"]} for r in rows),
        key=lambda x: (x["count"], x["score"]), reverse=True)[:6]
    top_paths = [{"path": p, "count": c}
                 for p, c in Counter(t["path"] for t in (timeline or [])).most_common(6)]
    return {
        "generated": datetime.now().strftime("%H:%M:%S"),
        "ip_count": len(results),                 # 공격 의심 IP 수
        "alert_count": len(alerts),               # 위험(경보)
        "watch_count": len(watches),              # 경고(관찰)
        # '공격 요청(건)' = 악성으로 보이는 요청 수(없는주소 404 + 인증거부).
        # 탐침경로는 대개 404 와 '같은 요청'이라 더하지 않는다 — 한 요청을 한 번만 센다.
        "attempt_count": sum(r["nf"] + r["auth"] for r in results),
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
<title>LogSentry 실시간 침입 감시</title>
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
  header h1 { font-size:18px; margin:0; font-weight:600; }
  .hr { display:flex; align-items:center; gap:14px; }
  .tbtn { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2);
          border-radius:6px; padding:5px 11px; font-size:12px; cursor:pointer; }
  .tbtn:hover { border-color:var(--accent); }
  #status { font-size:12px; color:var(--muted); }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%;
         background:var(--green); margin-right:6px; vertical-align:middle; }
  .tiles { display:grid; grid-template-columns:repeat(4,1fr); gap:12px; padding:20px; }
  @media (max-width:640px){ .tiles{ grid-template-columns:repeat(2,1fr); } }
  .tile { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:16px; }
  .tile .n { font-size:34px; font-weight:700; line-height:1; }
  .tile .l { font-size:13px; color:var(--muted); margin-top:8px; }
  .tile.danger .n { color:var(--danger); }
  .tile.warn .n { color:var(--warn); }
  #dist { padding:0 20px; }
  #dist .d { background:var(--dist-bg); border:1px solid var(--dist-bd); color:var(--dist-fg);
             border-radius:8px; padding:10px 12px; margin-bottom:10px; font-size:14px; }
  .wrap { padding:8px 20px 28px; }
  h2 { font-size:14px; color:var(--muted); font-weight:500; margin:12px 4px; }
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
             align-items:flex-start; justify-content:center; padding:40px 16px; z-index:50; }
  #overlay.on { display:flex; }
  .modal { background:var(--panel); border:1px solid var(--border2); border-radius:12px;
           max-width:640px; width:100%; max-height:85vh; overflow:auto; }
  .modal .mh { padding:16px 20px; border-bottom:1px solid var(--border);
               display:flex; align-items:center; justify-content:space-between; }
  .modal .mh h3 { margin:0; font-size:16px; }
  .modal .mx { cursor:pointer; color:var(--muted); font-size:20px; background:none; border:none; }
  .modal .mb { padding:18px 20px; }
  .kv { display:grid; grid-template-columns:96px 1fr; gap:8px 12px; font-size:14px; margin-bottom:16px; }
  .kv .k { color:var(--muted); }
  .kv .v { word-break:break-all; }
  .rec { background:var(--inset); border:1px solid var(--border); border-radius:10px; padding:14px; }
  .rec h4 { margin:0 0 8px; font-size:14px; color:var(--accent); }
  .disc { background:var(--disc-bg); border:1px solid var(--disc-bd); color:var(--disc-fg);
          border-radius:8px; padding:9px 11px; font-size:12.5px; line-height:1.55; margin-bottom:12px; }
  .rec ul { margin:8px 0 0; padding-left:18px; }
  .rec li { margin:6px 0; font-size:14px; line-height:1.5; }
  .cmd { margin-top:12px; background:var(--codebg); border:1px solid var(--border2); border-radius:8px;
         padding:10px 34px 10px 12px; font-family:ui-monospace,Consolas,monospace;
         font-size:12.5px; color:var(--cmd-fg); word-break:break-all; position:relative; }
  .cmd button { position:absolute; top:6px; right:6px; font-size:11px; background:var(--btn-bg);
                color:var(--btn-fg); border:1px solid var(--border2); border-radius:6px; padding:2px 8px; cursor:pointer; }
  .caution { margin-top:12px; font-size:13px; color:var(--warn); line-height:1.5; }
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
  .actions { margin-top:14px; display:flex; align-items:center; gap:12px; flex-wrap:wrap; }
  .actbtn { border:none; border-radius:8px; padding:9px 16px; font-size:13.5px; font-weight:600; cursor:pointer; }
  .actbtn.block { background:var(--danger); color:#fff; }
  .actbtn.unblock { background:var(--green); color:#fff; }
  .actbtn.temp { background:var(--warn); color:#fff; }
  .actbtn.subnet { background:#8957e5; color:#fff; }
  .actbtn.evic { background:var(--btn-bg); color:var(--btn-fg); border:1px solid var(--border2); }
  .actbtn.trust { background:#1f6feb; color:#fff; }
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
</style>
</head>
<body>
  <header>
    <h1>🛡️ LogSentry — 실시간 침입 감시</h1>
    <div class="hr">
      <button id="pauseBtn" class="tbtn" onclick="togglePause()">⏸ 일시정지</button>
      <button id="themeBtn" class="tbtn" onclick="toggleTheme()">☀ 밝게</button>
      <span id="status"><span class="dot"></span>연결 중…</span>
    </div>
  </header>

  <div class="tiles">
    <div class="tile"><div class="n" id="attempt">0</div><div class="l">공격 요청(건)</div></div>
    <div class="tile warn"><div class="n" id="warn">0</div><div class="l">경고</div></div>
    <div class="tile danger"><div class="n" id="danger">0</div><div class="l">위험</div></div>
    <div class="tile"><div class="n" id="ipc">0</div><div class="l">공격 의심 IP</div></div>
  </div>

  <div id="toppanels" class="toppanels"></div>
  <div id="dist"></div>
  <div id="blocked"></div>
  <div id="trusted"></div>

  <div class="wrap">
    <h2>종류별로 보기 <span style="color:#6e7681;font-weight:400">· 탭을 누르면 그 유형만, 검색창으로 더 좁히기</span></h2>
    <div class="toolbar">
      <div id="filters" class="filters"></div>
      <input id="search" class="search" type="search" oninput="onSearch(this.value)"
             placeholder="🔎 IP·경로·도구 검색…">
    </div>
    <h2>실시간 공격 타임라인 <span style="color:#6e7681;font-weight:400">· 최근 공격부터 · 줄을 클릭하면 상세·대응·차단</span></h2>
    <table>
      <thead><tr><th>시각</th><th>IP</th><th>노린 경로</th><th>유형</th><th>상태</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </div>

  <footer>LogSentry · 탐지·기록 + 선택적 IP 차단(관리자 권한 시 실제 방화벽 조작) · 침투 흔적·차단 내역은 DB에 영구 저장 · 3초마다 자동 새로고침</footer>

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
var FILTER = '전체';    // 지금 고른 종류별 필터
var KINDS = [];         // 탭에 뜬 종류 순서
var SEARCH = '';        // 검색어(IP·경로·도구)
var PAUSED = false;     // 자동 새로고침 일시정지

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
  BLOCKED = d.blocked || [];
  TRUSTED = d.trusted || [];
  renderTop(d);
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
      + '<span class="lbl">' + esc(x.ip) + '</span><span class="cnt">' + x.count + '</span></div>';
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
    var tool = e.tool ? ' <span class="badge watch">도구</span>' : '';
    var blk = (BLOCKED.indexOf(e.ip) >= 0) ? ' <span class="badge blk">차단됨</span>' : '';
    out.push('<tr class="clk ' + cls + '" onclick="openDetail(' + i + ')">'
      + '<td class="ip">' + esc(e.time) + '</td>'
      + '<td class="ip">' + esc(e.ip) + blk + '</td>'
      + '<td class="path">' + esc(e.path) + '</td>'
      + '<td>' + esc(e.kind) + tool + '</td>'
      + '<td class="st">' + e.status + '</td>'
      + '</tr>');
  }
  document.getElementById('rows').innerHTML = out.length ? out.join('')
    : '<tr><td colspan="5" class="empty">' + (SEARCH ? '검색 결과가 없습니다' : '해당 종류의 공격 기록이 없습니다 👍') + '</td></tr>';
}

// ── 조치 공통 도구: 서버 요청 / 한 번 더 묻는 확인창 / 되돌리기 토스트 ──
function postJSON(url, obj){
  return fetch(url, {method:'POST', headers:{'Content-Type':'application/json'},
                     body: JSON.stringify(obj)})
    .then(function(r){ return r.json(); })
    .catch(function(){ return {ok:false, message:'요청 실패 — 서버 연결을 확인하세요.'}; });
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
        closeDetail(); tick();
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
        closeDetail(); tick();
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

function openDetail(i){
  var e = LAST[i]; if(!e) return;
  var sc = e.severity === '위험' ? 'danger' : 'warn';
  var rec = e.rec || {};
  var ipq = esc(e.ip);                               // onclick 에 넣을 IP(검증된 IPv4)
  var isblk = BLOCKED.indexOf(e.ip) >= 0;            // 이미 차단된 IP 인가
  var acts = (rec.actions || []).map(function(a){ return '<li>' + esc(a) + '</li>'; }).join('');
  document.getElementById('m-title').innerHTML =
    '침투 상세 <span class="sev ' + sc + '">' + esc(e.severity) + '</span>';
  document.getElementById('m-body').innerHTML =
      '<div class="kv">'
    +   '<div class="k">시각</div><div class="v ip">' + esc(e.ts_iso || e.time) + '</div>'
    +   '<div class="k">공격자 IP</div><div class="v ip">' + esc(e.ip) + '</div>'
    +   '<div class="k">노린 경로</div><div class="v path">' + esc(e.method) + ' ' + esc(e.path) + '</div>'
    +   '<div class="k">상태코드</div><div class="v">' + e.status + '</div>'
    +   '<div class="k">유형</div><div class="v">' + esc(e.kind) + '</div>'
    +   '<div class="k">도구 지문</div><div class="v ip">' + esc(e.ua || '-') + '</div>'
    +   '</div>'
    + '<div class="rec">'
    +   '<h4>🤖 대응 추천 (규칙 기반 · 참고용)</h4>'
    +   '<div class="disc">※ 이 추천은 미리 정한 규칙에 따른 <b>참고용</b>이에요. '
    +     '항상 맞는 건 아니며 <b>확정 판단이 아닙니다</b> — 실제 차단·조치 전에 '
    +     '반드시 사람이 로그를 직접 확인하고, 운영 서버는 먼저 경고 모드로 지켜보세요.</div>'
    +   '<div>' + esc(rec.headline || '') + '</div>'
    +   '<ul>' + acts + '</ul>'
    +   (rec.block_cmd ? '<div class="cmd"><button onclick="copyCmd(this)">복사</button>'
          + esc(rec.block_cmd) + '</div>' : '')
    +   (rec.caution ? '<div class="caution">⚠ ' + esc(rec.caution) + '</div>' : '')
    + '</div>'
    + '<div class="actions">'
    +   (isblk
          ? '<button class="actbtn unblock" onclick="unblockIp(&#39;' + ipq + '&#39;)">✅ 차단 해제</button>'
          : '<button class="actbtn block" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;ip&#39;,0)">🚫 영구 차단</button>'
          + '<button class="actbtn temp" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;ip&#39;,600)">⏱️ 임시 10분</button>'
          + '<button class="actbtn subnet" onclick="doBlock(&#39;' + ipq + '&#39;,&#39;subnet&#39;,0)">🛡️ 대역 /24</button>')
    +   '<button class="actbtn evic" onclick="doEvidence(&#39;' + ipq + '&#39;)">💾 증거 저장</button>'
    +   '<button class="actbtn trust" onclick="doTrust(&#39;' + ipq + '&#39;)">✅ 오탐(신뢰)</button>'
    +   '<div class="ahint">실제 윈도우 방화벽을 조작합니다 · 관리자 권한 필요 · '
    +     '클릭하면 한 번 더 확인 · 되돌리기(실행 취소) 가능 · 자기자신/사설IP는 거부</div>'
    + '</div>';
  document.getElementById('overlay').classList.add('on');
}
function closeDetail(){ document.getElementById('overlay').classList.remove('on'); }
function copyCmd(btn){
  var txt = btn.parentNode.textContent.replace(/^복사(됨)?/, '').trim();
  if(navigator.clipboard){ navigator.clipboard.writeText(txt); }
  btn.textContent = '복사됨'; setTimeout(function(){ btn.textContent = '복사'; }, 1200);
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

    if a.db:
        print(f"침투 흔적 DB: {a.db} (영구 저장)")
    if state["blocked"]:
        print(f"차단 중인 IP 복원: {len(state['blocked'])}개")
    if state["trusted"]:
        print(f"신뢰 IP 복원: {len(state['trusted'])}개")

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
            except Exception as e:  # noqa: BLE001 — 한 번 실패해도 상황판은 멈추지 않는다
                print(f"⚠ 재검사 실패(무시하고 계속): {e}")
                payload = None
            if payload is not None:
                with lock:
                    state["payload"] = payload
            time.sleep(a.scan_interval)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")   # 브라우저가 옛 화면 캐시 못하게
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):   # noqa: N802 (http.server 가 정한 이름)
            if self.path.startswith("/api/alerts"):
                with lock:
                    resp = dict(state["payload"])                 # 얕은 복사 후
                    resp["blocked"] = sorted(state["blocked"])    # 현재 차단 목록을 끼워 보냄
                    resp["trusted"] = sorted(state["trusted"])    # 신뢰(오탐) 목록도
                body = json.dumps(resp, ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path.startswith("/api/blocks"):
                with lock:
                    body = json.dumps({"blocked": sorted(state["blocked"])},
                                      ensure_ascii=False).encode("utf-8")
                self._send(200, body, "application/json; charset=utf-8")
            elif self.path == "/" or self.path.startswith("/?"):
                self._send(200, _DASHBOARD_HTML.encode("utf-8"),
                           "text/html; charset=utf-8")
            else:
                self._send(404, b"not found", "text/plain; charset=utf-8")

        def do_POST(self):   # noqa: N802 — 조치 버튼(차단/해제/증거/신뢰)이 부르는 창구
            if self.path not in ("/api/block", "/api/unblock", "/api/evidence",
                                 "/api/trust", "/api/untrust"):
                self._send(404, b"not found", "text/plain; charset=utf-8")
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
            else:                                   # /api/evidence
                res = export_evidence(a.db, ip)
            self._send(200, json.dumps(res, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def log_message(self, *args):   # 상황판 자신의 접근 로그는 콘솔에 찍지 않는다
            pass

    threading.Thread(target=scanner, daemon=True).start()   # 재검사 스레드 시작
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
    p.add_argument("--show-db", type=int, nargs="?", const=30, metavar="N",
                   help="쌓인 침투 흔적 DB 에서 최근 N건(기본 30)을 표로 보여주고 끝낸다")
    a = p.parse_args()

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
