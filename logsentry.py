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
import re
from collections import defaultdict, deque
from datetime import datetime

# nginx/apache combined 로그 한 줄 파서
_NGINX = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+ '
    r'"[^"]*" "(?P<ua>[^"]*)"'
)
_TIME_FMT = "%d/%b/%Y:%H:%M:%S %z"

# 공격 도구 지문(User-Agent)
_TOOL_UA = ("curl", "python-requests", "python-urllib", "wget", "go-http",
            "nikto", "sqlmap", "nmap", "masscan", "scan", "zgrab", "httpx",
            "recon", "agent", "bot")
# 흔한 탐침 경로(있으면 가중)
_PROBE_PATHS = ("/.env", "/.git", "/wp-login", "/wp-admin", "/phpmyadmin",
                "/admin", "/actuator", "/config", "/backup", "/.aws",
                "/server-status", "/.ssh", "/vendor", "/shell")
# 정상 소음(제외)
_SKIP = ("/favicon.ico", "/robots.txt", "/health")


def parse_line(line, fmt="auto"):
    """로그 한 줄 → 공통 형태 dict. 양식을 자동 감지한다(입구만 양식을 탄다)."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):      # JSON 로그
        return _parse_json(line)
    return _parse_nginx(line)     # nginx/apache combined


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
        if any(e["path"].startswith(s) for s in _SKIP):
            continue
        d = agg[e["ip"]]
        d["reqs"] += 1
        if e["status"] == 404:
            d["nf"] += 1
        if e["status"] in (401, 403):
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

    alerts, watches = [], []
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

        if not reasons:
            continue
        span = ""
        if d["first"] and d["last"]:
            span = f" ({d['first']:%m-%d %H:%M}~{d['last']:%H:%M})"
        line = (f"IP {ip} — 점수 {score} · 서로 다른 경로 {len(d['paths'])}개{span}"
                f"\n       {' · '.join(reasons)}")
        (alerts if score >= score_threshold else watches).append((score, line))

    alerts.sort(reverse=True)
    watches.sort(reverse=True)
    return alerts, watches


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


def main():
    p = argparse.ArgumentParser(description="LogSentry — 접근 로그 침입 탐지")
    p.add_argument("logfile", help="접근 로그 파일(nginx/apache combined)")
    p.add_argument("--format", default="nginx")
    p.add_argument("--window", type=int, default=60)
    p.add_argument("--probe-threshold", type=int, default=5)
    p.add_argument("--auth-threshold", type=int, default=5)
    p.add_argument("--rate-threshold", type=int, default=20)
    p.add_argument("--score-threshold", type=int, default=6)
    a = p.parse_args()

    events, bad = [], 0
    with open(a.logfile, encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line, a.format)
            if e:
                events.append(e)
            elif line.strip():
                bad += 1

    alerts, watches = analyze(events, a.window, a.probe_threshold,
                              a.auth_threshold, a.rate_threshold, a.score_threshold)

    print(f"LogSentry — 로그 {len(events)}줄 분석"
          + (f" (형식 불일치 {bad}줄 건너뜀)" if bad else "") + "\n")
    print("🔴 경보" if alerts else "🔴 경보 없음")
    for _, x in alerts:
        print("  " + x)
    print()
    print("🟡 관찰" if watches else "🟡 관찰 없음")
    for _, x in watches:
        print("  " + x)


if __name__ == "__main__":
    main()
