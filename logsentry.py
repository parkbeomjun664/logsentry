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
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime

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


def _max_distinct_ips_in_window(timed_ips, window):
    """(시각, IP) 목록에서 window 초 창 안의 '서로 다른 IP 최대 수'.

    창을 미끄러뜨리며(슬라이딩) 각 순간 창 안 IP 종류 수를 세고 그 최댓값을 돌려준다.
    Counter 로 창에 남은 IP 만 센다(같은 IP 가 여러 번이면 1로).
    """
    q = deque()
    counts = defaultdict(int)   # 창 안에 살아있는 IP 별 등장 횟수
    worst = 0
    for ts, ip in sorted(timed_ips):      # 시각 순
        q.append((ts, ip))
        counts[ip] += 1
        while (ts - q[0][0]).total_seconds() > window:   # 창 밖은 버린다
            _, old = q.popleft()
            counts[old] -= 1
            if counts[old] == 0:
                del counts[old]           # 창에서 완전히 빠진 IP 는 종류에서 제외
        worst = max(worst, len(counts))   # 지금 창의 '서로 다른 IP 수'
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
    auth_ips = _max_distinct_ips_in_window(auth_hits, window)
    if auth_ips >= ip_threshold:
        results.append({"kind": "분산 무차별(인증실패)", "ips": auth_ips, "window": window})
    nf_ips = _max_distinct_ips_in_window(nf_hits, window)
    if nf_ips >= ip_threshold:
        results.append({"kind": "분산 스캔(없는 주소)", "ips": nf_ips, "window": window})
    return results


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
    try:
        while True:
            events, _ = load_events(a.logfile, a.format)
            results = analyze(events, a.window, a.probe_threshold,
                              a.auth_threshold, a.rate_threshold, a.score_threshold)
            current = {alert_key(r): r for r in results}  # IP+등급을 '이름표'로
            stamp = datetime.now().strftime("%H:%M:%S")
            if seen is None:                      # 첫 바퀴 = 기준선(조용)
                seen = set(current)
                print(f"[{stamp}] 기준선 — 현재 경보 {len(current)}건 저장")
            else:
                fresh = [current[k] for k in current if k not in seen]
                if fresh:
                    print(f"[{stamp}] 🔔 새 경보 {len(fresh)}건")
                    for r in fresh:
                        icon = "🔴" if r["level"] == "alert" else "🟡"
                        print("  " + icon + " " + fmt_screen(r))
                    if a.alert_log:
                        write_alert_log(a.alert_log, fresh)
                    send_webhook(a.webhook, fresh)   # 새 경보만 알림(소음 방지)
                else:
                    print(f"[{stamp}] 새 경보 없음")
                seen |= set(current)
            time.sleep(a.watch)
    except KeyboardInterrupt:
        print("\n감시 중지.")


def main():
    p = argparse.ArgumentParser(description="LogSentry — 접근 로그 침입 탐지")
    p.add_argument("logfile", help="접근 로그 파일(nginx/apache/JSON)")
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
    a = p.parse_args()

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
