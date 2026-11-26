"""LogSentry 탐지 검증 테스트 — 표준 라이브러리 unittest 만 사용(의존성 0).

"이런 공격 로그를 넣으면 이 IP 가 경보로 떠야 한다"를 코드로 고정해 둔다.
규칙을 고치다 탐지가 깨지면 이 테스트가 실패로 알려 준다.

실행:  python -m unittest -v
"""
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

import logsentry
from logsentry import (LoginTracker, _block_refusal, _host_ok, _post_allowed, _is_private, _subnet24,
                       _target_rule, _valid_ipv4, alert_key, analyze,
                       analyze_logins, block_ip, build_dashboard_payload,
                       build_timeline, detect_distributed, export_evidence,
                       delete_logs, delete_many, edge_blocked, load_config, load_deleted, load_history, load_trusted, purge_logs, restore_logs, open_db, parse_line,
                       recent_intrusions, recommend, send_webhook, store_events,
                       trust_ip, unblock_ip, untrust_ip)

# 기본 문턱(main 의 기본값과 같게)
DEFAULTS = dict(window=60, probe_threshold=5, auth_threshold=5,
                rate_threshold=20, score_threshold=6)


def nginx(ip, hhmmss, method, path, status, ua):
    """nginx combined 형식 한 줄을 만든다."""
    return (f'{ip} - - [10/Nov/2026:{hhmmss} +0900] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "{ua}"')


def run(lines):
    """로그 줄들을 분석해 {ip: 결과} 로 돌려준다."""
    events = [e for e in (parse_line(l) for l in lines) if e]
    return {r["ip"]: r for r in analyze(events, **DEFAULTS)}


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0"
PROBES = ["/.env", "/.git/config", "/wp-login.php", "/admin", "/phpmyadmin", "/actuator/env"]


class TestDetection(unittest.TestCase):

    def test_1_scanner_is_alerted(self):
        """없는 주소를 훑는 스캐너는 경보."""
        lines = [nginx("45.146.0.99", f"09:01:0{i}", "GET", p, 404, "python-requests/2.31")
                 for i, p in enumerate(PROBES)]
        r = run(lines)
        self.assertIn("45.146.0.99", r)
        self.assertEqual(r["45.146.0.99"]["level"], "alert")
        self.assertEqual(r["45.146.0.99"]["nf"], 6)

    def test_2_bruteforce_is_alerted(self):
        """로그인 무차별(401/403 반복)은 경보."""
        lines = [nginx("185.220.101.5", f"09:03:1{i}", "POST", "/api/login", 401, "curl/8.4.0")
                 for i in range(6)]
        r = run(lines)
        self.assertEqual(r["185.220.101.5"]["level"], "alert")
        self.assertEqual(r["185.220.101.5"]["auth"], 6)

    def test_3_slow_attack_is_alerted(self):
        """40분에 걸쳐 조금씩 쑤시는 느린 공격도 IP 합산 점수로 경보."""
        lines = [nginx("141.98.80.1", "09:05:00", "GET", "/.env", 404, "Go-http-client/1.1"),
                 nginx("141.98.80.1", "09:25:00", "GET", "/admin", 404, "Go-http-client/1.1"),
                 nginx("141.98.80.1", "09:45:00", "GET", "/server-status", 404, "Go-http-client/1.1")]
        r = run(lines)
        self.assertEqual(r["141.98.80.1"]["level"], "alert")
        # 경보만 보면 다른 점수로 문턱을 넘어 고장을 놓친다 → 셈 자체도 확인
        self.assertEqual(r["141.98.80.1"]["nf"], 3)
        self.assertEqual(r["141.98.80.1"]["probes"], 3)
        self.assertTrue(r["141.98.80.1"]["tool"])

    def test_4_normal_user_is_not_alerted(self):
        """정상 브라우저 사용자는 경보가 없어야 한다(오탐 방지)."""
        lines = [nginx("203.0.113.10", "09:00:01", "GET", "/", 200, BROWSER),
                 nginx("203.0.113.10", "09:00:04", "GET", "/products", 200, BROWSER),
                 nginx("203.0.113.10", "09:00:09", "POST", "/api/login", 200, BROWSER),
                 nginx("203.0.113.10", "09:01:00", "GET", "/cart", 200, BROWSER)]
        r = run(lines)
        self.assertNotIn("203.0.113.10", r)

    def test_5_json_format_detects_same(self):
        """같은 스캐너를 JSON 양식으로 넣어도 똑같이 경보(어댑터)."""
        lines = [json.dumps({"remote_addr": "45.146.0.99",
                             "time": f"2026-11-10T09:01:0{i}+09:00",
                             "method": "GET", "uri": p, "status": 404,
                             "user_agent": "python-requests/2.31"})
                 for i, p in enumerate(PROBES)]
        r = run(lines)
        self.assertEqual(r["45.146.0.99"]["level"], "alert")
        self.assertEqual(r["45.146.0.99"]["nf"], 6)

    def test_6_noise_is_ignored(self):
        """favicon·robots.txt 같은 정상 소음은 세지 않는다."""
        lines = [nginx("203.0.113.10", f"09:00:0{i}", "GET", p, 404, BROWSER)
                 for i, p in enumerate(["/favicon.ico", "/robots.txt"] * 4)]
        r = run(lines)
        self.assertNotIn("203.0.113.10", r)

    def test_7_stealthy_combined_is_alerted(self):
        """저강도라도 서로 다른 신호가 겹치면(없는주소+인증실패) 종합점수로 경보.

        개별 신호는 각 문턱(5) 미만이고 UA 도 브라우저로 위장 → 예전엔 조용히 통과했다.
        INFOLINK 데모에서 발견한 약점(복합 의심).
        """
        lines = [nginx("185.220.101.50", f"09:10:0{i}", "GET", p, 404, BROWSER)
                 for i, p in enumerate(["/legacy", "/old", "/v1x", "/arch"])]
        lines += [nginx("185.220.101.50", f"09:10:1{i}", "POST", "/auth/login", 401, BROWSER)
                  for i in range(4)]
        r = run(lines)
        self.assertIn("185.220.101.50", r)
        self.assertEqual(r["185.220.101.50"]["level"], "alert")

    def test_8_single_signal_failed_logins_not_alerted(self):
        """정상 직원이 비번 몇 번 틀린 것(단일 종류 신호)은 복합 의심으로 오탐하지 않는다."""
        lines = [nginx("203.0.113.88", f"09:20:0{i}", "POST", "/auth/login", 401, BROWSER)
                 for i in range(3)]
        r = run(lines)
        self.assertNotIn("203.0.113.88", r)

    def test_9_account_lockout_423_counts_as_auth(self):
        """계정잠금(423)도 인증 실패로 세어, 무차별 로그인을 놓치지 않는다."""
        lines = [nginx("198.51.100.7", f"09:30:0{i}", "POST", "/auth/login", 401, "curl/8.4.0")
                 for i in range(4)]
        lines += [nginx("198.51.100.7", f"09:30:1{i}", "POST", "/auth/login", 423, "curl/8.4.0")
                  for i in range(2)]
        r = run(lines)
        self.assertEqual(r["198.51.100.7"]["level"], "alert")
        self.assertEqual(r["198.51.100.7"]["auth"], 6)   # 401×4 + 423×2

    def test_10_probe_path_detected_regardless_of_status(self):
        """비표준 상태코드(307 등)여도 탐침 경로는 경로 패턴으로 잡힌다.

        ShotTrace 검증: 없는 주소가 404 가 아니라 307(리다이렉트)로 나가도
        /.env·/admin 같은 탐침 경로는 상태코드와 무관하게 탐지된다('경로 패턴은 살아남음').
        """
        lines = [nginx("45.1.1.1", f"09:00:0{i}", "GET", p, 307, "python-requests/2.31")
                 for i, p in enumerate(PROBES)]
        r = run(lines)
        self.assertIn("45.1.1.1", r)
        self.assertEqual(r["45.1.1.1"]["nf"], 0)             # 404 가 아니라 '없는 주소'는 0
        self.assertGreaterEqual(r["45.1.1.1"]["probes"], 5)  # 그래도 탐침 경로로 잡힘


class TestConfigAndAlerts(unittest.TestCase):
    """설정 파일·웹훅·감시 이름표 — 손으로만 확인하던 것을 테스트로 고정."""

    def setUp(self):
        # load_config 가 바꾸는 전역을 백업(테스트 간 오염 방지)
        self._backup = (logsentry._TOOL_UA, logsentry._PROBE_PATHS, logsentry._SKIP,
                        logsentry._TRUSTED_IPS, logsentry._AUTH_STATUSES)

    def tearDown(self):
        (logsentry._TOOL_UA, logsentry._PROBE_PATHS, logsentry._SKIP,
         logsentry._TRUSTED_IPS, logsentry._AUTH_STATUSES) = self._backup

    def test_alert_key_groups_by_ip_and_level(self):
        """감시 이름표는 IP+등급 — 같은 공격자는 한 이름표, 승격 시 다른 이름표."""
        self.assertEqual(alert_key({"ip": "1.2.3.4", "level": "alert"}),
                         alert_key({"ip": "1.2.3.4", "level": "alert"}))
        self.assertNotEqual(alert_key({"ip": "1.2.3.4", "level": "watch"}),
                            alert_key({"ip": "1.2.3.4", "level": "alert"}))

    def test_load_config_overrides(self):
        """설정 파일이 신뢰IP·인증코드·문턱을 덮어쓴다."""
        cfg = {"trusted_ips": ["9.9.9.9"], "auth_statuses": [401, 403, 423, 422],
               "thresholds": {"score": 99}}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        try:
            th = load_config(path)
            self.assertEqual(th["score"], 99)
            self.assertIn("9.9.9.9", logsentry._TRUSTED_IPS)
            self.assertIn(422, logsentry._AUTH_STATUSES)
        finally:
            os.remove(path)

    def test_load_config_missing_uses_defaults(self):
        """설정 파일이 없으면 조용히 기본값."""
        th = load_config("no_such_config_xyz.json")
        self.assertEqual(th["window"], 60)
        self.assertEqual(th["webhook"], "")

    def test_trusted_ip_excluded_from_alerts(self):
        """신뢰 IP 는 공격해도 경보에서 빠진다(오탐 방지)."""
        lines = [nginx("9.9.9.9", f"09:40:0{i}", "GET", p, 404, "sqlmap/1.7")
                 for i, p in enumerate(PROBES)]
        # 설정으로 9.9.9.9 를 신뢰 IP 로
        logsentry._TRUSTED_IPS = ("9.9.9.9",)
        r = run(lines)
        self.assertNotIn("9.9.9.9", r)

    def test_send_webhook_noop_without_url_or_alert(self):
        """주소가 없거나 경보가 없으면 전송을 시도조차 안 한다."""
        with mock.patch("logsentry.urllib.request.urlopen") as m:
            send_webhook("", [{"level": "alert", "ip": "1.1.1.1",
                               "score": 9, "reasons": ["x"]}])
            send_webhook("http://x.test/h", [{"level": "watch", "ip": "1.1.1.1",
                                              "score": 3, "reasons": ["x"]}])
            self.assertFalse(m.called)

    def test_send_webhook_posts_alert(self):
        """경보가 있고 주소가 있으면 실제로 POST 를 시도한다."""
        r = {"level": "alert", "ip": "1.1.1.1", "score": 9,
             "reasons": ["없는 주소 10회"]}
        with mock.patch("logsentry.urllib.request.urlopen") as m:
            send_webhook("http://x.test/hook", [r])
            self.assertTrue(m.called)


class TestDistributed(unittest.TestCase):
    """[v2] 여러 IP 로 쪼갠 분산 공격 — 서버 전체 관점 탐지."""

    def test_distributed_attack_detected(self):
        """10개 IP가 짧은 창에 몰려 각자 조용히 공격해도 집단으로 잡는다."""
        lines = []
        for n in range(10):
            lines.append(nginx(f"10.1.1.{n}", f"09:00:0{n}", "GET",
                               f"/page-{n}", 404, BROWSER))
            lines.append(nginx(f"10.1.1.{n}", f"09:00:0{n}", "POST",
                               "/auth/login", 401, BROWSER))
        events = [e for e in (parse_line(l) for l in lines) if e]
        kinds = {d["kind"] for d in detect_distributed(events, 60, 5)}
        self.assertIn("분산 무차별(인증실패)", kinds)
        self.assertIn("분산 스캔(없는 주소)", kinds)
        # 개별 IP 관점에선 아무도 경보가 아니어야(각 점수 3) — 그래서 분산 눈이 필요
        r = run(lines)
        self.assertEqual([x for x in r.values() if x["level"] == "alert"], [])

    def test_distributed_spread_in_time_not_alerted(self):
        """같은 IP 수라도 시간에 흩어져 있으면(창에 안 뭉치면) 분산 아님."""
        lines = [nginx(f"10.2.2.{n}", f"09:{n:02d}:00", "POST",
                       "/auth/login", 401, BROWSER) for n in range(10)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        self.assertEqual(detect_distributed(events, 60, 5), [])

    def test_distributed_few_ips_not_alerted(self):
        """IP 수가 문턱 미만이면 분산 아님."""
        lines = [nginx(f"3.3.3.{n}", f"09:00:0{n}", "POST",
                       "/auth/login", 401, BROWSER) for n in range(3)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        self.assertEqual(detect_distributed(events, 60, 5), [])


class TestAccountDimension(unittest.TestCase):
    """[v2 미들웨어] 계정 차원 — 접근 로그엔 없는 '어느 계정' 공격."""

    BASE = datetime(2026, 11, 13, 10, 0, 0, tzinfo=timezone.utc)

    def _ev(self, ip, account, success, sec):
        return {"ts": self.BASE + timedelta(seconds=sec), "ip": ip,
                "account": account, "success": success}

    def test_password_spray_detected(self):
        """한 IP 가 짧은 시간에 여러 계정에 실패 → 비밀번호 스프레이."""
        ev = [self._ev("6.6.6.6", f"user{n}", False, n * 3) for n in range(10)]
        kinds = {h["kind"] for h in analyze_logins(ev, 60, 5, 5, 5)}
        self.assertIn("비밀번호 스프레이", kinds)

    def test_account_focus_detected(self):
        """한 계정에 여러 IP 가 실패 → 계정 집중 공격."""
        ev = [self._ev(f"7.7.7.{n}", "admin", False, n * 3) for n in range(10)]
        kinds = {h["kind"] for h in analyze_logins(ev, 60, 5, 5, 5)}
        self.assertIn("계정 집중 공격", kinds)

    def test_normal_login_not_flagged(self):
        """한 사람이 본인 계정 비번 몇 번 실수한 것은 공격 아님."""
        ev = [self._ev("8.8.8.8", "me", False, n * 2) for n in range(3)]
        self.assertEqual(analyze_logins(ev, 60, 5, 5, 5), [])

    def test_successful_logins_ignored(self):
        """성공한 로그인은 세지 않는다(실패만 신호)."""
        ev = [self._ev("6.6.6.6", f"user{n}", True, n * 3) for n in range(10)]
        self.assertEqual(analyze_logins(ev, 60, 5, 5, 5), [])

    def test_simple_bruteforce_detected(self):
        """아이디 그대로 비밀번호만 바꿔 반복(한 IP+계정 반복)도 잡는다.

        스프레이(서로 다른 계정)·집중(서로 다른 IP) 어디에도 안 걸리던 빈틈 —
        가장 전형적인 로그인 무차별. (ShotTrace 운영 검증서 발견)
        """
        ev = [self._ev("9.9.9.9", "admin", False, n * 2) for n in range(6)]
        kinds = {h["kind"] for h in analyze_logins(ev, 60, 5, 5, 5)}
        self.assertIn("단순 무차별", kinds)
        # 스프레이(계정 1개)·집중(IP 1개)에는 해당 안 됨
        self.assertNotIn("비밀번호 스프레이", kinds)
        self.assertNotIn("계정 집중 공격", kinds)

    def test_bruteforce_below_threshold_not_flagged(self):
        """반복이 문턱 미만이면(비번 몇 번 실수) 공격 아님 — 오탐 방지."""
        ev = [self._ev("9.9.9.9", "admin", False, n * 2) for n in range(4)]
        self.assertEqual(analyze_logins(ev, 60, 5, 5, 5), [])

    def test_login_tracker_record_and_check(self):
        """드롭인 감시기: record 로 모아 check 로 스프레이를 잡는다."""
        t = LoginTracker(window=60, spray_threshold=5, account_threshold=5)
        for n in range(10):
            t.record("6.6.6.6", f"user{n}", False,
                     ts=self.BASE + timedelta(seconds=n * 2))
        kinds = {h["kind"] for h in t.check()}
        self.assertIn("비밀번호 스프레이", kinds)

    def test_login_tracker_prunes_old(self):
        """keep_seconds 보다 오래된 시도는 버려 메모리가 무한히 늘지 않는다."""
        t = LoginTracker(keep_seconds=100)
        t.record("1.1.1.1", "a", False, ts=self.BASE)
        t.record("1.1.1.1", "b", False, ts=self.BASE + timedelta(seconds=200))
        self.assertEqual(len(t._events), 1)   # 첫 건은 100초 넘어 버려짐

    def test_login_tracker_works_despite_http_200(self):
        """상태코드 무관: 로그인 실패가 HTTP 200 이어도 잡는다(ShotTrace 치명 약점 ①의 해법).

        ShotTrace(Next.js 서버액션)는 로그인 실패도 HTTP 200 이라 접근 로그 기반
        인증 탐지(P2)가 무력했다. LoginTracker 는 상태코드가 아니라 앱이 판정한
        success 를 직접 받으므로, 200 이든 307 이든 스프레이를 정확히 잡는다.
        """
        t = LoginTracker(window=60, spray_threshold=5, account_threshold=5)
        for n in range(10):
            # HTTP 응답은 200 이지만 앱이 판정한 success=False 로 기록
            t.record("9.9.9.9", f"user{n}", success=False,
                     ts=self.BASE + timedelta(seconds=n * 2))
        kinds = {h["kind"] for h in t.check()}
        self.assertIn("비밀번호 스프레이", kinds)


class TestDashboardAndDB(unittest.TestCase):
    """[v2 상황판] 대응 추천·침투 흔적 DB·타임라인 — 대표님 요청 기능."""

    def _events(self):
        """공격자 1명이 탐침 경로 6개(404)를 쑤시고, 중간에 정상 소음(favicon) 한 건."""
        lines = [nginx("203.0.113.77", f"09:00:0{i}", "GET", p, 404, "python-requests/2.31")
                 for i, p in enumerate(PROBES)]
        lines.append(nginx("203.0.113.77", "09:00:30", "GET", "/favicon.ico", 404,
                           "python-requests/2.31"))   # 정상 소음 — 세면 안 됨
        return [e for e in (parse_line(l) for l in lines) if e]

    def test_payload_counts_each_request_once(self):
        """공격 요청(건)=공격자가 보낸 요청 수 — 한 요청을 한 번만 세고 소음(favicon)은 뺀다."""
        results = analyze(self._events(), **DEFAULTS)
        p = build_dashboard_payload(results, [], [])
        self.assertEqual(p["attempt_count"], 6)   # 요청 6건(favicon 제외, 탐침을 더해 12로 부풀면 안 됨)
        self.assertEqual(p["ip_count"], 1)

    def test_attempt_count_on_redirect_server(self):
        """리다이렉트(307) 서버 — 404가 0이라도 공격 요청 수가 실제값으로 잡힌다(ShotTrace 교훈)."""
        lines = [nginx("203.0.113.77", f"09:00:0{i}", "GET", p, 307, "sqlmap/1.7")
                 for i, p in enumerate(PROBES)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        p = build_dashboard_payload(analyze(events, **DEFAULTS), [], [])
        self.assertEqual(p["attempt_count"], len(PROBES))   # 307이어도 6건으로 잡힘(옛 지표는 0)

    def test_timeline_newest_first_and_skips_noise(self):
        """타임라인은 최근 공격이 맨 위, 정상 소음(favicon)은 제외."""
        tl = build_timeline(self._events(), 60)
        self.assertEqual(len(tl), 6)                            # favicon 제외 6건
        times = [row["time"] for row in tl]
        self.assertEqual(times, sorted(times, reverse=True))   # 내림차순(최근 먼저)
        self.assertTrue(all("favicon" not in row["path"] for row in tl))

    def test_recommend_has_actions_and_block_command(self):
        """추천은 조치 목록과, 그 IP 를 박은 Windows 차단 명령을 준다."""
        rec = recommend("203.0.113.77", "/.env", 404, "python-requests/2.31", "탐침경로")
        self.assertEqual(rec["severity"], "위험")
        self.assertTrue(rec["actions"])                        # 조치가 비어있지 않음
        self.assertIn("203.0.113.77", rec["block_cmd"])        # 차단 명령에 그 IP
        self.assertIn("action=block", rec["block_cmd"])

    def test_auth_fail_is_warning_level_recommend(self):
        """인증거부도 '위험', 없는 주소(정찰)는 '경고'로 심각도를 나눈다."""
        self.assertEqual(recommend("1.1.1.1", "/x", 401, "curl", "인증거부")["severity"], "위험")
        self.assertEqual(recommend("1.1.1.1", "/x", 404, "curl", "없는 주소")["severity"], "경고")

    def test_db_stores_and_dedupes(self):
        """같은 공격을 두 번 저장해도 DB 는 중복을 무시한다(UNIQUE). 흔적은 영구 보존."""
        ev = self._events()
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = open_db(path)
        try:
            first = store_events(conn, ev)
            second = store_events(conn, ev)            # 똑같은 걸 다시 저장
            self.assertEqual(first, 6)                 # 수상한 6건 저장(favicon 제외)
            self.assertEqual(second, 0)                # 중복은 0건(안 쌓임)
            tl = recent_intrusions(conn, 60)
            self.assertEqual(len(tl), 6)
            self.assertEqual(tl[0]["ip"], "203.0.113.77")   # 최근 건이 맨 위
        finally:
            conn.close()
            os.remove(path)


class TestBlocking(unittest.TestCase):
    """[v3] IP 차단 — 안전장치 검증. 실제 방화벽(netsh)은 건드리지 않는 선에서."""

    def test_valid_ipv4_strict(self):
        """정상 IPv4만 통과 — 주입 문자열·범위초과·형식오류는 거부(명령어 주입 차단)."""
        self.assertTrue(_valid_ipv4("203.0.113.77"))
        for bad in ("999.1.1.1", "1.2.3", "a.b.c.d", "1.1.1.1; calc", "", "127.0.0.1 && del"):
            self.assertFalse(_valid_ipv4(bad), bad)

    def test_refuse_self_and_linklocal(self):
        """자기자신(127.x)·링크로컬(169.254.x)·형식오류는 차단을 거부한다."""
        self.assertIsNone(_block_refusal("203.0.113.77"))     # 공인 IP는 차단 가능
        self.assertIsNotNone(_block_refusal("127.0.0.1"))     # 나 자신 → 거부
        self.assertIsNotNone(_block_refusal("169.254.1.1"))   # 링크로컬 → 거부
        self.assertIsNotNone(_block_refusal("bad"))           # 형식오류 → 거부

    def test_is_private(self):
        """사설망 판별(사내 직원 경고용)."""
        for ip in ("10.0.0.5", "172.16.3.4", "192.168.1.9"):
            self.assertTrue(_is_private(ip), ip)
        self.assertFalse(_is_private("203.0.113.77"))

    def test_block_refused_does_not_run_firewall(self):
        """거부 대상(127.x·주입 문자열)은 netsh 를 부르지 않고 'refused'로 돌려준다."""
        r1 = block_ip("", "127.0.0.1")
        self.assertFalse(r1["ok"])
        self.assertEqual(r1["status"], "refused")
        r2 = block_ip("", "1.1.1.1; calc")        # 명령어 주입 시도
        self.assertEqual(r2["status"], "refused")

    def test_block_attempt_is_audited(self):
        """차단 시도는 결과와 무관하게 감사기록(block_audit)에 남는다 — 이력 추적."""
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            block_ip(path, "127.0.0.1")           # 거부되지만 기록은 남아야 함
            conn = open_db(path)
            rows = conn.execute("SELECT ip, action, result FROM block_audit").fetchall()
            conn.close()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1], "block")
            self.assertEqual(rows[0][2], "refused")
        finally:
            os.remove(path)


class TestActions(unittest.TestCase):
    """[v3.1] 임시/대역 차단·증거 저장·되돌리기 — 조치 확장. 실제 방화벽은 안 건드리는 선에서."""

    def _probe_events(self):
        lines = [nginx("203.0.113.77", f"09:00:0{i}", "GET", p, 404, "python-requests/2.31")
                 for i, p in enumerate(PROBES)]
        return [e for e in (parse_line(l) for l in lines) if e]

    def test_subnet_target_and_rule(self):
        """/24 대역 대상·규칙이름·표시키 계산."""
        self.assertEqual(_subnet24("203.0.113.77"), "203.0.113.0/24")
        net, rule, key = _target_rule("203.0.113.77", "subnet")
        self.assertEqual(net, "203.0.113.0/24")
        self.assertEqual(key, "203.0.113.0/24")
        self.assertIn("203-0-113-0_24", rule)

    def test_subnet_block_still_refuses_self(self):
        """대역 차단이라도 자기자신(127.x)은 거부 — 안전장치는 scope 무관."""
        self.assertEqual(block_ip("", "127.0.0.1", scope="subnet")["status"], "refused")

    def test_unblock_key_forms(self):
        """해제는 단일 IP 키와 '/24' 대역 키를 모두 받아 예외 없이 처리한다."""
        self.assertEqual(unblock_ip("", "bad")["status"], "refused")   # 형식오류 거부
        r = unblock_ip("", "203.0.113.0/24")                           # 대역 키도 dict 반환
        self.assertEqual(r.get("key"), "203.0.113.0/24")

    def test_evidence_export(self):
        """증거 저장 — 그 IP 기록을 파일로, 건수·내용 확인. 기록 없는 IP 는 거부."""
        ev = self._probe_events()
        fd, dbp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        conn = open_db(dbp)
        store_events(conn, ev)
        conn.close()
        res = export_evidence(dbp, "203.0.113.77")
        try:
            self.assertTrue(res["ok"])
            self.assertEqual(res["count"], len(PROBES))
            self.assertTrue(os.path.exists(res["path"]))
            with open(res["path"], encoding="utf-8") as fh:
                self.assertIn("203.0.113.77", fh.read())
            self.assertFalse(export_evidence(dbp, "198.51.100.9")["ok"])   # 기록 없음
        finally:
            if res.get("path") and os.path.exists(res["path"]):
                os.remove(res["path"])
            os.remove(dbp)


class TestTrustAndPanels(unittest.TestCase):
    """[v3.2] 신뢰 IP(오탐 처리) · Top 패널 — 피어 도구에서 적용한 개선."""

    def test_trust_roundtrip(self):
        """신뢰 추가→목록에 있음→해제→사라짐. 형식오류는 거부."""
        fd, dbp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            self.assertFalse(trust_ip(dbp, "bad")["ok"])             # 형식오류 거부
            self.assertTrue(trust_ip(dbp, "203.0.113.77")["ok"])
            self.assertIn("203.0.113.77", load_trusted(dbp))
            self.assertTrue(untrust_ip(dbp, "203.0.113.77")["ok"])
            self.assertNotIn("203.0.113.77", load_trusted(dbp))
        finally:
            os.remove(dbp)

    def test_top_panels_in_payload(self):
        """payload 에 Top 공격IP·Top 경로가 횟수 내림차순으로 담긴다."""
        lines = [nginx("203.0.113.77", f"09:00:0{i}", "GET", p, 404, "sqlmap")
                 for i, p in enumerate(PROBES)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        results = analyze(events, **DEFAULTS)
        p = build_dashboard_payload(results, [], build_timeline(events, 60))
        self.assertTrue(p["top_ips"])
        self.assertEqual(p["top_ips"][0]["ip"], "203.0.113.77")
        self.assertTrue(p["top_paths"])
        counts = [x["count"] for x in p["top_paths"]]
        self.assertEqual(counts, sorted(counts, reverse=True))       # 내림차순


class TestHistoryScreen(unittest.TestCase):
    """[v3.3] 숫자 칸 클릭 목록 · 조치 기록 화면 — 대표님 요청."""

    def test_history_lists_trusted_and_audit_newest_first(self):
        """조치 기록: 신뢰 IP와 조치 이력(최근 먼저)이 담기고, 거부된 시도도 남는다."""
        fd, dbp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        try:
            block_ip(dbp, "127.0.0.1")              # 거부(refused) — 이력엔 남아야 함
            trust_ip(dbp, "198.51.100.9")           # 신뢰(ok)
            h = load_history(dbp)
            self.assertTrue(h["db"])
            self.assertEqual([t["ip"] for t in h["trusted"]], ["198.51.100.9"])
            self.assertEqual(h["blocked"], [])      # 실제 차단 성공은 없음
            actions = [(a["action"], a["result"]) for a in h["audit"]]
            self.assertIn(("block", "refused"), actions)
            self.assertIn(("trust", "ok"), actions)
            ts = [a["ts"] for a in h["audit"]]
            self.assertEqual(ts, sorted(ts, reverse=True))   # 최근 먼저
        finally:
            os.remove(dbp)

    def test_history_without_db_is_empty_not_error(self):
        """DB 가 꺼져 있으면 빈 기록(db=False)을 돌려줄 뿐 오류가 나지 않는다."""
        h = load_history("")
        self.assertFalse(h["db"])
        self.assertEqual((h["blocked"], h["trusted"], h["audit"]), ([], [], []))

    def test_alert_rows_carry_request_count(self):
        """위험/경고 목록 화면용 — IP별 행에 요청 수(reqs)가 실린다."""
        lines = [nginx("203.0.113.77", f"09:00:0{i}", "GET", p, 404, "sqlmap")
                 for i, p in enumerate(PROBES)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        p = build_dashboard_payload(analyze(events, **DEFAULTS), [], [])
        self.assertEqual(p["alerts"][0]["reqs"], len(PROBES))


def caddy(ip, ts, method, uri, status, ua, remote=None):
    """Caddy 접근 로그(JSON) 한 줄을 실제 모양 그대로 만든다."""
    return json.dumps({
        "level": "info", "ts": ts, "logger": "http.log.access.log0", "msg": "handled request",
        "request": {"remote_ip": remote or ip, "remote_port": "51234", "client_ip": ip,
                    "proto": "HTTP/1.1", "method": method, "host": "infopath.iptime.org:3000",
                    "uri": uri, "headers": {"User-Agent": [ua], "Authorization": ["REDACTED"]}},
        "bytes_read": 0, "duration": 0.0012, "size": 512, "status": status,
    })


class TestCaddyLog(unittest.TestCase):
    """[v3.4] Caddy 접근 로그 읽기 — 인포패스 MES 앞단(Caddy) 로그를 바로 탐지에 쓰기 위해."""

    def test_parses_nested_fields(self):
        """겹친 구조에서 IP·방식·경로(쿼리 제거)·상태·도구 지문·시각을 꺼낸다."""
        e = parse_line(caddy("211.45.1.2", 1764036000.5, "GET", "/api/files/1?token=REDACTED", 404, "sqlmap/1.7"))
        self.assertEqual(e["ip"], "211.45.1.2")
        self.assertEqual(e["method"], "GET")
        self.assertEqual(e["path"], "/api/files/1")
        self.assertEqual(e["status"], 404)
        self.assertEqual(e["ua"], "sqlmap/1.7")
        self.assertIsNotNone(e["ts"])
        self.assertEqual(round(e["ts"].timestamp(), 1), 1764036000.5)

    def test_prefers_client_ip_over_remote_ip(self):
        """client_ip(진짜 IP)를 remote_ip 보다 먼저 쓴다."""
        e = parse_line(caddy("211.45.1.2", 1764036000, "GET", "/", 200, "Mozilla/5.0", remote="192.168.10.1"))
        self.assertEqual(e["ip"], "211.45.1.2")

    def test_caddy_lines_are_detected_as_attack(self):
        """Caddy 로그만으로도 탐침 스캐너를 경보로 잡는다(기존 탐지 규칙 그대로)."""
        lines = [caddy("211.45.1.2", 1764036000 + i, "GET", p, 404, "sqlmap/1.7") for i, p in enumerate(PROBES)]
        events = [e for e in (parse_line(l) for l in lines) if e]
        self.assertEqual(len(events), len(PROBES))
        r = {x["ip"]: x for x in analyze(events, **DEFAULTS)}
        self.assertEqual(r["211.45.1.2"]["level"], "alert")

    def test_non_access_json_is_ignored(self):
        """request 가 없거나 깨진 JSON 줄은 조용히 건너뛴다."""
        self.assertIsNone(parse_line('{"level":"info","ts":1764036000,"msg":"server running"}'))
        self.assertIsNone(parse_line('{"request": {"uri": "/"}, "status": 200}'))   # IP 없음
        self.assertIsNone(parse_line('[1, 2, 3]'))


class TestRealTrafficLessons(unittest.TestCase):
    """[v3.5] 인포패스 첫 관찰(11/25)에서 배운 것 — React2Shell 놓침, 8081 401 오분류, 대역 신뢰."""

    def setUp(self):
        self._b = (logsentry._TRUSTED_IPS, logsentry._AUTH_PATHS, logsentry._SUSPICIOUS_HEADERS)

    def tearDown(self):
        logsentry._TRUSTED_IPS, logsentry._AUTH_PATHS, logsentry._SUSPICIOUS_HEADERS = self._b

    def _react2shell(self, ip="27.100.38.10", n=4):
        out = []
        for i in range(n):
            o = json.loads(caddy(ip, 1764065760 + i, "POST", "/", 499, "Mozilla/5.0"))
            o["request"]["headers"]["Next-Action"] = ["x"]
            o["request"]["headers"]["Content-Type"] = ["multipart/form-data; boundary=----x"]
            out.append(json.dumps(o))
        return [parse_line(l) for l in out]

    def test_react2shell_single_request_is_alert(self):
        """Next-Action 헤더 요청은 한 번만 와도 '위험' 경보 — 오늘 실제로 놓친 공격."""
        ev = self._react2shell(n=1)
        r = {x["ip"]: x for x in analyze(ev, **DEFAULTS)}
        self.assertEqual(r["27.100.38.10"]["level"], "alert")
        self.assertTrue(any("의심 헤더" in s for s in r["27.100.38.10"]["reasons"]))
        tl = build_timeline(ev, 60)
        self.assertEqual(tl[0]["kind"], "의심 헤더")
        self.assertEqual(tl[0]["severity"], "위험")

    def test_suspicious_headers_can_be_turned_off(self):
        """서버 액션을 실제로 쓰는 앱이면 설정으로 끌 수 있다(오탐 방지)."""
        logsentry._SUSPICIOUS_HEADERS = ()
        r = {x["ip"]: x for x in analyze(self._react2shell(n=1), **DEFAULTS)}
        self.assertNotIn("27.100.38.10", r)

    def test_nonstandard_method_flagged(self):
        """EXDW 같은 비표준 메서드(nmap 서비스 탐지)는 의심으로 잡는다."""
        e = parse_line(nginx("35.210.235.16", "11:45:00", "EXDW", "/", 401, "Mozilla/5.0"))
        self.assertEqual(build_timeline([e], 60)[0]["kind"], "비표준 메서드")
        r = {x["ip"]: x for x in analyze([e], **DEFAULTS)}
        self.assertIn("35.210.235.16", r)

    def test_auth_paths_separates_login_failure_from_scanning(self):
        """로그인 경로를 지정하면: 로그인 401=인증거부, 다른 경로 401=권한 밖 경로(정찰)."""
        logsentry._AUTH_PATHS = ("/api/v1/auth/login",)
        login = parse_line(caddy("1.2.3.4", 1764036000, "POST", "/api/v1/auth/login", 401, "Mozilla/5.0"))
        scan = parse_line(caddy("5.6.7.8", 1764036000, "GET", "/mcp", 401, "Mozilla/5.0"))
        kinds = {r["ip"]: r["kind"] for r in build_timeline([login, scan], 60)}
        self.assertEqual(kinds["1.2.3.4"], "인증거부")
        self.assertEqual(kinds["5.6.7.8"], "권한 밖 경로")

    def test_distributed_401_scan_is_scan_not_bruteforce(self):
        """7개 IP가 /mcp 등에 401 → 로그인 경로 지정 시 '분산 스캔'으로(무차별 아님) — Infrawatch 사례."""
        logsentry._AUTH_PATHS = ("/api/v1/auth/login",)
        ev = [parse_line(caddy(f"203.0.113.{i}", 1764034780 + i * 0.2, "GET", "/mcp", 401, "Mozilla/5.0"))
              for i in range(1, 8)]
        kinds = [d["kind"] for d in detect_distributed(ev, 60, 5)]
        self.assertTrue(any("스캔" in k for k in kinds), kinds)
        self.assertFalse(any("무차별" in k for k in kinds), kinds)

    def test_trusted_cidr(self):
        """신뢰 IP에 대역(CIDR)을 쓸 수 있다 — 대역 안은 제외, 밖은 그대로 탐지."""
        logsentry._TRUSTED_IPS = ("192.168.10.0/24", "::1")
        inside = [parse_line(nginx("192.168.10.5", f"09:00:0{i}", "GET", p, 404, "sqlmap")) for i, p in enumerate(PROBES)]
        outside = [parse_line(nginx("192.168.11.5", f"09:00:0{i}", "GET", p, 404, "sqlmap")) for i, p in enumerate(PROBES)]
        r = {x["ip"]: x for x in analyze(inside + outside, **DEFAULTS)}
        self.assertNotIn("192.168.10.5", r)
        self.assertIn("192.168.11.5", r)


class TestRealTrafficLessons2(unittest.TestCase):
    """[v3.6] 개선판 적용 결과에서 나온 보완 — Nmap 고정 탐침, 덧붙이기 설정, 표시 분리."""

    def setUp(self):
        self._b = (logsentry._PROBE_PATHS, logsentry._TOOL_UA, logsentry._SKIP, logsentry._AUTH_PATHS)

    def tearDown(self):
        logsentry._PROBE_PATHS, logsentry._TOOL_UA, logsentry._SKIP, logsentry._AUTH_PATHS = self._b

    def test_nmap_fixed_probe_is_probe(self):
        """Nmap 서비스 탐지 고정 문자열(/nice ports,/Trinity.txt.bak)은 기본으로 탐침 — 71.6.243.52 사례."""
        e = parse_line(caddy("71.6.243.52", 1764049190, "GET", "/nice%20ports%2C/Trinity.txt.bak", 401, ""))
        self.assertEqual(build_timeline([e], 60)[0]["kind"], "탐침경로")

    def test_extra_keys_append_not_replace(self):
        """*_extra 설정은 기본 목록을 지우지 않고 덧붙인다."""
        cfg = {"probe_paths_extra": ["/secret-admin"], "skip_extra": ["/_next/static/"]}
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
        try:
            load_config(path)
            self.assertIn("/secret-admin", logsentry._PROBE_PATHS)
            self.assertIn("/.env", logsentry._PROBE_PATHS)          # 기본 목록 유지
            self.assertIn("/_next/static/", logsentry._SKIP)
            self.assertIn("/favicon.ico", logsentry._SKIP)
        finally:
            os.remove(path)

    def test_reason_splits_404_and_offlimits(self):
        """경보 이유에 '없는 주소'와 '권한 밖 경로'를 나눠 표시한다(섞인 숫자로 헷갈리지 않게)."""
        logsentry._AUTH_PATHS = ("/api/v1/auth/login",)
        lines = ([caddy("9.8.7.6", 1764036000 + i, "GET", f"/nope{i}", 404, "Mozilla/5.0") for i in range(3)]
                 + [caddy("9.8.7.6", 1764036010 + i, "GET", f"/api/x{i}", 401, "Mozilla/5.0") for i in range(5)])
        r = {x["ip"]: x for x in analyze([parse_line(l) for l in lines], **DEFAULTS)}
        self.assertIn("없는 주소 3회 · 권한 밖 경로 5회", r["9.8.7.6"]["reasons"])


class TestDashboardSecurity(unittest.TestCase):
    """[v3.7] 상황판 조치 요청 위조(CSRF)·DNS 리바인딩 방지 — 서버 세션 검토에서 발견."""

    T = "s3cr3t-token"

    def test_host_must_be_ip_or_localhost(self):
        """Host 가 IP 숫자나 localhost 일 때만 — 도메인 이름(리바인딩 수법)은 거절."""
        for ok in ("127.0.0.1:8790", "localhost:8790", "[::1]:8790", "192.168.10.2:8790", "127.0.0.1"):
            self.assertTrue(_host_ok(ok), ok)
        for bad in ("evil.example:8790", "attacker.test", "", None, "127.0.0.1.nip.io:8790"):
            self.assertFalse(_host_ok(bad), bad)

    def test_post_needs_matching_token(self):
        """비밀 표(토큰)가 없거나 틀리면 거절, 맞으면 허용."""
        h = {"Host": "127.0.0.1:8790", "Origin": "http://127.0.0.1:8790"}
        self.assertEqual(_post_allowed(h, self.T), (False, "token"))
        self.assertEqual(_post_allowed({**h, "X-LogSentry-Token": "wrong"}, self.T), (False, "token"))
        self.assertEqual(_post_allowed({**h, "X-LogSentry-Token": self.T}, self.T), (True, ""))

    def test_post_from_other_site_rejected(self):
        """다른 사이트(Origin 불일치)·null Origin·도메인 Host 는 토큰이 맞아도 거절."""
        base = {"Host": "127.0.0.1:8790", "X-LogSentry-Token": self.T}
        self.assertEqual(_post_allowed({**base, "Origin": "https://evil.example"}, self.T)[1], "Origin")
        self.assertEqual(_post_allowed({**base, "Origin": "null"}, self.T)[1], "Origin")
        self.assertEqual(_post_allowed({**base, "Host": "evil.example:8790"}, self.T)[1], "Host")

    def test_top_panel_counts_all_requests(self):
        """Top 패널 숫자는 그 IP의 전체 요청 수 — 의심 헤더만 보낸 공격자도 0 이 아니게."""
        lines = []
        for i in range(4):
            o = json.loads(caddy("27.100.38.10", 1764065760 + i, "POST", "/", 499, "Mozilla/5.0"))
            o["request"]["headers"]["Next-Action"] = ["x"]
            lines.append(json.dumps(o))
        ev = [parse_line(l) for l in lines]
        p = build_dashboard_payload(analyze(ev, **DEFAULTS), [], build_timeline(ev, 60))
        self.assertEqual(p["top_ips"][0]["ip"], "27.100.38.10")
        self.assertEqual(p["top_ips"][0]["count"], 4)


class TestBrand(unittest.TestCase):
    """[v3.8] 화면 이름(brand) 설정 — 인포패스는 InfoGuard, 공개 저장소는 기본 LogSentry."""

    def setUp(self):
        self._b = logsentry._BRAND

    def tearDown(self):
        logsentry._BRAND = self._b

    def test_default_brand_is_logsentry(self):
        self.assertEqual(logsentry._BRAND, "LogSentry")

    def test_config_sets_brand(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"brand": "InfoGuard"}, f)
        try:
            load_config(path)
            self.assertEqual(logsentry._BRAND, "InfoGuard")
        finally:
            os.remove(path)

    def test_dashboard_has_brand_placeholder(self):
        """화면 템플릿에 자리표시자가 있어 켤 때 이름이 끼워진다."""
        self.assertIn("__LS_BRAND__", logsentry._DASHBOARD_HTML)
        self.assertNotIn("LogSentry 실시간", logsentry._DASHBOARD_HTML)  # 제목이 고정 이름이 아님


class TestBrandLogo(unittest.TestCase):
    """[v3.9] 로고 설정(brand_logo) — 파일/ data URI, 없으면 기본 방패, 공개 저장소엔 로고 미포함."""

    def setUp(self): self._b = logsentry._BRAND_LOGO
    def tearDown(self): logsentry._BRAND_LOGO = self._b

    def test_default_is_shield(self):
        logsentry._BRAND_LOGO = ""
        self.assertIn("brand-emoji", logsentry._logo_html())

    def test_data_uri_passthrough(self):
        logsentry._BRAND_LOGO = "data:image/png;base64,AAAA"
        h = logsentry._logo_html()
        self.assertIn("brand-logo-img", h)
        self.assertIn("data:image/png;base64,AAAA", h)

    def test_file_path_embedded(self):
        fd, path = tempfile.mkstemp(suffix=".png")
        os.write(fd, bytes([0x89, 0x50, 0x4E, 0x47]) + b"logo-bytes")
        os.close(fd)
        try:
            logsentry._BRAND_LOGO = path
            self.assertIn("data:image/png;base64,", logsentry._logo_html())
        finally:
            os.remove(path)

    def test_bad_path_falls_back(self):
        logsentry._BRAND_LOGO = os.path.join("no_such_dir_xyz", "missing.png")
        self.assertIn("brand-emoji", logsentry._logo_html())

    def test_public_html_has_no_company_logo(self):
        """공개 템플릿엔 회사 로고(data URI)가 없다 — 기본 자리표시자만."""
        self.assertIn("__LS_LOGO__", logsentry._DASHBOARD_HTML)
        self.assertNotIn("data:image", logsentry._DASHBOARD_HTML)


class TestLogDeleteRestore(unittest.TestCase):
    """[v3.10] 공격 내역 삭제(소프트)·복구·영구삭제 — 대표님 요청."""

    def _db(self):
        fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
        lines = [nginx("203.0.113.50", f"09:00:0{i}", "GET", pt, 404, "sqlmap")
                 for i, pt in enumerate(PROBES[:3])]
        lines += [nginx("198.51.100.7", f"09:01:0{i}", "GET", f"/x{i}", 404, "curl") for i in range(2)]
        ev = [e for e in (parse_line(l) for l in lines) if e]
        conn = open_db(p); store_events(conn, ev); conn.close()
        return p

    def test_delete_one_hides_from_timeline_and_goes_to_trash(self):
        p = self._db()
        try:
            conn = open_db(p); tl = recent_intrusions(conn); conn.close()
            self.assertEqual(len(tl), 5)
            row = tl[0]
            r = delete_logs(p, {"scope": "one", "ip": row["ip"], "ts": row["ts_iso"],
                                "path": row["path"], "status": row["status"]})
            self.assertEqual(r["count"], 1)
            conn = open_db(p)
            self.assertEqual(len(recent_intrusions(conn)), 4)   # 타임라인에서 사라짐
            conn.close()
            self.assertEqual(len(load_deleted(p)["rows"]), 1)   # 삭제함에 있음
        finally:
            os.remove(p)

    def test_delete_by_ip_and_restore(self):
        p = self._db()
        try:
            r = delete_logs(p, {"scope": "ip", "ip": "198.51.100.7"})
            self.assertEqual(r["count"], 2)
            conn = open_db(p)
            ips = {t["ip"] for t in recent_intrusions(conn)}; conn.close()
            self.assertNotIn("198.51.100.7", ips)
            restore_logs(p, {"scope": "ip", "ip": "198.51.100.7"})
            conn = open_db(p)
            ips = {t["ip"] for t in recent_intrusions(conn)}; conn.close()
            self.assertIn("198.51.100.7", ips)                  # 복구됨
            self.assertEqual(len(load_deleted(p)["rows"]), 0)
        finally:
            os.remove(p)

    def test_deleted_survives_rescan(self):
        """삭제한 건은 같은 로그를 다시 저장해도 되살아나지 않는다(소프트 삭제 유지)."""
        p = self._db()
        try:
            delete_logs(p, {"scope": "ip", "ip": "198.51.100.7"})
            lines = [nginx("198.51.100.7", f"09:01:0{i}", "GET", f"/x{i}", 404, "curl") for i in range(2)]
            ev = [e for e in (parse_line(l) for l in lines) if e]
            conn = open_db(p); store_events(conn, ev)           # 재스캔(중복 저장 시도)
            ips = {t["ip"] for t in recent_intrusions(conn)}; conn.close()
            self.assertNotIn("198.51.100.7", ips)
        finally:
            os.remove(p)

    def test_purge_is_permanent(self):
        p = self._db()
        try:
            delete_logs(p, {"scope": "ip", "ip": "198.51.100.7"})
            self.assertEqual(len(load_deleted(p)["rows"]), 2)
            r = purge_logs(p, {"scope": "all"})
            self.assertEqual(r["count"], 2)
            self.assertEqual(len(load_deleted(p)["rows"]), 0)   # 삭제함 비워짐
            conn = open_db(p)
            total = conn.execute("SELECT COUNT(*) FROM intrusion").fetchone()[0]; conn.close()
            self.assertEqual(total, 3)                          # 영구 삭제라 행 자체가 사라짐
        finally:
            os.remove(p)

    def test_delete_many_selected(self):
        p = self._db()
        try:
            conn = open_db(p); tl = recent_intrusions(conn); conn.close()
            picks = [{"ts": r["ts_iso"], "ip": r["ip"], "path": r["path"], "status": r["status"]} for r in tl[:3]]
            r = delete_many(p, picks, 1)
            self.assertEqual(r["count"], 3)
            conn = open_db(p); self.assertEqual(len(recent_intrusions(conn)), 2); conn.close()
            self.assertEqual(len(load_deleted(p)["rows"]), 3)
            delete_many(p, picks, 0)   # 복구
            conn = open_db(p); self.assertEqual(len(recent_intrusions(conn)), 5); conn.close()
        finally:
            os.remove(p)

    def test_delete_all(self):
        p = self._db()
        try:
            r = delete_logs(p, {"scope": "all"})
            self.assertEqual(r["count"], 5)
            conn = open_db(p); self.assertEqual(len(recent_intrusions(conn)), 0); conn.close()
            self.assertEqual(len(load_deleted(p)["rows"]), 5)
            restore_logs(p, {"scope": "all"})
            conn = open_db(p); self.assertEqual(len(recent_intrusions(conn)), 5); conn.close()
        finally:
            os.remove(p)

    def test_restore_all(self):
        p = self._db()
        try:
            delete_logs(p, {"scope": "ip", "ip": "203.0.113.50"})
            delete_logs(p, {"scope": "ip", "ip": "198.51.100.7"})
            self.assertEqual(len(load_deleted(p)["rows"]), 5)
            restore_logs(p, {"scope": "all"})
            self.assertEqual(len(load_deleted(p)["rows"]), 0)
            conn = open_db(p); self.assertEqual(len(recent_intrusions(conn)), 5); conn.close()
        finally:
            os.remove(p)


class TestEdgeBlocked(unittest.TestCase):
    """[v3.11] 앞단(Caddy)이 403 으로 거절한 의심 헤더 공격은 '앞단 차단'으로 구분."""

    def test_flag(self):
        self.assertTrue(edge_blocked("의심 헤더", 403))
        self.assertFalse(edge_blocked("의심 헤더", 499))      # 앱까지 간 것(이전 상태)
        self.assertFalse(edge_blocked("권한 밖 경로", 403))    # 앱의 403 은 앞단 차단 아님

    def test_recommend_says_already_blocked(self):
        r = recommend("203.0.113.10", "/", 403, "Mozilla/5.0", "의심 헤더")
        self.assertIn("이미 거절", r["headline"])
        self.assertEqual(r["severity"], "위험")              # 공격 의도는 그대로 위험으로 표시
        r2 = recommend("203.0.113.10", "/", 499, "Mozilla/5.0", "의심 헤더")
        self.assertNotIn("이미 거절", r2["headline"])

    def test_timeline_entry_carries_flag(self):
        from logsentry import _timeline_entry
        self.assertTrue(_timeline_entry("t", "", "1.2.3.4", "/", "POST", 403, "x", "의심 헤더")["edge_blocked"])
        self.assertFalse(_timeline_entry("t", "", "1.2.3.4", "/", "POST", 499, "x", "의심 헤더")["edge_blocked"])


class TestIpIntel(unittest.TestCase):
    """[v3.12] 공격 IP 출처(나라·기관·종류) — 네트워크 없이 등록기관 응답 모양으로 시험."""

    APNIC = {"country": "IN", "name": "EXAMPLE-IN", "startAddress": "27.100.38.0",
             "endAddress": "27.100.38.255",
             "remarks": [{"description": ["Example Web Hosting Pvt Ltd"]}],
             "entities": [{"roles": ["registrant"],
                           "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                    ["fn", {}, "text", "Example Web Hosting Pvt Ltd"]]]}]}
    ARIN = {"name": "MSFT", "handle": "NET-20-33-0-0-1",
            "cidr0_cidrs": [{"v4prefix": "20.33.0.0", "length": 16}],
            "entities": [{"roles": ["registrant"],
                          "vcardArray": ["vcard", [["fn", {}, "text", "Microsoft Corporation"],
                                                   ["adr", {"label": "One Microsoft Way\nRedmond\nWA\n98052\nUnited States"},
                                                    "text", ["", "", "", "", "", "", ""]]]]}]}

    def setUp(self):
        import logsentry
        self.ls = logsentry
        self._trusted = logsentry._TRUSTED_IPS

    def tearDown(self):
        self.ls._TRUSTED_IPS = self._trusted

    def test_parse_apnic_shape(self):
        r = self.ls.parse_rdap(self.APNIC)
        self.assertEqual(r["country"], "IN")
        self.assertEqual(r["org"], "Example Web Hosting Pvt Ltd")
        self.assertEqual(r["net"], "EXAMPLE-IN")
        self.assertIn("27.100.38.0", r["cidr"])

    def test_parse_arin_shape_country_from_label(self):
        r = self.ls.parse_rdap(self.ARIN)
        self.assertEqual(r["country"], "US")             # ARIN 은 주소 마지막 줄의 영어 나라 이름
        self.assertEqual(r["cidr"], "20.33.0.0/16")
        self.assertEqual(r["org"], "Microsoft Corporation")

    def test_parse_real_ripe_shape_picks_org_not_person(self):
        obj = {"name": "INFRAWATCH", "country": "GB",
               "remarks": [{"description": ["-----------", "Real time internet intelligence data", "infrawat.ch"]}],
               "entities": [
                   {"roles": ["registrant"], "handle": "HYDRA-MNT",
                    "vcardArray": ["vcard", [["fn", {}, "text", "HYDRA-MNT"], ["kind", {}, "text", "individual"]]]},
                   {"roles": ["administrative", "technical"], "handle": "LD1-RIPE",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Person Name"], ["kind", {}, "text", "individual"]]]},
                   {"roles": ["registrant"], "handle": "ORG-IL1-RIPE",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Infrawatch Limited"], ["kind", {}, "text", "org"]]]},
                   {"roles": ["abuse"], "handle": "ACRO1-RIPE",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Abuse contact role object"], ["kind", {}, "text", "group"]]]}]}
        r = self.ls.parse_rdap(obj)
        self.assertEqual(r["org"], "Infrawatch Limited")            # 회사(org) 우선
        self.assertEqual(r["descr"], "Real time internet intelligence data · infrawat.ch")   # 줄표 줄 버림
        self.assertNotIn("Person Name", r["org"])                   # 개인 이름은 기관으로 안 씀
        info = self.ls.lookup_ip("81.19.219.231", fetch=lambda u: obj, resolver=lambda ip: "")
        self.assertNotIn("Person Name", json.dumps(info, ensure_ascii=False))   # 저장·화면에도 없음
        self.assertNotIn("HYDRA-MNT", r["org"])                     # 관리자 코드도 아님
        self.assertEqual(self.ls.classify_ip(r["org"], r["net"], r["descr"] + " " + r["extra"]), "scanner")

    def test_parse_real_apnic_shape_skips_abuse_contact(self):
        obj = {"name": "YouStable", "country": "IN",
               "remarks": [{"description": ["YouStable"], "title": "description"}],
               "entities": [
                   {"roles": ["abuse"], "handle": "IRT-HSL-AP",
                    "vcardArray": ["vcard", [["fn", {}, "text", "IRT-HSL-AP"], ["kind", {}, "text", "group"]]]},
                   {"roles": ["technical", "administrative"], "handle": "QTPL2-AP",
                    "vcardArray": ["vcard", [["fn", {}, "text", "Qloudin Technologies Pvt Ltd administrator"],
                                             ["kind", {}, "text", "group"]]]}]}
        r = self.ls.parse_rdap(obj)
        self.assertEqual(r["org"], "YouStable")                     # 신고 창구(IRT) 이름이 아님
        self.assertEqual(self.ls.classify_ip(r["org"], r["net"], r["descr"] + " " + r["extra"]), "cloud")

    def test_afrinic_individual_role_used_only_for_kind(self):
        obj = {"country": "CA", "entities": [
            {"roles": ["administrative", "technical"], "handle": "CIS1-AFRINIC",
             "vcardArray": ["vcard", [["fn", {}, "text", "Cloud Innovation Support"], ["kind", {}, "text", "individual"]]]}]}
        info = self.ls.lookup_ip("45.194.92.57", fetch=lambda u: obj, resolver=lambda ip: "")
        self.assertEqual(info["org"], "")                          # 표시·저장 안 함
        self.assertEqual(info["kind"], "cloud")                    # 분류에는 참고

    def test_parse_garbage_is_safe(self):
        self.assertEqual(self.ls.parse_rdap("not json")["country"], "")
        self.assertEqual(self.ls.parse_rdap({"entities": [{"vcardArray": "broken"}]})["org"], "")

    def test_classify(self):
        c = self.ls.classify_ip
        self.assertEqual(c(rdns="scanner-12.ch1.censys-scanner.com"), "scanner")
        self.assertEqual(c(org="Example Web Hosting Pvt Ltd"), "cloud")
        self.assertEqual(c(org="Microsoft Corporation", net="MSFT"), "cloud")
        self.assertEqual(c(org="KT Corporation"), "isp")
        self.assertEqual(c(rdns="211-36-1-2.dynamic.example.net"), "isp")
        self.assertEqual(c(org="Some Trading Company"), "unknown")
        # 검색엔진이 클라우드보다 먼저(Censys 는 클라우드 대역에서도 돎)
        self.assertEqual(c(org="Google LLC", rdns="x.censys-scanner.com"), "scanner")

    def test_never_lookup_private_or_trusted(self):
        f = self.ls._ip_lookupable
        self.assertFalse(f("192.168.10.1"))
        self.assertFalse(f("127.0.0.1"))
        self.assertFalse(f("::1"))
        self.assertFalse(f("not-an-ip"))
        self.assertFalse(f("203.0.113.5"))              # 문서용 예약 대역도 공인이 아님
        self.assertTrue(f("27.100.38.10"))
        self.ls._TRUSTED_IPS = ("27.100.38.0/24",)
        self.assertFalse(f("27.100.38.10"))              # 신뢰 대역은 밖에 묻지 않음

    def test_lookup_private_makes_no_request(self):
        calls = []
        info = self.ls.lookup_ip("192.168.10.1", fetch=lambda u: calls.append(u), resolver=lambda ip: "x")
        self.assertFalse(info["ok"])
        self.assertEqual(calls, [])

    def test_lookup_uses_bootstrap_and_normalized_url(self):
        calls = []
        boot = {"services": [[["27.0.0.0/8"], ["http://ignored/", "https://rdap.apnic.net/"]]]}

        def fetch(url):
            calls.append(url)
            return self.APNIC
        info = self.ls.lookup_ip("27.100.38.10", boot, fetch=fetch, resolver=lambda ip: "")
        self.assertEqual(calls, ["https://rdap.apnic.net/ip/27.100.38.10"])   # https 주소만 사용
        self.assertTrue(info["ok"])
        self.assertEqual((info["country"], info["country_ko"], info["kind"]), ("IN", "인도", "cloud"))

    def test_lookup_fetch_failure_falls_back_to_rdns(self):
        def boom(url):
            raise OSError("timeout")
        info = self.ls.lookup_ip("27.100.38.10", fetch=boom, resolver=lambda ip: "scan.shodan.io")
        self.assertTrue(info["ok"])                      # rDNS 만으로도 종류는 앎
        self.assertEqual(info["kind"], "scanner")
        info2 = self.ls.lookup_ip("27.100.38.10", fetch=boom, resolver=lambda ip: "")
        self.assertFalse(info2["ok"])
        self.assertIn("timeout", info2["error"])

    def test_rdap_base_fallback(self):
        self.assertEqual(self.ls.rdap_base("8.8.8.8", {"services": []}), self.ls._RDAP_FALLBACK)
        self.assertEqual(self.ls.rdap_base("8.8.8.8", None), self.ls._RDAP_FALLBACK)

    def test_pick_targets_respects_cache_and_privacy(self):
        import time as _t
        now = _t.time()
        fresh = datetime.fromtimestamp(now - 60).isoformat(timespec="seconds")
        old_fail = datetime.fromtimestamp(now - 7200).isoformat(timespec="seconds")
        payload = {"timeline": [{"ip": "192.168.10.1"}, {"ip": "27.100.38.10"}, {"ip": "8.8.8.8"},
                                {"ip": "1.1.1.1"}],
                   "alerts": [{"ip": "9.9.9.9"}], "top_ips": [{"ip": "8.8.8.8"}]}
        cache = {"27.100.38.10": {"ok": True, "looked_at": fresh},     # 최근 성공 → 다시 안 물음
                 "1.1.1.1": {"ok": False, "looked_at": old_fail}}      # 2시간 전 실패 → 다시 물음
        got = self.ls.pick_lookup_targets(payload, cache, now, limit=5)
        self.assertEqual(got, ["8.8.8.8", "1.1.1.1", "9.9.9.9"])     # 사설 제외·중복 제거·화면 순서
        self.assertEqual(len(self.ls.pick_lookup_targets(payload, {}, now, limit=2)), 2)

    def test_db_roundtrip_and_view(self):
        fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
        try:
            conn = open_db(p)
            info = self.ls.lookup_ip("27.100.38.10", fetch=lambda u: self.APNIC, resolver=lambda ip: "")
            self.ls.save_ipinfo(conn, info)
            loaded = self.ls.load_ipinfo(conn)
            conn.close()
            self.assertEqual(loaded["27.100.38.10"]["org"], "Example Web Hosting Pvt Ltd")
            v = self.ls.ipinfo_view(loaded["27.100.38.10"])
            self.assertEqual((v["kind_label"], v["kind_short"]), ("클라우드·호스팅", "호스팅"))
            self.assertNotIn("error", v)                 # 내부 오류 문구는 화면에 안 보냄
        finally:
            os.remove(p)

    def test_config_switch(self):
        fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
        before = self.ls._IP_LOOKUP
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"ip_lookup": True}, f)
            load_config(p)
            self.assertTrue(self.ls._IP_LOOKUP)
        finally:
            self.ls._IP_LOOKUP = before
            os.remove(p)


class TestIncidents(unittest.TestCase):
    """[v3.13] '뚫렸나?' — 막힌 시도가 아니라 실제 사고일 수 있는 것만 골라낸다."""

    PUB = "27.100.38.10"      # 공인 IP(조회·판정 대상). 문서용 예약 대역은 공인이 아니라서 쓰지 않음

    def setUp(self):
        import logsentry
        self.ls = logsentry
        self._auth, self._secret = logsentry._AUTH_PATHS, logsentry._SECRET_PATHS
        logsentry._AUTH_PATHS = ("/api/auth/login",)

    def tearDown(self):
        self.ls._AUTH_PATHS, self.ls._SECRET_PATHS = self._auth, self._secret

    def ev(self, lines):
        return [e for e in (parse_line(l) for l in lines) if e]

    def test_secret_path_list(self):
        f = self.ls.is_secret_path
        for p in ("/.env", "/admin/.env", "/.env.bak", "/.git/config", "/app/.git", "/actuator/heapdump",
                  "/phpinfo.php?x=1", "/backup.sql"):
            self.assertTrue(f(p), p)
        for p in ("/actuator/health", "/admin", "/api/config", "/.github/x", "/ko/login", "/"):
            self.assertFalse(f(p), p)          # 정상 200 이 나올 수 있는 주소는 사고로 안 봄

    def test_exposure_only_when_success(self):
        ev = self.ev([nginx(self.PUB, "10:00:00", "GET", "/.env", 404, "curl/8"),
                      nginx(self.PUB, "10:00:01", "GET", "/.git/config", 200, "curl/8"),
                      nginx(self.PUB, "10:00:02", "GET", "/actuator/health", 200, "curl/8"),
                      nginx("192.168.10.5", "10:00:03", "GET", "/.env", 200, "Mozilla/5.0")])
        incs = self.ls.detect_incidents(ev)
        self.assertEqual([(i["type"], i["path"]) for i in incs],
                         [("exposure", "/.git/config"), ("exposure", "/.env")])   # 사내에서 열려도 노출은 노출

    def test_attack_header_success_vs_blocked(self):
        def line(st):
            o = json.loads(caddy(self.PUB, 1764000000.0, "POST", "/", st, "Mozilla/5.0"))
            o["request"]["headers"]["Next-Action"] = ["x"]
            return json.dumps(o)
        self.assertEqual(self.ls.detect_incidents(self.ev([line(403)])), [])      # 앞단에서 막힘 = 사고 아님
        incs = self.ls.detect_incidents(self.ev([line(200)]))
        self.assertEqual(incs[0]["type"], "attack_ok")

    def test_login_success_plain_is_quiet(self):
        ev = self.ev([nginx("211.36.1.2", "09:00:00", "POST", "/api/auth/login", 200, "Mozilla/5.0")])
        self.assertEqual(self.ls.detect_incidents(ev), [])                         # 평범한 국내 로그인

    def test_login_after_many_failures(self):
        lines = [nginx(self.PUB, f"09:00:0{k}", "POST", "/api/auth/login", 401, "Mozilla/5.0") for k in range(6)]
        lines.append(nginx(self.PUB, "09:00:09", "POST", "/api/auth/login", 200, "Mozilla/5.0"))
        incs = self.ls.detect_incidents(self.ev(lines), fail_threshold=5)
        self.assertEqual(incs[0]["type"], "login")
        self.assertIn("실패 6회", incs[0]["reasons"][0])

    def test_session_expiry_401s_are_not_attack_signal(self):
        # 세션 만료된 직원: API 401 을 여러 번 받은 뒤 다시 로그인 → 사고 아님
        lines = [nginx("211.36.1.2", f"09:00:0{k}", "GET", "/api/orders", 401, "Mozilla/5.0") for k in range(8)]
        lines.append(nginx("211.36.1.2", "09:00:09", "POST", "/api/auth/login", 200, "Mozilla/5.0"))
        self.assertEqual(self.ls.detect_incidents(self.ev(lines)), [])

    def test_login_from_ip_that_probed(self):
        lines = [nginx(self.PUB, "09:00:00", "GET", "/.env", 404, "Mozilla/5.0"),
                 nginx(self.PUB, "09:00:05", "POST", "/api/auth/login", 200, "Mozilla/5.0")]
        incs = self.ls.detect_incidents(self.ev(lines))
        self.assertTrue(any("탐침" in r for r in incs[0]["reasons"]))

    def test_login_hosting_or_foreign_needs_ipinfo(self):
        ev = self.ev([nginx(self.PUB, "09:00:00", "POST", "/api/auth/login", 200, "Mozilla/5.0")])
        self.assertEqual(self.ls.detect_incidents(ev, {}), [])                     # 출처 모르면 아직 판단 안 함
        incs = self.ls.detect_incidents(ev, {self.PUB: {"kind": "cloud", "country": "IN"}})
        rs = " ".join(incs[0]["reasons"])
        self.assertIn("호스팅", rs)
        self.assertIn("해외(인도)", rs)
        self.assertEqual(self.ls.detect_incidents(ev, {self.PUB: {"kind": "isp", "country": "KR"}}), [])

    def test_internal_login_never_flagged(self):
        lines = [nginx("192.168.10.1", f"09:00:0{k}", "POST", "/api/auth/login", 401, "Mozilla/5.0") for k in range(7)]
        lines.append(nginx("192.168.10.1", "09:00:09", "POST", "/api/auth/login", 200, "Mozilla/5.0"))
        self.assertEqual(self.ls.detect_incidents(self.ev(lines)), [])

    def test_get_on_login_path_is_not_login(self):
        ev = self.ev([nginx(self.PUB, "09:00:00", "GET", "/api/auth/login", 200, "Mozilla/5.0")])
        self.assertEqual(self.ls.detect_incidents(ev, {self.PUB: {"kind": "cloud"}}), [])

    def test_store_ack_reopen(self):
        fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
        try:
            ev = self.ev([nginx(self.PUB, "10:00:01", "GET", "/.git/config", 200, "curl/8")])
            incs = self.ls.detect_incidents(ev)
            conn = open_db(p)
            self.assertEqual(len(self.ls.store_incidents(conn, incs)), 1)
            self.assertEqual(self.ls.store_incidents(conn, incs), [])               # 같은 사고는 다시 '새것' 아님
            self.assertEqual(len(self.ls.load_incidents(conn)), 1)
            conn.close()
            self.assertTrue(self.ls.ack_incident(p, incs[0]["key"], True)["ok"])
            conn = open_db(p)
            self.assertEqual(self.ls.load_incidents(conn), [])                       # 확인함 → 열린 목록에서 빠짐
            self.assertEqual(len(self.ls.load_incidents(conn, open_only=False)), 1)  # 지우진 않음
            conn.close()
            self.ls.ack_incident(p, incs[0]["key"], False)
            conn = open_db(p)
            self.assertEqual(len(self.ls.load_incidents(conn)), 1)                  # 다시 열기
            conn.close()
            self.assertFalse(self.ls.ack_incident(p, "없는키", True)["ok"])
        finally:
            os.remove(p)

    def test_today_summary(self):
        fd, p = tempfile.mkstemp(suffix=".db"); os.close(fd)
        try:
            conn = open_db(p)
            day = "2026-11-10"
            for k, st in enumerate((404, 401, 403, 307, 499)):
                conn.execute("INSERT INTO intrusion(ts, ip, path, status, kind) VALUES(?,?,?,?,?)",
                             (f"{day}T09:00:0{k}+09:00", self.PUB, f"/x{k}", st, "없는 주소"))
            conn.execute("INSERT INTO intrusion(ts, ip, path, status, kind) VALUES(?,?,?,?,?)",
                         ("2026-11-09T23:59:59+09:00", self.PUB, "/y", 404, "없는 주소"))   # 어제
            conn.commit()
            self.assertEqual(self.ls.today_summary(conn=conn, today=day),
                             {"date": day, "attempts": 5, "blocked": 3})   # 307·499 는 '막힘' 아님
            conn.close()
        finally:
            os.remove(p)

    def test_login_ips_get_lookup_priority(self):
        ev = self.ev([nginx(self.PUB, "09:00:00", "POST", "/api/auth/login", 200, "Mozilla/5.0")])
        payload = {"logins": self.ls.recent_logins(ev), "timeline": [{"ip": "8.8.8.8"}]}
        self.assertEqual(self.ls.payload_ips(payload)[0], self.PUB)

    def test_secret_paths_config(self):
        fd, p = tempfile.mkstemp(suffix=".json"); os.close(fd)
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"secret_paths_extra": ["/internal-dump"]}, f)
            load_config(p)
            self.assertTrue(self.ls.is_secret_path("/internal-dump/a"))
            self.assertTrue(self.ls.is_secret_path("/.env"))                         # 기본 목록은 유지
        finally:
            os.remove(p)


if __name__ == "__main__":
    unittest.main(verbosity=2)
