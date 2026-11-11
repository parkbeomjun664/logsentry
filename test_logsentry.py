"""LogSentry 탐지 검증 테스트 — 표준 라이브러리 unittest 만 사용(의존성 0).

"이런 공격 로그를 넣으면 이 IP 가 경보로 떠야 한다"를 코드로 고정해 둔다.
규칙을 고치다 탐지가 깨지면 이 테스트가 실패로 알려 준다.

실행:  python -m unittest -v
"""
import json
import unittest

from logsentry import analyze, parse_line

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
