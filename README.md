# LogSentry

표준 웹서버 접근 로그를 읽어 **침입 시도를 탐지·기록**하는 범용 도구.
대상 앱의 코드를 고치지 않고, **어느 프로젝트든 로그만 있으면** 붙는다. 의존성 0(파이썬 표준 라이브러리만).

> A lightweight, dependency-free intrusion detector that reads standard web access logs
> (nginx/apache/JSON) and flags scanning, brute-force, and slow/distributed attacks — no app changes.

---

## 왜 만들었나

AI 기반 자동 공격은 로그인 화면만이 아니라 **API·없는 주소를 빠르게·넓게·느리게** 쑤신다.
대부분의 서버는 이미 모든 요청을 접근 로그에 남긴다. LogSentry 는 **그 로그만 읽어**, 코드 수정 없이
공격 징후를 찾아 경보하고 기록한다.

INFOLINK MES 보안 과제에서 만든 침입 탐지 규칙(계정 잠금·경로 탐색·IP 상관분석 등)을,
특정 DB·프레임워크에 묶이지 않도록 **로그 기반·프로젝트 독립**으로 이식한 결과물이다.

## 핵심 특징

- **코드 무수정** — 대상 앱을 전혀 건드리지 않는다. 로그 파일만 가리키면 된다.
- **범용** — nginx/apache combined, JSON 접근 로그 지원. 양식은 파서(어댑터)만 추가하면 는다.
- **의존성 0** — 파이썬 표준 라이브러리만. 어디서나 실행.
- **자동 감시** — `--watch` 로 주기 재검사, 새 경보만 알림.
- **기록** — `--alert-log` 로 경보를 ASCII 구조(key=value)로 남겨 어떤 인코딩·도구에서도 안 깨지고 파싱 가능.
- **오탐 관리** — 정상 트래픽/소음(favicon 등) 제외, 확실한 것만 경보·애매한 것은 관찰.

## 설치 / 실행

파이썬 3.11+ 만 있으면 된다. 설치 불필요.

```bash
# 한 번 검사
python logsentry.py access.log

# 자동 감시(60초마다, 새 경보만) + 파일 기록
python logsentry.py /var/log/nginx/access.log --watch 60 --alert-log alerts.txt
```

## 탐지 규칙

| 규칙 | 내용 |
|---|---|
| P1 경로 탐색 | 한 IP 가 없는 주소(404)를 여러 번 |
| P2 인증 두드림 | 한 IP 가 401/403 을 여러 번 |
| P3 과속 | 한 IP 가 짧은 시간(창) 안에 많은 요청 |
| P4 도구 지문 | User-Agent 가 curl/python/sqlmap/nmap 등 |
| P5 IP 종합 | 위 신호를 IP 로 합산·점수화 → 분산·저속 공격까지 |

> 계정 단위(비밀번호 스프레이·계정 잠금)는 접근 로그에 계정 정보가 없어, 앱 연동 단계(v2)에서 추가.

## 예시 결과

```
$ python logsentry.py sample_access.log
LogSentry — 로그 26줄 분석

🔴 경보
  IP 45.146.0.99 — 점수 32 · 서로 다른 경로 10개 (11-10 09:01~09:01)
       없는 주소 10회 · 탐침경로 10개 · 도구 UA
  IP 185.220.101.5 — 점수 14 · 서로 다른 경로 2개
       인증거부 6회 · 도구 UA
  IP 141.98.80.1 — 점수 11 · 서로 다른 경로 3개 (09:05~09:48)   ← 43분에 걸친 느린 탐색
       탐침경로 3개 · 도구 UA
```

자동 감시(`--watch`) 중 새 공격자가 로그에 등장하면 다음 바퀴에서 포착한다.
파일 기록은 기계가 읽기 쉬운 형태로 남는다:

```
[2026-11-10 09:50:16] ALERT ip=45.146.0.99 score=23 distinct_paths=7 notfound=7 authfail=0 probe_paths=7 tool_ua=1 rate=7 ...
```

## 설계

```
 로그 한 줄 ─▶ [ 파서(어댑터) ] ─▶ 공통 이벤트 ─▶ [ 탐지 엔진 ] ─▶ [ 보여주기 ]
                nginx / json          {ip·경로·상태·지문}   P1~P5 점수화     화면(한글) / 파일(ASCII)
```

- **파서(입구)만 양식을 탄다.** JSON·apache 등은 파서 하나 추가 → 탐지 엔진은 그대로 재사용(어댑터 패턴).
- **자료와 보여주기를 분리.** 탐지 엔진은 사실(dict)만 만들고, 화면용·파일용 포맷은 바깥에서.

## 옵션

```
--watch N           N초마다 자동 재검사(새 경보만)
--alert-log FILE    경보를 파일에 이어 기록(ASCII)
--window N          과속·창 크기(기본 60초)
--probe-threshold   경로 탐색 경보 문턱(기본 5)
--auth-threshold    인증 두드림 경보 문턱(기본 5)
--rate-threshold    과속 문턱(기본 20req/창)
--score-threshold   종합 점수 경보 문턱(기본 6)
```

## 로드맵

- **v0** 접근 로그 → P1~P5 탐지 ✅
- **v1** JSON 지원 · 파일 기록 · 자동 감시 ✅ / apache·설정 파일 (진행)
- **v2** 드롭인 미들웨어 어댑터 → 계정 단위 신호·AI 엔드포인트
- **v3**(선택) 자동 차단(fail2ban 연동) · 대시보드

## 원칙

읽기 전용 · 대상 코드 미수정 · 정상 소음 제외(오탐 관리) · 기록은 변조·인코딩에 강하게.
