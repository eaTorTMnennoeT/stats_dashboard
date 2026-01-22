# CDN Abuser Detection AI - 고도화된 악성 유저 탐지 시스템 v2.0

## 개요

이 문서는 CDN 로그 데이터를 기반으로 악성 유저(어뷰저)를 탐지하는 AI 알고리즘을 설명합니다.
298M+ 개의 nginx 로그를 분석하여 정상 유저와 악성 유저의 패턴을 파악하고,
다중 패턴 기반 점수 시스템을 구현했습니다.

---

## 1. 로그 데이터 분석 결과

### 1.1 데이터 규모
- 총 로그: ~298,335,901개
- 등록 서버: 9대 (CDN 분산)
- 분석 기간: 실시간 (1h ~ 24h 선택)

### 1.2 정상 유저 패턴

| 지표 | 일반 유저 | 설명 |
|------|----------|------|
| 트래픽 | < 2GB/day | 영상 1-3개 시청 |
| 요청 빈도 | < 0.5/sec | 자연스러운 스트리밍 |
| 100초 버스트 | < 50 req | HLS 세그먼트 로딩 |
| 경로 다양성 | > 5% | 여러 영상 시청 |
| User-Agent | 1-2개 | 단일 기기 사용 |
| 서버 분산 | 1-3대 | CDN 자동 분배 |

```
일반 유저 접근 패턴:
  ┌──────────────────────────────────────────────────┐
  │ 시간    │ 요청수 │ 설명                          │
  ├──────────────────────────────────────────────────┤
  │ 0-10s   │  3-5   │ manifest + 초기 세그먼트      │
  │ 10-60s  │  5-10  │ 버퍼링 (세그먼트 선로딩)      │
  │ 1-60m   │  6/min │ 재생 속도에 맞춘 요청         │
  └──────────────────────────────────────────────────┘
```

### 1.3 악성 유저 패턴 (실제 차단된 IP 분석)

#### 차단 IP 사례 분석

**IP: 182.228.254.98** (차단됨: 10.7GB)
```
- 요청 패턴: /v/p/, /v/w/ 세그먼트 집중
- User-Agent: Mac Safari (위장)
- 특징: 동일 영상 반복 다운로드
```

**IP: 123.108.163.151** (차단됨: 19.9GB)
```
- 요청 패턴: /v/f/ 경로 index50 반복
- User-Agent: Windows Chrome (위장)
- 특징: 단일 경로 80%+ 집중
```

**IP: 111.91.172.208** (차단됨: 11.2GB)
```
- 요청 패턴: seg-XXX 순차 다운로드
- User-Agent: Android Chrome
- 특징: 모든 세그먼트 고속 다운로드
```

### 공통 악성 패턴
```
- 트래픽: 10GB~20GB+ (정상의 5~10배)
- 동일 영상 반복 다운로드 (80%+ 동일 경로)
- 전체 CDN 서버 동시 접근 (9/9대)
- 100초당 200+ 요청 버스트
- 다운로드 도구 사용 의심 (다중 User-Agent)
```

---

## 2. 탐지 알고리즘 (8개 패턴 분석)

### 패턴 1: 트래픽 양 (최대 60점)

대용량 다운로드는 불법 다운로더의 핵심 특징

```rust
if gb > 30.0 {
    score += 60;  // 극대용량 (EXTREME_TRAFFIC)
} else if gb > 15.0 {
    score += 45;  // 대용량 (HIGH_TRAFFIC)
} else if gb > 8.0 {
    score += 30;  // 높은 트래픽
} else if gb > 3.0 {
    score += 15;  // 중간 트래픽
}
```

### 패턴 2: 100초 버스트 (최대 80점)

단시간 집중 요청 - 다운로드 가속기 특징

```rust
if max_req_100s > 500 {
    score += 80;  // 극심한 버스트 (EXTREME_BURST)
} else if max_req_100s > 200 {
    score += 50;  // 높은 버스트 (HIGH_BURST)
} else if max_req_100s > 100 {
    score += 30;  // 버스트
}
```

시각화:
```
일반 유저:    ▂▂▃▂▂▂▃▂▂▂ (평균 30 req/100s)
다운로더:    ▂▂▂████▂▂▂ (피크 500+ req/100s)
```

### 패턴 3: 단일 비디오 어뷰즈 (최대 100점) ⭐ 핵심

동일 경로 반복 접근 - 다운로드 도구의 전형적 패턴

```rust
let single_ratio = single_path_requests / total_requests;
let single_gb = single_path_bytes / GB;

if single_ratio > 0.8 && single_gb > 5.0 {
    score += 100;  // SINGLE_VIDEO_ABUSE
} else if single_ratio > 0.6 && single_gb > 2.0 {
    score += 60;   // REPEATED_DOWNLOAD
} else if single_path_requests > 200 {
    score += 30;   // 동일경로 반복
}
```

예시:
```
악성 유저 (단일 비디오 어뷰즈):
  경로 /v/f/abc123/index50 → 12,500 요청 (85%)
  경로 /v/f/abc123/index51 → 1,200 요청 (8%)
  기타                      → 800 요청 (7%)
```

### 패턴 4: 멀티서버 공격 (최대 50점)

CDN 전체 서버에 동시 접근 - 로드밸런서 우회 시도

```rust
if server_count >= total_servers && gb > 5.0 {
    score += 50;  // ALL_SERVERS_ATTACK
} else if server_count > total_servers / 2 && gb > 3.0 {
    score += 25;  // 다수서버 접근
}
```

```
일반 유저: 서버 1, 3 접근 (CDN 자동 분배)
악성 유저: 서버 1, 2, 3, 4, 5, 6, 7, 8, 9 모두 접근
```

### 패턴 5: User-Agent 다중 사용 (최대 35점)

봇/도구 사용 의심 - UA 로테이션

```rust
if unique_agents > 5 && requests > 100 {
    score += 35;  // MULTI_UA
} else if unique_agents > 3 {
    score += 15;  // UA 변경
}
```

### 패턴 6: 요청당 바이트 (최대 25점)

대형 세그먼트 집중 요청

```rust
let mb_per_req = bytes_per_request / MB;
if mb_per_req > 10.0 {
    score += 25;  // 대형 세그먼트 요청
}
```

### 패턴 7: 시간당 트래픽 (최대 50점)

다운로드 속도 분석

```rust
let gb_per_hour = total_gb / activity_hours;

if gb_per_hour > 20.0 {
    score += 50;  // EXTREME_SPEED
} else if gb_per_hour > 10.0 {
    score += 30;  // 고속
} else if gb_per_hour > 5.0 {
    score += 15;  // 빠른 다운
}
```

### 패턴 8: 경로 다양성 (최대 30점)

정상 유저는 다양한 영상 시청

```rust
let path_ratio = unique_paths / total_requests;
if path_ratio < 0.01 && requests > 500 {
    score += 30;  // 낮은 경로다양성
}
```

---

## 3. 확정 악성 유저 판별 (300점)

다음 조건 충족 시 **100% 악성 유저**로 판별하고 300점 부여:

### 조건 A: 단일 비디오 + 대규모 공격
```
SINGLE_VIDEO_ABUSE + (ALL_SERVERS_ATTACK OR > 10GB)
```

로직 설명:
- 하나의 영상을 80% 이상 반복 다운로드하면서
- 전체 서버를 공격하거나 10GB 이상 다운로드
- → 100% 불법 다운로더

### 조건 B: 극심한 버스트 + 극대용량
```
EXTREME_BURST + EXTREME_TRAFFIC
```

로직 설명:
- 500+ req/100s 극심한 버스트 발생
- 30GB+ 극대용량 트래픽
- → 100% 다운로드 도구 사용

---

## 4. 위험도 레벨

| 점수 | 레벨 | 설명 | 권장 조치 |
|-----|------|-----|---------|
| 300+ | `confirmed` | 확정 악성 | 즉시 차단 |
| 150+ | `critical` | 위험 | 차단 권장 |
| 100+ | `high` | 높음 | 모니터링 강화 |
| 50+ | `medium` | 중간 | 주시 필요 |
| <50 | `low` | 낮음 | 정상 가능성 |

---

## 5. 플래그 시스템

각 패턴 탐지 시 플래그 부여:

| 플래그 | 의미 | 심각도 |
|-------|-----|-------|
| `CONFIRMED_ABUSER` | 확정 악성 | ⚫ 최고 |
| `SINGLE_VIDEO_ABUSE` | 단일 영상 어뷰즈 | 🔴 높음 |
| `EXTREME_BURST` | 극심한 버스트 | 🔴 높음 |
| `ALL_SERVERS_ATTACK` | 전체 서버 공격 | 🔴 높음 |
| `EXTREME_TRAFFIC` | 극대용량 트래픽 | 🔴 높음 |
| `EXTREME_SPEED` | 극고속 다운로드 | 🔴 높음 |
| `HIGH_TRAFFIC` | 대용량 트래픽 | 🟠 중간 |
| `HIGH_BURST` | 높은 버스트 | 🟠 중간 |
| `REPEATED_DOWNLOAD` | 반복 다운로드 | 🟠 중간 |
| `MULTI_UA` | 다중 User-Agent | 🟠 중간 |

---

## 6. API 사용법

### 엔드포인트
```
GET /api/servers/logs/abusers?period=6h&limit=30
```

### 파라미터
- `period`: 분석 기간 (1h, 3h, 6h, 12h, 24h)
- `limit`: 결과 수 (기본 30)

### 응답 예시
```json
{
  "abusers": [
    {
      "ip": "123.108.163.151",
      "requests": 15420,
      "totalBytes": 21474836480,
      "gb": "20.0",
      "gb_per_hour": "15.2",
      "avg_req_per_sec": "0.71",
      "max_req_100s": 342,
      "unique_paths": 45,
      "unique_agents": 1,
      "first_seen": "2026-01-22 10:00:00",
      "last_seen": "2026-01-22 11:19:00",
      "score": 300,
      "risk_level": "confirmed",
      "reasons": [
        "🔴 극대용량: 20.0GB",
        "🔴 극심한 버스트: 342req/100s",
        "🔴 단일비디오 어뷰즈: 85% (17.5GB)",
        "🔴 전체서버 공격: 9/9대"
      ],
      "flags": [
        "EXTREME_TRAFFIC",
        "HIGH_BURST",
        "SINGLE_VIDEO_ABUSE",
        "ALL_SERVERS_ATTACK",
        "CONFIRMED_ABUSER"
      ],
      "servers": ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
      "alreadyBlocked": false
    }
  ]
}
```

---

## 7. 쿼리 최적화

### 사용된 QuestDB 쿼리

**1. 기본 통계**
```sql
SELECT client_ip, count() as requests, sum(bytes_sent) as total_bytes,
       min(timestamp) as first_seen, max(timestamp) as last_seen,
       count_distinct(path) as unique_paths,
       count_distinct(user_agent) as unique_agents
FROM nginx_logs
WHERE timestamp > dateadd('h', -6, now()) AND status = 200
GROUP BY client_ip
ORDER BY total_bytes DESC
LIMIT 150
```

**2. 100초 버스트 분석**
```sql
SELECT client_ip, max(cnt) as max_req
FROM (
    SELECT client_ip, count() as cnt
    FROM nginx_logs
    WHERE timestamp > dateadd('h', -6, now()) AND status = 200
    SAMPLE BY 100s ALIGN TO CALENDAR
)
GROUP BY client_ip
```

**3. 단일 경로 집중도**
```sql
SELECT client_ip, path, count() as cnt, sum(bytes_sent) as bytes
FROM nginx_logs
WHERE timestamp > dateadd('h', -6, now()) AND status = 200
GROUP BY client_ip, path
HAVING cnt > 50
ORDER BY cnt DESC
```

모든 쿼리에 30초 타임아웃 적용.

---

## 8. 성능 최적화

### 병렬 쿼리 실행
- 4개 쿼리를 동시에 실행
- 각 쿼리 30초 타임아웃
- 결과를 HashMap으로 병합

### 메모리 효율
- limit * 5 배수로 여유있게 조회
- 점수 계산 후 상위 limit개만 반환
- 점수순 정렬 후 반환

---

## 9. 향후 개선 방향

### 9.1 머신러닝 도입 가능성
- 시계열 이상 탐지 (Isolation Forest)
- 클러스터링 기반 그룹 탐지
- 실시간 스트리밍 분석

### 9.2 추가 패턴 후보
- ASN/호스팅 프로바이더 분석 (VPS 탐지)
- 지리적 이동 패턴 (VPN 탐지)
- 세그먼트 다운로드 순서 분석
- 시간대별 접근 패턴 (새벽 시간대)
- TLS fingerprint 분석

### 9.3 자동화
- score 300 이상 자동 차단 연동
- 임계값 자동 조정 (통계 기반)
- 실시간 Slack/Discord 알림

---

## 10. 변경 이력

| 날짜 | 버전 | 변경 내용 |
|-----|-----|---------|
| 2026-01-22 | v2.1 | Referer 패턴 제거 (정상 유저도 Referer 없을 수 있음), 8개 패턴으로 조정 |
| 2026-01-22 | v2.0 | 9개 패턴 기반 고도화, 확정 악성 유저 300점 시스템, 플래그 시스템 |
| 2026-01-21 | v1.0 | 기본 트래픽/요청빈도 기반 탐지 |

---

*Generated by Claude AI - CDN Abuser Detection System v2.1*
*분석 기반: 298M+ nginx 로그, 실제 차단 IP 패턴 분석*
