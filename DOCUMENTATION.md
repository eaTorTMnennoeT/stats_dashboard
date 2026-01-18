# P2P Stats System - 기술 문서

P2P 스트리밍 서비스의 실시간 통계 수집 및 시각화 시스템

---

## 1. 기술 스택

### Backend

| 구분 | 기술 | 버전 | 용도 |
|------|------|------|------|
| 언어 | Rust | 1.75+ | 고성능 비동기 서버 |
| 런타임 | Tokio | 1.x | 비동기 I/O 런타임 |
| 웹 프레임워크 | Axum | 0.7 | HTTP/WebSocket 서버 |
| WebSocket | tokio-tungstenite | 0.21 | WebSocket 프로토콜 |
| TLS | rustls + rcgen | - | 자체 서명 인증서 생성 및 TLS |
| HTTP 클라이언트 | reqwest | 0.11 | API 프록시, QuestDB 쿼리 |
| 직렬화 | serde + serde_json | 1.x | JSON 처리 |

### Database

| 구분 | 기술 | 용도 |
|------|------|------|
| 시계열 DB | QuestDB | 히스토리 데이터 저장 (ILP 프로토콜) |
| 인메모리 | Rust HashMap + RwLock | 실시간 세션/통계 관리 |

### Frontend

| 구분 | 기술 | 용도 |
|------|------|------|
| 언어 | Vanilla JavaScript (ES6+) | UI 로직 |
| 차트 | Chart.js 4.4 | 실시간 그래프 |
| 스타일 | Inline CSS | 다크 테마 UI |
| 통신 | Fetch API + WebSocket | API 호출 및 실시간 업데이트 |

### Infrastructure

| 구분 | 기술 | 용도 |
|------|------|------|
| 컨테이너 | Docker | QuestDB 실행 |
| 서비스 관리 | systemd | 프로세스 데몬화 |
| 리버스 프록시 | - | 직접 노출 (프록시 없음) |

---

## 2. 아키텍처

```
┌─────────────────┐      WSS (8443)      ┌─────────────────┐
│   P2P Client    │ ─────────────────▶   │    simple_ws    │
│   (Browser)     │      TLS 암호화       │  WebSocket 서버  │
└─────────────────┘                       └────────┬────────┘
                                                   │
                                    ┌──────────────┼──────────────┐
                                    │              │              │
                                    ▼              ▼              ▼
                             ┌──────────┐   ┌──────────┐   ┌──────────┐
                             │ In-Memory│   │ QuestDB  │   │Dashboard │
                             │ Sessions │   │  :9009   │   │  :8080   │
                             │ HashMap  │   │  (ILP)   │   │          │
                             └──────────┘   └──────────┘   └────┬─────┘
                                                  ▲              │
                                                  │   HTTP Query │
                                                  └──────────────┘
                                                      :9002
```

### 데이터 흐름

1. **P2P 클라이언트** → WebSocket으로 simple_ws에 연결
2. **simple_ws** → 세션 생성, 인메모리 HashMap에 저장
3. **simple_ws** → 10초마다 QuestDB로 집계 데이터 전송 (ILP)
4. **simple_ws** → 세션 종료 시 visitor_logs에 트래픽 저장
5. **Dashboard** → simple_ws API로 실시간 데이터 조회
6. **Dashboard** → QuestDB로 히스토리 데이터 조회

---

## 3. 설치 방법

### 3.1 요구사항

- **OS**: Linux (Ubuntu 20.04+ 권장)
- **Rust**: 1.75 이상
- **Docker**: QuestDB 실행용
- **메모리**: 최소 4GB (10만 연결 시 3GB+ 사용)
- **포트**: 8443 (WSS), 8080 (Dashboard), 9000-9019 (QuestDB)

### 3.2 QuestDB 설치

```bash
# Docker로 QuestDB 실행
docker run -d --name questdb \
  --restart unless-stopped \
  -p 9000:9000 \
  -p 9002:9002 \
  -p 9009:9009 \
  -p 8812:8812 \
  -p 9019:9019 \
  -v questdb_data:/var/lib/questdb \
  questdb/questdb

# 포트 설명
# 9000: Web Console
# 9002: HTTP API (쿼리)
# 9009: ILP (데이터 적재)
# 9019: ILP TCP
# 8812: PostgreSQL Wire Protocol
```

### 3.3 프로젝트 클론 및 빌드

```bash
# 클론
git clone https://github.com/eaTorTMnennoeT/stats_dashboard.git /opt/rust
cd /opt/rust

# simple_ws 빌드
cd simple_ws
cargo build --release

# stats_dashboard 빌드
cd ../stats_dashboard
cargo build --release
```

### 3.4 TLS 인증서

simple_ws는 시작 시 자동으로 자체 서명 인증서를 생성합니다.
커스텀 인증서 사용 시:

```bash
# 인증서 디렉토리 생성
mkdir -p /opt/rust/simple_ws/certs

# 인증서 배치
cp your_cert.pem /opt/rust/simple_ws/certs/cert.pem
cp your_key.pem /opt/rust/simple_ws/certs/key.pem
```

### 3.5 systemd 서비스 등록

```bash
# simple-ws.service
cat > /etc/systemd/system/simple-ws.service << 'EOF'
[Unit]
Description=P2P WebSocket Server
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/rust/simple_ws
ExecStart=/opt/rust/simple_ws/target/release/simple_ws
Restart=always
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

# stats-dashboard.service
cat > /etc/systemd/system/stats-dashboard.service << 'EOF'
[Unit]
Description=P2P Stats Dashboard
After=network.target simple-ws.service

[Service]
Type=simple
WorkingDirectory=/opt/rust/stats_dashboard
ExecStart=/opt/rust/stats_dashboard/target/release/stats_dashboard
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 서비스 활성화 및 시작
systemctl daemon-reload
systemctl enable simple-ws stats-dashboard
systemctl start simple-ws stats-dashboard
```

### 3.6 시스템 튜닝 (대규모 연결용)

```bash
# /etc/security/limits.d/p2p-stats.conf
cat > /etc/security/limits.d/p2p-stats.conf << 'EOF'
* soft nofile 1000000
* hard nofile 1000000
root soft nofile 1000000
root hard nofile 1000000
EOF

# /etc/sysctl.d/99-p2p-stats.conf
cat > /etc/sysctl.d/99-p2p-stats.conf << 'EOF'
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF

sysctl -p /etc/sysctl.d/99-p2p-stats.conf
```

---

## 4. 사용 방법 (How to Use)

### 4.1 서비스 관리

```bash
# 시작
systemctl start simple-ws stats-dashboard

# 중지
systemctl stop simple-ws stats-dashboard

# 재시작
systemctl restart simple-ws stats-dashboard

# 상태 확인
systemctl status simple-ws stats-dashboard

# 로그 확인
journalctl -u simple-ws -f
journalctl -u stats-dashboard -f
```

### 4.2 대시보드 접속

- **URL**: http://your-server:8080
- **탭 구성**:
  - **Dashboard**: 주요 지표 요약, 실시간 차트
  - **실시간**: 디바이스/브라우저/유입경로 상세 통계
  - **시청 중**: 스웜(영상)별 시청자 목록
  - **방문자**: IP별 방문 기록 검색
  - **인기 콘텐츠**: 인기 영상 순위
  - **IP 분석**: IP별 트래픽 분석
  - **히스토리**: 과거 데이터 그래프
  - **서버**: 서버별 트래픽 분포
  - **설정**: 갱신 주기, 캐시 설정

### 4.3 API 엔드포인트

#### simple_ws (8443)

| 엔드포인트 | 메서드 | 설명 |
|------------|--------|------|
| `/` | WebSocket | P2P 클라이언트 연결 |
| `/stats` | GET | 서버 상태 (연결 수, 메모리) |
| `/api/realtime` | GET | 실시간 통계 |
| `/api/live` | GET | 스웜별 시청자 목록 |
| `/api/sessions` | GET | 세션 목록 (페이지네이션) |
| `/api/ip_stats` | GET | IP별 세션 통계 |

#### stats_dashboard (8080)

| 엔드포인트 | 메서드 | 설명 |
|------------|--------|------|
| `/api/realtime` | GET | 실시간 통계 (프록시) |
| `/api/live` | GET | 시청 중 목록 (프록시) |
| `/api/sessions` | GET | 세션 목록 (프록시) |
| `/api/ip-analysis` | GET | IP 분석 (실시간/히스토리) |
| `/api/visitors` | GET | 방문자 기록 |
| `/api/popular` | GET | 인기 콘텐츠 |
| `/api/summary` | GET | 요약 통계 |
| `/api/history/stats` | GET | 히스토리 통계 |
| `/api/servers/realtime` | GET | 서버별 통계 |
| `/ws` | WebSocket | 실시간 푸시 |

### 4.4 QuestDB 테이블

```sql
-- 전체 통계 (10초마다 기록)
CREATE TABLE IF NOT EXISTS p2p_stats (
    ts TIMESTAMP,
    viewers LONG,
    unique_users LONG,
    http_bytes LONG,
    p2p_bytes LONG,
    p2p_up_bytes LONG,
    peers LONG,
    swarms LONG
) TIMESTAMP(ts) PARTITION BY DAY;

-- 스웜별 통계
CREATE TABLE IF NOT EXISTS p2p_swarms (
    ts TIMESTAMP,
    swarm_id SYMBOL,
    filename STRING,
    viewers LONG,
    http_bytes LONG,
    p2p_bytes LONG
) TIMESTAMP(ts) PARTITION BY DAY;

-- 방문자 로그 (세션 종료 시 기록)
CREATE TABLE IF NOT EXISTS visitor_logs (
    timestamp TIMESTAMP,
    ip STRING,
    session_id STRING,
    swarm_id STRING,
    filename STRING,
    device STRING,
    device_name STRING,
    browser STRING,
    referrer STRING,
    net_type STRING,
    player_id SHORT,
    http_bytes LONG,
    p2p_bytes LONG,
    p2p_up_bytes LONG
) TIMESTAMP(timestamp) PARTITION BY DAY;

-- 일별 집계 (자동 생성)
CREATE TABLE IF NOT EXISTS daily_stats (
    date TIMESTAMP,
    total_sessions LONG,
    unique_ips LONG,
    total_http LONG,
    total_p2p LONG,
    total_p2p_up LONG,
    peak_viewers LONG
) TIMESTAMP(date) PARTITION BY MONTH;
```

---

## 5. 장단점

### 장점

| 항목 | 설명 |
|------|------|
| **고성능** | Rust + Tokio 조합으로 12만+ 동시 연결 처리, C10K 문제 없음 |
| **저지연** | 인메모리 세션 관리로 실시간 통계 나노초 단위 접근 |
| **메모리 효율** | 12만 연결에 ~3GB, GC 없는 Rust 특성상 메모리 예측 가능 |
| **단순 아키텍처** | Redis 없이 단일 프로세스로 운영, 외부 의존성 최소화 |
| **자동 TLS** | 서버 시작 시 자체 서명 인증서 자동 생성 |
| **시계열 최적화** | QuestDB로 시간 기반 쿼리 빠름, 파티셔닝 자동 |
| **실시간 + 히스토리** | 메모리(실시간) + DB(히스토리) 하이브리드 구조 |
| **무료 스택** | 모든 구성 요소 오픈소스, 라이선스 비용 없음 |

### 단점

| 항목 | 설명 |
|------|------|
| **단일 장애점** | 단일 서버 구조로 서버 장애 시 전체 서비스 중단 |
| **수평 확장 제한** | 인메모리 세션으로 다중 서버 클러스터링 어려움 |
| **세션 휘발성** | 서버 재시작 시 모든 WebSocket 세션 끊김, 클라이언트 재연결 필요 |
| **QuestDB 의존** | QuestDB 장애 시 히스토리 기록 불가 (실시간은 정상) |
| **Rust 학습곡선** | 유지보수를 위해 Rust 지식 필요 |
| **모니터링 부재** | 별도 APM/모니터링 도구 미포함, 외부 도구 연동 필요 |
| **백업 미구현** | QuestDB 데이터 자동 백업 없음, 수동 설정 필요 |

### 개선 가능 영역

| 항목 | 현재 | 개선안 |
|------|------|--------|
| 고가용성 | 단일 서버 | Redis/NATS로 세션 공유 후 다중 서버 |
| 백업 | 없음 | QuestDB 스냅샷 + S3 업로드 크론잡 |
| 모니터링 | 기본 /stats | Prometheus metrics 엔드포인트 추가 |
| 알림 | 없음 | Grafana Alerting 또는 Slack 웹훅 |

---

## 6. 프로젝트 구조

```
/opt/rust/
├── simple_ws/                    # WebSocket 서버
│   ├── Cargo.toml
│   ├── src/
│   │   └── main.rs              # 메인 서버 코드
│   └── certs/                   # TLS 인증서 (자동 생성)
│       ├── cert.pem
│       └── key.pem
│
├── stats_dashboard/             # 관리자 대시보드
│   ├── Cargo.toml
│   ├── src/
│   │   └── main.rs              # API 서버 + 프록시
│   └── static/
│       └── index.html           # SPA 대시보드 UI
│
├── README.md                    # 프로젝트 개요
├── howto.md                     # 서비스 관리 가이드
├── DOCUMENTATION.md             # 이 문서
└── todo.md                      # 개발 계획
```

---

## 7. 문제 해결

### 포트 충돌

```bash
# 사용 중인 포트 확인
ss -tlnp | grep -E '8443|8080'

# 프로세스 강제 종료
fuser -k 8443/tcp
fuser -k 8080/tcp
```

### QuestDB 연결 실패

```bash
# QuestDB 상태 확인
docker ps | grep questdb
docker logs questdb --tail 50

# 재시작
docker restart questdb
```

### WebSocket 연결 끊김

```bash
# 파일 디스크립터 확인
cat /proc/$(pgrep simple_ws)/limits | grep "open files"

# 현재 연결 수
ss -s
```

### 메모리 부족

```bash
# 메모리 사용량 확인
ps aux --sort=-%mem | head -10

# simple_ws 메모리
cat /proc/$(pgrep simple_ws)/status | grep -E 'VmRSS|VmSize'
```

---

## 8. 버전 히스토리

| 버전 | 날짜 | 변경 사항 |
|------|------|-----------|
| 1.0 | 2025-01 | 초기 버전 |
| 1.1 | 2025-01 | IP 분석 탭 추가, 트래픽 DB 저장 |
| 1.2 | 2025-01 | 실시간 모드 제목 표시, IP 복사 기능 |
