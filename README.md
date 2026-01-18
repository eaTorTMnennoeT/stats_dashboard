# P2P Stats Dashboard

P2P 스트리밍 서비스의 실시간 통계를 수집하고 시각화하는 대시보드 시스템

## 아키텍처

```
┌─────────────┐      WebSocket      ┌─────────────┐
│  P2P Client │ ──────(TLS)──────▶ │  simple_ws  │
│  (Browser)  │                     │   :8443     │
└─────────────┘                     └──────┬──────┘
                                           │
                                    ┌──────┴──────┐
                                    ▼             ▼
                              ┌──────────┐  ┌──────────┐
                              │ QuestDB  │  │ Dashboard│
                              │ :9002    │  │  :8080   │
                              └──────────┘  └────┬─────┘
                                    ▲            │
                                    └────────────┘
                                      HTTP Query
```

## 프로젝트 구조

```
/opt/rust/
├── simple_ws/              # WebSocket 서버
│   ├── Cargo.toml
│   ├── src/main.rs         # 메인 서버 (862줄)
│   └── certs/              # TLS 인증서
│       ├── cert.pem
│       └── key.pem
│
└── stats_dashboard/        # 관리자 대시보드
    ├── Cargo.toml
    ├── src/main.rs         # API 프록시 서버 (161줄)
    └── static/
        └── index.html      # 대시보드 UI (611줄)
```

## 기술 스택

| 구분 | 기술 |
|------|------|
| 언어 | Rust 1.75+, JavaScript (ES6) |
| 런타임 | Tokio (async runtime) |
| 웹 프레임워크 | Axum 0.7 |
| 프로토콜 | WebSocket (WSS), HTTP/HTTPS |
| 데이터베이스 | QuestDB (시계열 DB) |
| 프론트엔드 | Vanilla JS, Chart.js 4.4 |
| TLS | rustls |

## Redis/Dragonfly 미사용 이유

| 용도 | Redis 대신 사용 | 이유 |
|------|----------------|------|
| 실시간 통계 | Rust 인메모리 (`RwLock<HashMap>`) | 외부 DB 호출 없이 나노초 단위 접근, 단일 서버라 분산 필요 없음 |
| 세션 관리 | Rust `HashMap<u64, Session>` | WebSocket 연결당 세션, 프로세스 내 관리 |
| 히스토리 | QuestDB | 시계열 특화 DB, 집계 쿼리 최적화 |
| 캐싱 | 프론트엔드 JS | 대시보드 자체 캐싱 옵션 |

**결론:** 단일 서버 + 실시간 처리 구조에서 외부 캐시 레이어 추가 시 오히려 레이턴시만 증가. Rust 인메모리가 Redis보다 빠름.

## 컴포넌트

### simple_ws (WebSocket 서버)

P2P 클라이언트로부터 실시간 통계를 수집하는 WebSocket 서버

**기능:**
- WebSocket 연결 관리 (TLS)
- 실시간 통계 집계 (시청자, 트래픽, P2P 비율)
- 스웜(Swarm) 단위 통계
- 디바이스/브라우저/유입경로 분석
- QuestDB로 10초마다 데이터 저장 (ILP 프로토콜)

**API 엔드포인트:**
| 엔드포인트 | 설명 |
|------------|------|
| `GET /stats` | 서버 상태 (연결 수, 메모리, CPU) |
| `GET /api/realtime` | 실시간 전체 통계 |
| `GET /api/live` | 스웜별 시청자 목록 |

**수집 데이터:**
- 시청자 수 / 고유 사용자 수
- HTTP/P2P 트래픽 (다운로드/업로드)
- 피어 연결 수
- 디바이스 타입 (모바일/데스크톱/태블릿)
- 기기명 (Windows PC, Android, iPhone 등)
- 브라우저, 유입 경로

### stats_dashboard (대시보드)

관리자용 웹 대시보드

**페이지:**
| 페이지 | 설명 |
|--------|------|
| Dashboard | 주요 지표 요약 + 실시간 차트 |
| 실시간 | 상세 접속자 통계 (디바이스, 브라우저, 유입경로) |
| 시청 중 | 스웜별 시청자 목록 (페이지네이션) |
| 히스토리 | QuestDB 기반 과거 데이터 조회 |
| 설정 | 업데이트 주기, 캐싱 설정 |

**API 프록시:**
| 엔드포인트 | 프록시 대상 |
|------------|-------------|
| `/api/realtime` | simple_ws /api/realtime |
| `/api/live` | simple_ws /api/live |
| `/api/stats` | simple_ws /stats |
| `/api/history/stats` | QuestDB 쿼리 |
| `/api/history/swarms` | QuestDB 쿼리 |

## 설치 및 실행

### 요구사항

- Rust 1.75+
- QuestDB (Docker)

### QuestDB 실행

```bash
docker run -d --name questdb \
  -p 9000:9000 -p 9002:9002 -p 9009:9009 -p 8812:8812 -p 9019:9019 \
  questdb/questdb
```

### 빌드

```bash
# simple_ws
cd /opt/rust/simple_ws
cargo build --release

# stats_dashboard
cd /opt/rust/stats_dashboard
cargo build --release
```

### 실행

```bash
# WebSocket 서버
cd /opt/rust/simple_ws
./target/release/simple_ws

# 대시보드
cd /opt/rust/stats_dashboard
./target/release/stats_dashboard
```

### 접속

- 대시보드: http://localhost:8080
- WebSocket: wss://localhost:8443

## QuestDB 테이블

```sql
-- 전체 통계
CREATE TABLE p2p_stats (
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
CREATE TABLE p2p_swarms (
    ts TIMESTAMP,
    swarm_id SYMBOL,
    filename STRING,
    viewers LONG,
    http_bytes LONG,
    p2p_bytes LONG
) TIMESTAMP(ts) PARTITION BY DAY;
```

## 설정

### simple_ws

`src/main.rs` 상수 수정:

```rust
const QUESTDB_ILP_ADDR: &str = "127.0.0.1:9019";  // QuestDB ILP 주소
```

### stats_dashboard

`src/main.rs` 상수 수정:

```rust
const SIMPLE_WS_URL: &str = "https://127.0.0.1:8443";  // simple_ws 주소
const QUESTDB_URL: &str = "http://127.0.0.1:9002";     // QuestDB HTTP 주소
```

## 성능

- 동시 접속: 120,000+ 연결 처리
- 메모리: ~3GB (12만 연결 기준)
- CPU: 멀티코어 활용 (72 workers)

## 라이선스

MIT
