# Simple Tracker - Rust WebRTC P2P 트래커

## 프로젝트 개요

Novage P2P-Media-Loader와 호환되는 고성능 WebRTC 시그널링 트래커를 Rust로 구현하고, 기존 stats_dashboard에 트래커 모니터링 페이지를 추가한다.

---

## 목표

### 1. 핵심 목표
- [ ] WebTorrent 트래커 프로토콜 구현 (WebSocket 기반)
- [ ] 10만+ 동시 연결 처리 (simple_ws 수준)
- [ ] 기존 `tracker.linkwang.org` 대체 가능

### 2. 모니터링 목표
- [ ] 실시간 피어/스웜 현황 API
- [ ] stats_dashboard에 트래커 어드민 페이지 추가

### 3. 고급 기능 (선택)
- [ ] 지역/ISP 기반 피어 매칭 최적화
- [ ] 악성 피어 차단 기능
- [ ] 피어 연결 성공/실패율 통계

---

## 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                        클라이언트                            │
│  (P2P-Media-Loader + HLS.js)                                │
└──────────────────┬──────────────────────────────────────────┘
                   │ WebSocket
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                   simple_tracker                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Signaling  │  │   Swarm     │  │      Stats API      │  │
│  │   Handler   │  │   Manager   │  │   (for dashboard)   │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│         │               │                    │              │
│         └───────────────┴────────────────────┘              │
│                         │                                   │
│                    ┌────┴────┐                              │
│                    │ Storage │ (in-memory HashMap)          │
│                    └─────────┘                              │
└─────────────────────────────────────────────────────────────┘
                   │ HTTP API
                   ▼
┌─────────────────────────────────────────────────────────────┐
│                   stats_dashboard                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │Dashboard │  │ Traffic  │  │ Players  │  │  Tracker   │  │
│  │          │  │          │  │          │  │  (신규)    │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## WebTorrent 트래커 프로토콜

### 클라이언트 → 트래커

```javascript
// 1. Announce (스웜 참여)
{
  "action": "announce",
  "info_hash": "스웜ID (hex)",
  "peer_id": "피어ID (hex)",
  "offers": [
    { "offer_id": "xxx", "offer": { /* RTCSessionDescription */ } }
  ],
  "numwant": 10  // 원하는 피어 수
}

// 2. Answer (WebRTC 응답)
{
  "action": "announce",
  "info_hash": "스웜ID",
  "peer_id": "피어ID",
  "to_peer_id": "상대방ID",
  "answer": { /* RTCSessionDescription */ },
  "offer_id": "xxx"
}

// 3. Scrape (스웜 정보 조회)
{
  "action": "scrape",
  "info_hash": "스웜ID"
}
```

### 트래커 → 클라이언트

```javascript
// 1. Offer 전달
{
  "action": "announce",
  "info_hash": "스웜ID",
  "peer_id": "보낸피어ID",
  "offer": { /* RTCSessionDescription */ },
  "offer_id": "xxx"
}

// 2. Answer 전달
{
  "action": "announce",
  "info_hash": "스웜ID",
  "answer": { /* RTCSessionDescription */ },
  "offer_id": "xxx"
}

// 3. Scrape 응답
{
  "action": "scrape",
  "files": {
    "스웜ID": { "complete": 0, "incomplete": 10 }
  }
}
```

---

## 데이터 구조

```rust
// 피어 정보
struct Peer {
    peer_id: String,
    socket_id: u64,           // WebSocket 연결 ID
    ip: String,
    joined_at: u64,           // 타임스탬프
    last_seen: u64,
    offers_sent: u64,         // 보낸 offer 수
    offers_received: u64,     // 받은 offer 수
    connections_made: u64,    // 성공한 WebRTC 연결 수
}

// 스웜 정보
struct Swarm {
    info_hash: String,
    peers: HashMap<String, Peer>,  // peer_id -> Peer
    created_at: u64,
    total_announces: u64,
}

// 전역 상태
struct TrackerState {
    swarms: HashMap<String, Swarm>,      // info_hash -> Swarm
    socket_to_peer: HashMap<u64, (String, String)>,  // socket_id -> (info_hash, peer_id)

    // 통계
    total_connections: u64,
    total_announces: u64,
    total_offers_relayed: u64,
    total_answers_relayed: u64,
}
```

---

## API 엔드포인트

### WebSocket (트래커 기능)
- `wss://host:port/` - 메인 트래커 엔드포인트

### HTTP (모니터링 API)
```
GET /api/stats
- 전체 통계 (연결 수, 스웜 수, 피어 수 등)

GET /api/swarms
- 스웜 목록 (피어 수 기준 정렬)

GET /api/swarm/{info_hash}
- 특정 스웜 상세 정보

GET /api/peers
- 전체 피어 목록

GET /api/health
- 헬스체크
```

### 모니터링 API 응답 예시

```json
// GET /api/stats
{
  "uptime": 86400,
  "totalConnections": 125000,
  "activeConnections": 105000,
  "totalSwarms": 28000,
  "activeSwarms": 17500,
  "totalAnnounces": 5000000,
  "offersRelayed": 2500000,
  "answersRelayed": 2400000,
  "connectionsPerSecond": 150,
  "announcesPerSecond": 500
}

// GET /api/swarms?limit=10
{
  "swarms": [
    {
      "infoHash": "abc123...",
      "peerCount": 156,
      "createdAt": 1705700000,
      "announces": 1250
    }
  ],
  "total": 28000
}
```

---

## stats_dashboard 트래커 페이지

### UI 구성

```
┌─────────────────────────────────────────────────────────────┐
│  트래커 모니터링                                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ 연결     │  │ 스웜     │  │ Offer    │  │ Answer   │   │
│  │ 105,000  │  │ 17,500   │  │ 2.5M     │  │ 2.4M     │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  실시간 연결 그래프                                   │   │
│  │  ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~            │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  인기 스웜 TOP 10                                    │   │
│  │  1. every5.cdn.com/video1.m3u8  (156명)             │   │
│  │  2. every5.cdn.com/video2.m3u8  (142명)             │   │
│  │  ...                                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  시그널링 성공률                                      │   │
│  │  Offer 전달: 99.2%  │  Answer 전달: 98.8%           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## TODO 리스트

### Phase 1: 기본 트래커 구현
- [ ] 1.1 Cargo 프로젝트 생성 (`simple_tracker`)
- [ ] 1.2 WebSocket 서버 기본 구조 (actix-web)
- [ ] 1.3 트래커 프로토콜 파싱 (announce, scrape)
- [ ] 1.4 스웜/피어 관리 구조체
- [ ] 1.5 Offer/Answer 릴레이 로직
- [ ] 1.6 피어 타임아웃 처리 (idle 60초 제거)
- [ ] 1.7 기본 동작 테스트

### Phase 2: 모니터링 API
- [ ] 2.1 `/api/stats` - 전체 통계
- [ ] 2.2 `/api/swarms` - 스웜 목록
- [ ] 2.3 `/api/swarm/{id}` - 스웜 상세
- [ ] 2.4 `/api/health` - 헬스체크
- [ ] 2.5 CORS 설정

### Phase 3: stats_dashboard 연동
- [ ] 3.1 사이드바에 "트래커" 메뉴 추가
- [ ] 3.2 트래커 페이지 HTML/CSS
- [ ] 3.3 실시간 통계 카드 (연결, 스웜, offer, answer)
- [ ] 3.4 인기 스웜 TOP 10 테이블
- [ ] 3.5 실시간 연결 그래프 (선택)

### Phase 4: 배포 및 전환
- [ ] 4.1 SSL 인증서 설정
- [ ] 4.2 systemd 서비스 등록
- [ ] 4.3 player.php 트래커 URL 변경
- [ ] 4.4 기존 트래커와 병렬 운영 테스트
- [ ] 4.5 완전 전환

### Phase 5: 고급 기능 (선택)
- [ ] 5.1 지역 기반 피어 매칭
- [ ] 5.2 IP 차단 기능
- [ ] 5.3 QuestDB 연동 (히스토리 저장)
- [ ] 5.4 시그널링 성공/실패율 통계

---

## 기술 스택

| 구성요소 | 기술 |
|----------|------|
| 언어 | Rust |
| WebSocket | actix-web + actix-ws |
| HTTP API | actix-web |
| 직렬화 | serde_json |
| 동시성 | tokio + RwLock |
| SSL | rustls |

---

## 포트 설정

| 서비스 | 포트 | 용도 |
|--------|------|------|
| simple_ws | 8443 | 통계 수집 |
| simple_tracker | 8444 | P2P 트래커 |
| stats_dashboard | 8080 | 어드민 |

---

## 예상 일정

| Phase | 예상 작업량 |
|-------|-------------|
| Phase 1 | 기본 트래커 |
| Phase 2 | API 추가 |
| Phase 3 | 대시보드 연동 |
| Phase 4 | 배포 |
| Phase 5 | 고급 기능 (선택) |

---

## 참고 자료

- [WebTorrent Tracker Protocol](https://github.com/webtorrent/bittorrent-tracker/blob/master/lib/common.js)
- [Novage P2P-Media-Loader](https://github.com/Novage/p2p-media-loader)
- [actix-web WebSocket](https://actix.rs/docs/websockets/)
