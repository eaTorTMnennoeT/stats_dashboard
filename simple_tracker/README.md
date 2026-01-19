# Simple Tracker

WebRTC 기반 P2P 스트리밍을 위한 고성능 WebTorrent 트래커 서버

## 개요

Simple Tracker는 WebTorrent 프로토콜을 지원하는 시그널링 서버로, ISP/지역 기반 지능형 피어 매칭 알고리즘을 통해 P2P 트래픽을 최적화합니다.

## 주요 기능

### 🌍 지역 기반 피어 매칭 (Geo-based Peer Matching)

5단계 계층적 매칭 알고리즘:
1. **ISP + 도시** - 같은 ISP, 같은 도시 (최고 품질)
2. **같은 ISP** - 같은 ISP, 다른 도시
3. **같은 도시** - 다른 ISP, 같은 도시
4. **같은 국가** - 같은 국가 내 매칭
5. **랜덤** - 해외 포함 전체

### 📊 실시간 모니터링

- 활성 연결/스웜/피어 통계
- ISP별, 국가별, 도시별 분포
- 매칭 알고리즘 성능 통계
- 시그널링 로그 (매칭 티어 표시)

### 🔒 보안 기능

- TLS/HTTPS 지원 (rustls)
- 피어 ID 스푸핑 방지
- Offer 만료 추적 (expecting_answers)

## 기술 스택

| 기술 | 용도 |
|------|------|
| Rust | 시스템 프로그래밍 언어 |
| Actix-web | 고성능 비동기 웹 프레임워크 |
| Actix-ws | WebSocket 지원 |
| Tokio | 비동기 런타임 |
| IndexMap | 순서 유지 해시맵 (피어 다양성) |
| MaxMind GeoIP2 | IP → ISP/국가/도시 매핑 |
| Rustls | TLS 구현 |
| Serde | JSON 직렬화 |

## 설치 및 실행

### 요구사항

- Rust 1.70+
- MaxMind GeoIP2 데이터베이스 (옵션)

### GeoIP 데이터베이스 설치

```bash
mkdir -p data
# MaxMind에서 다운로드 후 배치
# - data/GeoLite2-ASN.mmdb
# - data/GeoLite2-Country.mmdb
# - data/GeoLite2-City.mmdb
```

### TLS 인증서 설정 (옵션)

```bash
mkdir -p certs
# 인증서 배치
# - certs/cert.pem
# - certs/key.pem
```

### 빌드 및 실행

```bash
# 빌드
cargo build --release

# 실행
./target/release/simple_tracker
```

서버는 기본적으로 `0.0.0.0:2053`에서 실행됩니다.

## API 엔드포인트

### WebSocket (트래커)

- `GET /` - WebTorrent WebSocket 연결
- `GET /announce` - WebTorrent WebSocket 연결

### HTTP API (모니터링)

| 엔드포인트 | 설명 |
|-----------|------|
| `GET /api/stats` | 전체 통계 |
| `GET /api/swarms` | 스웜 목록 |
| `GET /api/swarm/{hash}` | 스웜 상세 |
| `GET /api/isps` | ISP별 통계 |
| `GET /api/countries` | 국가별 통계 |
| `GET /api/cities` | 도시별 통계 |
| `GET /api/logs` | 시그널링 로그 |
| `GET /api/connections` | 피어 연결 관계 |
| `GET /api/health` | 헬스 체크 |

### 응답 예시

```json
{
  "uptime": 3600,
  "activeConnections": 50000,
  "activeSwarms": 15000,
  "totalPeers": 45000,
  "matchesSameIspCity": 500,
  "matchesSameIsp": 20000,
  "matchesSameCity": 1000,
  "matchesSameCountry": 23000,
  "matchesRandom": 500
}
```

## 설정 상수

| 설정 | 기본값 | 설명 |
|------|--------|------|
| MAX_PEER_AGE_MS | 180,000 | 피어 타임아웃 (3분) |
| MAX_OFFER_AGE_MS | 120,000 | Offer 만료 (2분) |
| MAX_OFFERS_PER_ANNOUNCE | 10 | Announce당 최대 Offer |
| CLEANUP_INTERVAL_SECS | 30 | 정리 주기 |
| MAX_MESSAGE_LOGS | 200 | 로그 보관 수 |

## 장점

### 성능
- **Rust + Actix**: C/C++ 수준의 성능
- **비동기 I/O**: 수만 동시 연결 처리
- **IndexMap**: O(1) 삽입/조회 + 순서 유지

### 트래픽 최적화
- **ISP 내부 매칭**: 망 내부 트래픽 → 빠른 속도
- **지역 우선**: 지연시간 최소화
- **계층적 폴백**: 항상 최적의 피어 선택

### 운영
- **실시간 모니터링**: 대시보드 연동
- **매칭 통계**: 알고리즘 효과 측정
- **헬스 체크**: 장애 감지

## 단점 / 한계

### GeoIP 의존성
- MaxMind 데이터베이스 필요 (유료 라이선스)
- IP 정보 부정확할 수 있음 (VPN, 모바일)
- IPv6 커버리지 낮음

### 단일 프로세스
- 멀티 워커 분리 미지원 (Aquatic 방식)
- 수평 확장 시 로드밸런서 필요

### 메모리 사용
- 모든 피어/스웜 정보 메모리 보관
- 대규모 시 메모리 증가

## Aquatic 대비 차이점

| 항목 | Simple Tracker | Aquatic |
|------|----------------|---------|
| 런타임 | Tokio | Glommio (io_uring) |
| 워커 | 단일 | Socket + Swarm 분리 |
| 지역 매칭 | 5단계 계층적 | 없음 |
| 모니터링 | HTTP API | Prometheus |
| 복잡도 | 단순 | 고성능 최적화 |

## 테스트

```bash
# 유닛 테스트 실행
cargo test -- --nocapture
```

테스트 항목:
- 피어 선택 우선순위 검증
- 전체 티어 동작 확인
- 셔플 분포 검증 (부하 분산)

## 라이선스

MIT License

## 참고

- [WebTorrent Protocol](https://webtorrent.io/)
- [Aquatic Tracker](https://github.com/greatest-ape/aquatic)
- [MaxMind GeoIP2](https://www.maxmind.com/)
