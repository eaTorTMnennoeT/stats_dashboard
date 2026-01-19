# Aquatic 트래커 분석 결과

## 1. 아키텍처

### 워커 분리 구조
```
Socket Workers (N개)          Swarm Workers (M개)
┌─────────────────┐          ┌─────────────────┐
│ TCP 연결 관리   │──────────│ 스웜/피어 관리  │
│ WebSocket 파싱  │  Mesh    │ Offer/Answer    │
│ TLS 처리        │ Channel  │ 릴레이          │
└─────────────────┘          └─────────────────┘
```

- **Socket Worker**: 연결 수락, WebSocket 파싱, TLS 처리
- **Swarm Worker**: 피어 관리, Offer/Answer 릴레이, 통계
- **Channel Mesh**: 워커 간 고속 통신 (glommio)

### 핵심 기술
| 기술 | 용도 | 성능 영향 |
|------|------|----------|
| glommio | io_uring 기반 async runtime | 높은 I/O 성능 |
| IndexMap | 순서 유지 해시맵 | 랜덤 피어 선택 최적화 |
| HopSlotMap | 슬롯맵 (빠른 삽입/삭제) | 연결 관리 최적화 |
| channel_mesh | 워커 간 통신 | 락 프리 통신 |

---

## 2. 데이터 구조

### TorrentMap (스웜 관리)
```rust
struct TorrentMap {
    torrents: IndexMap<InfoHash, TorrentData>,
}

struct TorrentData {
    peers: IndexMap<PeerId, Peer>,
    num_seeders: usize,
}

struct Peer {
    connection_id: ConnectionId,
    consumer_id: ConsumerId,
    seeder: bool,
    valid_until: ValidUntil,
    expecting_answers: IndexMap<ExpectingAnswer, ValidUntil>,
}
```

### 특징
- IPv4/IPv6 별도 관리
- 시더/리처 카운트 별도 추적
- Offer에 대한 Answer 기대 추적 (`expecting_answers`)
- 모든 항목에 만료 시간 (`ValidUntil`)

---

## 3. 피어 매칭 알고리즘 (핵심!)

### extract_response_peers 함수
```rust
// 피어 수가 적으면: 전체 반환 (자신 제외)
// 피어 수가 많으면: 맵의 앞/뒤 절반에서 랜덤 선택

if peer_map.len() <= max_num_peers_to_take + 1 {
    // 전체 반환
} else {
    // 앞쪽 절반에서 랜덤 offset으로 N개
    // 뒤쪽 절반에서 랜덤 offset으로 N개
    // 합쳐서 반환
}
```

### 왜 이렇게 하나?
- **동질성 방지**: 같은 시간대에 접속한 피어들만 매칭되는 것 방지
- **다양성 확보**: 오래된 피어 + 새로운 피어 혼합
- **IndexMap 활용**: 순서 보장으로 시간대별 분포 가능

---

## 4. 프로토콜 처리

### Announce 처리 흐름
```
1. 피어 ID 검증 (connection_id 확인 - 스푸핑 방지)
2. 피어 등록/업데이트 (seeder/leecher 상태)
3. Offer 처리 → 랜덤 피어에게 전달
4. Answer 처리 → expecting_answers 확인 후 전달
5. AnnounceResponse 반환 (complete/incomplete 수)
```

### 보안 기능
- **피어 ID 스푸핑 방지**: connection_id로 요청 검증
- **Offer 만료**: 일정 시간 내 Answer 없으면 삭제
- **Access List**: 특정 info_hash 허용/차단

---

## 5. 설정 값 (기본값)

| 설정 | 기본값 | 설명 |
|------|--------|------|
| max_peer_age | 180초 | 피어 타임아웃 |
| max_offer_age | 120초 | Offer 만료 시간 |
| max_connection_idle | 180초 | 연결 유휴 타임아웃 |
| peer_announce_interval | 120초 | 재announce 주기 |
| max_offers | 10 | 최대 offer 수 |
| max_scrape_torrents | 255 | scrape 최대 토렌트 수 |

---

## 6. Metrics (Prometheus)

수집 항목:
- `aquatic_peers` (ip_version, worker_index)
- `aquatic_torrents` (ip_version, worker_index)
- `aquatic_active_connections` (ip_version, worker_index)

---

## 7. simple_tracker에 적용할 개선사항

### 필수 적용
1. **IndexMap 사용** - 피어 매칭 다양성 확보
2. **피어 ID 검증** - 스푸핑 방지
3. **Offer 만료 추적** - expecting_answers 구조
4. **개선된 피어 선택 알고리즘** - 앞/뒤 절반 랜덤 선택

### 성능 최적화
1. **워커 분리** (선택) - CPU 코어 많을 때 유리
2. **ValidUntil 구조체** - 타임스탬프 비교 최적화
3. **shrink_to_fit** - 메모리 최적화

### 추가 기능
1. **ISP 기반 매칭** - MaxMind GeoIP2 연동
2. **지역 기반 매칭** - 같은 국가/지역 우선
3. **고급 모니터링 API** - 피어별, 스웜별 상세 통계
4. **Access List** - 특정 스웜 차단

---

## 8. ISP 기반 매칭 구현 방안

### MaxMind GeoIP2 연동
```rust
use maxminddb::Reader;

struct GeoData {
    country: String,
    asn: u32,        // ISP 식별자
    as_org: String,  // ISP 이름 (예: "SK Telecom")
}

fn get_geo_data(reader: &Reader, ip: &str) -> Option<GeoData> {
    // IP → 국가, ASN, ISP 정보
}
```

### 피어 선택 우선순위
```
1순위: 같은 ISP (ASN)
2순위: 같은 국가
3순위: 랜덤
```

### 효과
- 같은 ISP 내 P2P는 망 내부 트래픽 → 빠름
- 국제 트래픽 감소 → 비용 절감
- 지연시간 감소 → 사용자 경험 향상

---

## 9. 구현 우선순위

### Phase 1: 핵심 개선
- [ ] IndexMap으로 자료구조 변경
- [ ] 피어 ID 검증 추가
- [ ] expecting_answers 구조 추가
- [ ] 개선된 피어 선택 알고리즘

### Phase 2: ISP/지역 매칭
- [ ] MaxMind DB 연동
- [ ] GeoData 캐싱
- [ ] ISP 기반 피어 선택

### Phase 3: 모니터링 고도화
- [ ] 피어별 상세 통계 API
- [ ] ISP별 통계 API
- [ ] 스웜별 상세 통계 API
- [ ] Prometheus 메트릭 (선택)

### Phase 4: 성능 최적화 (필요시)
- [ ] 워커 분리 구조
- [ ] io_uring 적용 (glommio)
