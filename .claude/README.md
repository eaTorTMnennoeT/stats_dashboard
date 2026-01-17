# P2P Stats Server - Rust 마이그레이션

## 현재 상태 (2026-01-17)
- **서버 상태**: 운영 중
- **CPU**: ~64% (이전 838%)
- **동시 연결**: 70,000+ 처리 중
- **바이너리**: `/opt/rust/target/release/p2p_stats`

## 완료된 최적화

### 1. WebSocket 활성화
- `main.rs:69` - `/ws` 엔드포인트 503 → 정상 핸들러 연결
- HTTP 폴링에서 WebSocket으로 전환되어 부하 대폭 감소

### 2. Actix 서버 튜닝 (`main.rs`)
```rust
.workers(32)                      // CPU/2, 최대 32
.backlog(8192)                    // 연결 대기열
.max_connections(100_000)         // 최대 동시 연결
.max_connection_rate(50_000)      // 초당 새 연결
.keep_alive(75초)
.client_request_timeout(10초)
.client_disconnect_timeout(5초)
```

### 3. DashMap 샤딩 (`stats.rs`)
```rust
sessions: DashMap::with_shard_amount(128)
swarms: DashMap::with_shard_amount(64)
// 기타 맵들도 적절히 샤딩
```

### 4. ClickHouse 배치 Insert (`db/clickhouse.rs`)
- 매 insert마다 commit → 500개씩 배치 또는 5초마다 플러시
- `mpsc::unbounded_channel` 사용하여 논블로킹

### 5. 빌드 최적화 (`Cargo.toml`)
```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
strip = true
```

## 서버 실행 방법
```bash
cd /opt/rust
nohup ./target/release/p2p_stats > /tmp/p2p_stats.log 2>&1 &
```

## 다음 세션에서 할 수 있는 것들
1. **jemalloc 추가** - 네트워크 되면 `tikv-jemallocator` 의존성 추가
2. **메트릭 모니터링** - Prometheus 엔드포인트 추가
3. **graceful shutdown** - SIGTERM 핸들링
4. **systemd 서비스** - 자동 재시작 설정

## 파일 구조
```
/opt/rust/
├── Cargo.toml
├── src/
│   ├── main.rs      # 서버 진입점, Actix 설정
│   ├── ws.rs        # WebSocket 핸들러
│   ├── stats.rs     # 실시간 통계 (DashMap)
│   ├── api/mod.rs   # REST API
│   ├── admin.rs     # 어드민 API
│   └── db/
│       ├── mod.rs
│       ├── clickhouse.rs  # ClickHouse 배치 insert
│       └── dragonfly.rs   # Redis 캐시
└── target/release/p2p_stats
```

## 성능 비교
| 항목 | 변경 전 | 변경 후 |
|------|--------|--------|
| CPU | 838% | 64% |
| 연결 수 | ~2,000 | 70,000+ |
| WebSocket | 503 에러 | 정상 |
| CH Insert | 매번 commit | 배치 500개/5초 |
