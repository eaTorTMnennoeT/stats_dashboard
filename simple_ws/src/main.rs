use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
    routing::get,
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig;
use futures_util::{FutureExt, SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::{Mutex, RwLock};
use arc_swap::ArcSwap;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

use reqwest::Client as HttpClient;
use tower_http::cors::CorsLayer;

const WORKER_THREADS: usize = 72;
const BLOCKING_THREADS: usize = 128;
const MAX_CONNECTIONS: usize = 1_000_000;
const IDLE_TIMEOUT_SECS: u64 = 120;
const MAX_TRACKING_ENTRIES: usize = 10_000;
const PING_INTERVAL_SECS: u64 = 15;
const CLICKHOUSE_URL: &str = "http://127.0.0.1:8123";
const CLICKHOUSE_FLUSH_SECS: u64 = 1;

/// Saved delta values captured before reset, used for accurate ClickHouse flush
struct SavedDeltas {
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    /// swarm_id -> (r_http_bytes, r_p2p_bytes, r_p2p_up_bytes)
    swarm_deltas: HashMap<String, (u64, u64, u64)>,
}

// Global stats
static TOTAL_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static SYSTEM: std::sync::OnceLock<Mutex<System>> = std::sync::OnceLock::new();
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

// P2P Stats
lazy_static::lazy_static! {
    static ref P2P_STATS: Arc<RwLock<P2PStats>> = Arc::new(RwLock::new(P2PStats::default()));
    static ref SESSIONS: Arc<RwLock<HashMap<String, Session>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref VISITOR_LOGS: Arc<Mutex<Vec<VisitorLog>>> = Arc::new(Mutex::new(Vec::new()));
    static ref IP_TOTALS: Arc<RwLock<HashMap<String, u64>>> = Arc::new(RwLock::new(HashMap::new()));
    // API 응답 캐시 (lock-free 읽기)
    static ref REALTIME_CACHE: ArcSwap<String> = ArcSwap::from_pointee(String::from("{}"));
}

#[derive(Clone)]
struct VisitorLog {
    ip: String,
    session_id: String,
    swarm_id: String,
    filename: String,
    device: String,
    device_name: String,
    browser: String,
    referrer: String,
    net_type: String,
    player_id: u8,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
}

#[derive(Default)]
struct P2PStats {
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    peers: u64,
    // Delta values for current interval
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    // Timestamp when deltas were last reset (for accurate speed calculation)
    last_reset_ms: u64,
    player1: PlayerStats,
    player2: PlayerStats,
    devices: DeviceStats,
    device_names: HashMap<String, u64>,
    networks: NetworkStats,
    browsers: HashMap<String, u64>,
    referrers: HashMap<String, u64>,
    swarms: HashMap<String, SwarmStats>,
    // IP별 세션 카운트 (모든 세션 종료 시에만 삭제)
    unique_ips: HashMap<String, u64>,
    // 서버별 고유 IP 추적 (server_name -> (IP -> session_count))
    server_unique_ips: HashMap<String, HashMap<String, u64>>,
}

#[derive(Default, Clone)]
struct PlayerStats {
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    // Delta values for current interval
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    // Last known speed (preserved after reset for API)
    last_http_speed: u64,
    last_p2p_speed: u64,
    last_p2p_up_speed: u64,
    // 플레이어별 고유 IP 카운트
    unique_ips: HashMap<String, u64>,
}

#[derive(Default)]
struct DeviceStats {
    mobile: u64,
    desktop: u64,
    tablet: u64,
    unknown: u64,
}

#[derive(Default)]
struct NetworkStats {
    wifi: u64,
    cellular: u64,
    g4: u64,
    g5: u64,
    ethernet: u64,
    unknown: u64,
}

#[derive(Default, Clone)]
struct SwarmStats {
    filename: String,
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    // Delta values for current interval
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    // IP별 세션 카운트 (0이면 삭제)
    unique_ips: HashMap<String, u64>,
}

struct Session {
    swarm_id: String,
    player_id: u8,
    filename: String,
    device: String,
    device_name: String,
    net_type: String,
    browser: String,
    referrer: String,
    user_ip: String,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    // Delta values for current interval (real-time speed)
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    peers: u64,
    initialized: bool,
    last_active: Instant,
}

impl Default for Session {
    fn default() -> Self {
        Session {
            swarm_id: String::new(),
            player_id: 0,
            filename: String::new(),
            device: String::new(),
            device_name: String::new(),
            net_type: String::new(),
            browser: String::new(),
            referrer: String::new(),
            user_ip: String::new(),
            http_bytes: 0,
            p2p_bytes: 0,
            p2p_up_bytes: 0,
            r_http_bytes: 0,
            r_p2p_bytes: 0,
            r_p2p_up_bytes: 0,
            peers: 0,
            initialized: false,
            last_active: Instant::now(),
        }
    }
}

#[derive(Deserialize)]
struct ClientMessage {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(rename = "swarmId")]
    swarm_id: Option<String>,
    #[serde(rename = "playerId")]
    player_id: Option<u8>,
    filename: Option<String>,
    device: Option<String>,
    #[serde(rename = "deviceName")]
    device_name: Option<String>,
    #[serde(rename = "netType")]
    net_type: Option<String>,
    browser: Option<String>,
    referrer: Option<String>,
    #[serde(rename = "userIp")]
    user_ip: Option<String>,
    #[serde(rename = "httpBytes")]
    http_bytes: Option<u64>,
    #[serde(rename = "p2pBytes")]
    p2p_bytes: Option<u64>,
    #[serde(rename = "p2pUpBytes")]
    p2p_up_bytes: Option<u64>,
    peers: Option<u64>,
    // Delta values (new format)
    #[serde(rename = "rhttpBytes")]
    r_http_bytes: Option<u64>,
    #[serde(rename = "rp2pBytes")]
    r_p2p_bytes: Option<u64>,
    #[serde(rename = "rp2pUpBytes")]
    r_p2p_up_bytes: Option<u64>,
}

fn main() {
    std::panic::set_hook(Box::new(|info| {
        eprintln!("PANIC: {:?}", info);
        std::process::exit(1);
    }));

    // API 전용 서버를 별도 스레드/런타임에서 실행 (WebSocket 부하에 영향받지 않음)
    std::thread::spawn(|| {
        let api_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(8)
            .max_blocking_threads(16)
            .enable_all()
            .thread_name("api-worker")
            .build()
            .expect("Failed to build API runtime");

        api_rt.block_on(async {
            async fn ping() -> &'static str {
                "pong"
            }

            let api_app = Router::new()
                .route("/ping", get(ping))
                .route("/health", get(health))
                .route("/stats", get(stats))
                .route("/api/realtime", get(api_realtime))
                .route("/api/live", get(api_live))
                .route("/api/sessions", get(api_sessions))
                .route("/api/ip_stats", get(api_ip_stats))
                .layer(CorsLayer::permissive());

            let addr = SocketAddr::from(([127, 0, 0, 1], 8444));
            eprintln!("API server listening on {} (dedicated runtime, localhost only)", addr);

            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("Failed to bind API listener on {}: {}", addr, e);
                    return;
                }
            };
            if let Err(e) = axum::serve(listener, api_app.into_make_service()).await {
                eprintln!("API server error: {}", e);
            }
        });
    });

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKER_THREADS)
        .max_blocking_threads(BLOCKING_THREADS)
        .enable_all()
        .thread_name("ws-worker")
        .build()
        .expect("Failed to build runtime");

    rt.block_on(async_main());
}

async fn async_main() {
    // 서버 시작 전 캐시 초기화
    update_realtime_cache();

    // Spawn QuestDB flush task
    tokio::spawn(clickhouse_flush_task());

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/api/realtime", get(api_realtime))
        .route("/api/live", get(api_live))
        .route("/api/sessions", get(api_sessions))
        .route("/api/ip_stats", get(api_ip_stats))
        .layer(CorsLayer::permissive());

    let tls_config = RustlsConfig::from_pem_file("certs/cert.pem", "certs/key.pem")
        .await
        .expect("Failed to load TLS config");

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    eprintln!("WSS server listening on {} (workers: {})", addr, WORKER_THREADS);

    let server = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>());

    if let Err(e) = server.await {
        eprintln!("WSS server fatal error: {}", e);
    }
}

async fn clickhouse_flush_task() {
    let mut interval = tokio::time::interval(Duration::from_secs(CLICKHOUSE_FLUSH_SECS));
    let client = HttpClient::new();
    let mut tick_count: u64 = 0;

    loop {
        interval.tick().await;
        tick_count += 1;

        let saved_deltas = calculate_speeds_and_reset_deltas();

        update_realtime_cache();

        if let Err(e) = flush_to_clickhouse(&client, &saved_deltas).await {
            eprintln!("ClickHouse flush error: {}", e);
        }

        if tick_count % 60 == 0 {
            let active_ips = P2P_STATS.read().unique_ips.clone();
            let mut ip_totals = IP_TOTALS.write();
            ip_totals.retain(|ip, _| active_ips.contains_key(ip));
        }
    }
}

fn calculate_speeds_and_reset_deltas() -> SavedDeltas {
    let mut stats = P2P_STATS.write();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let elapsed_ms = if stats.last_reset_ms > 0 { now_ms.saturating_sub(stats.last_reset_ms) } else { 1000 };
    let elapsed_secs = (elapsed_ms as f64 / 1000.0).max(0.1);

    stats.player1.last_http_speed = (stats.player1.r_http_bytes as f64 / elapsed_secs) as u64;
    stats.player1.last_p2p_speed = (stats.player1.r_p2p_bytes as f64 / elapsed_secs) as u64;
    stats.player1.last_p2p_up_speed = (stats.player1.r_p2p_up_bytes as f64 / elapsed_secs) as u64;
    stats.player2.last_http_speed = (stats.player2.r_http_bytes as f64 / elapsed_secs) as u64;
    stats.player2.last_p2p_speed = (stats.player2.r_p2p_bytes as f64 / elapsed_secs) as u64;
    stats.player2.last_p2p_up_speed = (stats.player2.r_p2p_up_bytes as f64 / elapsed_secs) as u64;

    let saved = SavedDeltas {
        r_http_bytes: stats.r_http_bytes,
        r_p2p_bytes: stats.r_p2p_bytes,
        r_p2p_up_bytes: stats.r_p2p_up_bytes,
        swarm_deltas: stats.swarms.iter().map(|(id, s)| {
            (id.clone(), (s.r_http_bytes, s.r_p2p_bytes, s.r_p2p_up_bytes))
        }).collect(),
    };

    stats.last_reset_ms = now_ms;

    stats.r_http_bytes = 0;
    stats.r_p2p_bytes = 0;
    stats.r_p2p_up_bytes = 0;
    stats.player1.r_http_bytes = 0;
    stats.player1.r_p2p_bytes = 0;
    stats.player1.r_p2p_up_bytes = 0;
    stats.player2.r_http_bytes = 0;
    stats.player2.r_p2p_bytes = 0;
    stats.player2.r_p2p_up_bytes = 0;
    for swarm in stats.swarms.values_mut() {
        swarm.r_http_bytes = 0;
        swarm.r_p2p_bytes = 0;
        swarm.r_p2p_up_bytes = 0;
    }

    saved
}

fn update_realtime_cache() {
    // read()로 블로킹 락 획득 — try_read()는 writer 대기 중일 때 항상 실패하므로
    // 188K+ 동시 연결 환경에서 캐시가 영원히 업데이트되지 않는 버그 발생
    let stats = P2P_STATS.read();
    let response = build_realtime_response_from_stats(&stats);
    drop(stats); // 락 해제
    if let Ok(json) = serde_json::to_string(&response) {
        // lock-free atomic swap
        REALTIME_CACHE.store(Arc::new(json));
    }
}

async fn flush_to_clickhouse(client: &HttpClient, saved: &SavedDeltas) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string();
    let now_escaped = escape_sql(&now);

    let p2p_stats_query = {
        let stats = P2P_STATS.read();
        format!(
            "INSERT INTO p2p_stats VALUES ('{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
            now_escaped,
            stats.viewers,
            stats.unique_ips.len(),
            stats.http_bytes,
            stats.p2p_bytes,
            stats.p2p_up_bytes,
            stats.peers,
            stats.swarms.len(),
            saved.r_http_bytes,
            saved.r_p2p_bytes,
            saved.r_p2p_up_bytes
        )
    };

    let p2p_servers_query = {
        let stats = P2P_STATS.read();
        let mut server_stats: HashMap<String, (u64, u64, u64, u64, u64, u64, u64)> = HashMap::new();
        for (swarm_id, swarm) in stats.swarms.iter() {
            let server = swarm_id.split('.').next().unwrap_or("unknown").to_string();
            let entry = server_stats.entry(server).or_insert((0, 0, 0, 0, 0, 0, 0));
            entry.0 += swarm.http_bytes;
            entry.1 += swarm.p2p_bytes;
            entry.2 += swarm.p2p_up_bytes;
            let swarm_saved = saved.swarm_deltas.get(swarm_id).copied().unwrap_or((0, 0, 0));
            entry.3 += swarm_saved.0;
            entry.4 += swarm_saved.1;
            entry.5 += swarm_saved.2;
            entry.6 += swarm.unique_ips.len() as u64;
        }
        if server_stats.is_empty() {
            None
        } else {
            let values: Vec<String> = server_stats.iter().map(|(server, (http, p2p, p2p_up, r_http, r_p2p, r_p2p_up, viewers))| {
                format!("('{}', {}, {}, {}, {}, '{}', {}, {}, {}, {})",
                    escape_sql(server), viewers, viewers, http, p2p, now_escaped, p2p_up, r_http, r_p2p, r_p2p_up)
            }).collect();
            Some(format!("INSERT INTO p2p_servers VALUES {}", values.join(",")))
        }
    };

    // Collect visitor_logs data
    let visitor_logs_query = {
        let mut logs = VISITOR_LOGS.lock();
        if logs.is_empty() {
            None
        } else {
            let collected: Vec<_> = logs.drain(..).collect();
            let values: Vec<String> = collected.iter().map(|log| {
                format!("('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', {}, '{}', {}, {}, {})",
                    escape_sql(&log.ip), escape_sql(&log.session_id),
                    escape_sql(&log.swarm_id), escape_sql(&log.filename),
                    escape_sql(&log.device), escape_sql(&log.device_name),
                    escape_sql(&log.browser), escape_sql(&log.referrer),
                    escape_sql(&log.net_type), log.player_id, now,
                    log.http_bytes, log.p2p_bytes, log.p2p_up_bytes)
            }).collect();
            Some(format!("INSERT INTO visitor_logs VALUES {}", values.join(",")))
        }
    };

    let queries: Vec<String> = std::iter::once(p2p_stats_query)
        .chain(p2p_servers_query)
        .chain(visitor_logs_query)
        .collect();

    for query in queries {
        for attempt in 0..3u32 {
            match client.post(CLICKHOUSE_URL)
                .timeout(Duration::from_secs(5))
                .body(query.clone())
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => break,
                Ok(resp) => {
                    if attempt == 2 {
                        eprintln!("ClickHouse INSERT failed after 3 attempts: {}", resp.status());
                    }
                }
                Err(e) => {
                    if attempt == 2 {
                        eprintln!("ClickHouse send failed after 3 attempts: {}", e);
                    }
                    tokio::time::sleep(Duration::from_millis(50 * (attempt as u64 + 1))).await;
                }
            }
        }
    }

    Ok(())
}

async fn health() -> String {
    format!("OK - {} connections", TOTAL_CONNECTIONS.load(Ordering::Relaxed))
}

#[derive(Serialize)]
struct RealtimeResponse {
    total: TotalStats,
    player1: PlayerStatsResponse,
    player2: PlayerStatsResponse,
    #[serde(rename = "activeSwarms")]
    active_swarms: usize,
    devices: DevicesResponse,
    #[serde(rename = "deviceNames")]
    device_names: Vec<NameCount>,
    networks: NetworksResponse,
    browsers: Vec<NameCount>,
    referrers: Vec<NameCount>,
    servers: Vec<ServerSwarmStats>,
}

#[derive(Serialize)]
struct TotalStats {
    viewers: u64,
    #[serde(rename = "uniqueUsers")]
    unique_users: u64,
    #[serde(rename = "httpBytes")]
    http_bytes: u64,
    #[serde(rename = "p2pBytes")]
    p2p_bytes: u64,
    #[serde(rename = "p2pUpBytes")]
    p2p_up_bytes: u64,
    peers: u64,
    #[serde(rename = "p2pRatio")]
    p2p_ratio: String,
}

#[derive(Serialize)]
struct PlayerStatsResponse {
    viewers: u64,
    #[serde(rename = "uniqueUsers")]
    unique_users: u64,
    #[serde(rename = "httpBytes")]
    http_bytes: u64,
    #[serde(rename = "p2pBytes")]
    p2p_bytes: u64,
    #[serde(rename = "p2pUpBytes")]
    p2p_up_bytes: u64,
    #[serde(rename = "p2pRatio")]
    p2p_ratio: String,
    #[serde(rename = "rHttpBytes")]
    r_http_bytes: u64,
    #[serde(rename = "rP2pBytes")]
    r_p2p_bytes: u64,
    #[serde(rename = "rP2pUpBytes")]
    r_p2p_up_bytes: u64,
}

#[derive(Serialize)]
struct DevicesResponse {
    mobile: u64,
    desktop: u64,
    tablet: u64,
    unknown: u64,
}

#[derive(Serialize)]
struct NetworksResponse {
    wifi: u64,
    cellular: u64,
    #[serde(rename = "4g")]
    g4: u64,
    #[serde(rename = "5g")]
    g5: u64,
    ethernet: u64,
    unknown: u64,
}

#[derive(Serialize)]
struct NameCount {
    name: String,
    count: u64,
}

#[derive(Serialize)]
struct ServerSwarmStats {
    name: String,
    swarms: u64,
    viewers: u64,
    #[serde(rename = "uniqueUsers")]
    unique_users: u64,
}

// API: 캐시된 응답 즉시 반환 (lock-free)
async fn api_realtime() -> axum::response::Response {
    let cached = REALTIME_CACHE.load();
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(cached.as_str().to_owned()))
        .unwrap()
}

// 스탯에서 응답 빌드 (락은 호출자가 관리)
fn build_realtime_response_from_stats(stats: &P2PStats) -> RealtimeResponse {
    // 서버별 스웜 수 계산
    let mut server_swarm_count: HashMap<String, u64> = HashMap::new();
    for swarm_id in stats.swarms.keys() {
        let server = swarm_id.split('.').next().unwrap_or("unknown").to_string();
        *server_swarm_count.entry(server).or_insert(0) += 1;
    }

    // 서버별 viewers (연결 수) 계산
    let mut server_viewers: HashMap<String, u64> = HashMap::new();
    for (swarm_id, swarm) in stats.swarms.iter() {
        let server = swarm_id.split('.').next().unwrap_or("unknown").to_string();
        *server_viewers.entry(server).or_insert(0) += swarm.viewers;
    }

    let http_bytes = stats.http_bytes;
    let p2p_bytes = stats.p2p_bytes;
    let total_traffic = http_bytes + p2p_bytes;
    let p2p_ratio = if total_traffic > 0 {
        format!("{:.1}", (p2p_bytes as f64 / total_traffic as f64) * 100.0)
    } else { "0".to_string() };

    let p1_total = stats.player1.http_bytes + stats.player1.p2p_bytes;
    let p1_ratio = if p1_total > 0 {
        format!("{:.1}", (stats.player1.p2p_bytes as f64 / p1_total as f64) * 100.0)
    } else { "0".to_string() };

    let p2_total = stats.player2.http_bytes + stats.player2.p2p_bytes;
    let p2_ratio = if p2_total > 0 {
        format!("{:.1}", (stats.player2.p2p_bytes as f64 / p2_total as f64) * 100.0)
    } else { "0".to_string() };

    let mut browsers: Vec<_> = stats.browsers.iter()
        .map(|(k, v)| NameCount { name: k.clone(), count: *v }).collect();
    browsers.sort_by(|a, b| b.count.cmp(&a.count));
    browsers.truncate(10);

    let mut referrers: Vec<_> = stats.referrers.iter()
        .map(|(k, v)| NameCount { name: k.clone(), count: *v }).collect();
    referrers.sort_by(|a, b| b.count.cmp(&a.count));
    referrers.truncate(10);

    let mut device_names: Vec<_> = stats.device_names.iter()
        .map(|(k, v)| NameCount { name: k.clone(), count: *v }).collect();
    device_names.sort_by(|a, b| b.count.cmp(&a.count));
    device_names.truncate(10);

    // 서버별 통계 빌드 (실제 고유 IP 사용)
    let mut servers: Vec<ServerSwarmStats> = server_swarm_count.into_iter()
        .map(|(name, swarms)| {
            let viewers = server_viewers.get(&name).copied().unwrap_or(0);
            let unique_users = stats.server_unique_ips.get(&name).map(|ips| ips.len() as u64).unwrap_or(0);
            ServerSwarmStats { name, swarms, viewers, unique_users }
        })
        .collect();
    servers.sort_by(|a, b| b.swarms.cmp(&a.swarms));

    // stats.viewers = 초기화된 실제 플레이어 세션 수
    // TOTAL_CONNECTIONS = 모든 WebSocket 연결 (초기화 안된 것 포함)
    // unique_ips = 초기화된 세션의 고유 IP
    RealtimeResponse {
        total: TotalStats {
            viewers: stats.viewers,  // 초기화된 세션만 (실제 시청자)
            unique_users: stats.unique_ips.len() as u64,
            http_bytes, p2p_bytes,
            p2p_up_bytes: stats.p2p_up_bytes,
            peers: stats.peers,
            p2p_ratio,
        },
        player1: PlayerStatsResponse {
            viewers: stats.player1.viewers,
            unique_users: stats.player1.unique_ips.len() as u64,
            http_bytes: stats.player1.http_bytes,
            p2p_bytes: stats.player1.p2p_bytes,
            p2p_up_bytes: stats.player1.p2p_up_bytes,
            p2p_ratio: p1_ratio,
            r_http_bytes: stats.player1.last_http_speed,
            r_p2p_bytes: stats.player1.last_p2p_speed,
            r_p2p_up_bytes: stats.player1.last_p2p_up_speed,
        },
        player2: PlayerStatsResponse {
            viewers: stats.player2.viewers,
            unique_users: stats.player2.unique_ips.len() as u64,
            http_bytes: stats.player2.http_bytes,
            p2p_bytes: stats.player2.p2p_bytes,
            p2p_up_bytes: stats.player2.p2p_up_bytes,
            p2p_ratio: p2_ratio,
            r_http_bytes: stats.player2.last_http_speed,
            r_p2p_bytes: stats.player2.last_p2p_speed,
            r_p2p_up_bytes: stats.player2.last_p2p_up_speed,
        },
        active_swarms: stats.swarms.len(),
        devices: DevicesResponse {
            mobile: stats.devices.mobile,
            desktop: stats.devices.desktop,
            tablet: stats.devices.tablet,
            unknown: stats.devices.unknown,
        },
        device_names,
        networks: NetworksResponse {
            wifi: stats.networks.wifi,
            cellular: stats.networks.cellular,
            g4: stats.networks.g4,
            g5: stats.networks.g5,
            ethernet: stats.networks.ethernet,
            unknown: stats.networks.unknown,
        },
        browsers, referrers, servers,
    }
}

#[derive(Serialize)]
struct LiveItem {
    swarm_id: String,
    filename: String,
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
}

#[derive(Serialize)]
struct LiveResponse {
    data: Vec<LiveItem>,
    total: usize,
}

async fn api_live(axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>) -> Json<LiveResponse> {
    let limit: usize = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20);
    let offset: usize = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    let stats = P2P_STATS.read();
    let mut swarms: Vec<_> = stats.swarms.iter()
        .map(|(id, s)| LiveItem {
            swarm_id: id.clone(),
            filename: s.filename.clone(),
            viewers: s.unique_ips.len() as u64,  // 실시간 고유 IP 수
            http_bytes: s.http_bytes,
            p2p_bytes: s.p2p_bytes,
        })
        .collect();

    swarms.sort_by(|a, b| b.viewers.cmp(&a.viewers));
    let total = swarms.len();
    let data: Vec<_> = swarms.into_iter().skip(offset).take(limit).collect();

    Json(LiveResponse { data, total })
}

#[derive(Serialize)]
struct SessionItem {
    session_id: String,
    ip: String,
    filename: String,
    swarm_id: String,
    player_id: u8,
    device: String,
    device_name: String,
    browser: String,
    referrer: String,
    net_type: String,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    r_http_bytes: u64,
    r_p2p_bytes: u64,
    r_p2p_up_bytes: u64,
    peers: u64,
    ip_total: u64,  // 서버시작 후 해당 IP 누적 트래픽
    last_active_secs: u64,  // 마지막 활성시간 (초 전)
}

#[derive(Serialize)]
struct SessionsResponse {
    data: Vec<SessionItem>,
    total: usize,
}

#[derive(Serialize)]
struct IpStatsItem {
    ip: String,
    sessions: u64,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    total: u64,
}

#[derive(Serialize)]
struct IpStatsResponse {
    data: Vec<IpStatsItem>,
    total: usize,
}

async fn api_sessions(axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>) -> Json<SessionsResponse> {
    let limit: usize = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50).min(200);
    let offset: usize = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
    let sort_by = params.get("sort").map(|s| s.as_str()).unwrap_or("http_bytes");
    let search = params.get("search").map(|s| s.to_lowercase());

    let sessions = SESSIONS.read();
    let ip_totals = IP_TOTALS.read();

    // 검색 필터가 없으면 빠른 경로
    let has_search = search.as_ref().map(|s| !s.is_empty()).unwrap_or(false);

    // 참조만 수집 (String 복사 없음)
    let mut refs: Vec<(&String, &Session, i64)> = sessions.iter()
        .filter(|(_, s)| s.initialized)
        .filter(|(id, s)| {
            if !has_search { return true; }
            let q = search.as_ref().unwrap();
            s.user_ip.to_lowercase().contains(q) ||
            s.filename.to_lowercase().contains(q) ||
            s.browser.to_lowercase().contains(q) ||
            s.referrer.to_lowercase().contains(q) ||
            s.device_name.to_lowercase().contains(q) ||
            id.to_lowercase().contains(q)
        })
        .map(|(id, s)| {
            let ts = id.split('_').next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0);
            let key = sort_by.trim_start_matches('-');
            let sort_key = match key {
                "p2p_bytes" => s.p2p_bytes as i64,
                "p2p_up_bytes" => s.p2p_up_bytes as i64,
                "total" => *ip_totals.get(&s.user_ip).unwrap_or(&0) as i64,
                "peers" => s.peers as i64,
                "speed" => (s.r_http_bytes + s.r_p2p_bytes) as i64,
                "connected" => -ts,  // 오래된 순 (oldest first)
                "recent" => ts,      // 최근 순 (newest first)
                _ => s.http_bytes as i64,
            };
            (id, s, sort_key)
        })
        .collect();

    let total = refs.len();

    // 정렬 (- prefix면 오름차순, 아니면 내림차순)
    let ascending = sort_by.starts_with('-');
    if ascending {
        refs.sort_unstable_by(|a, b| a.2.cmp(&b.2));
    } else {
        refs.sort_unstable_by(|a, b| b.2.cmp(&a.2));
    }

    // 페이지네이션 후 SessionItem 생성
    let now = Instant::now();
    let data: Vec<_> = refs.into_iter()
        .skip(offset)
        .take(limit)
        .map(|(id, s, _)| {
            let ip_total = *ip_totals.get(&s.user_ip).unwrap_or(&0);
            SessionItem {
                session_id: id.clone(),
                ip: s.user_ip.clone(),
                filename: s.filename.clone(),
                swarm_id: s.swarm_id.clone(),
                player_id: s.player_id,
                device: s.device.clone(),
                device_name: s.device_name.clone(),
                browser: s.browser.clone(),
                referrer: s.referrer.clone(),
                net_type: s.net_type.clone(),
                http_bytes: s.http_bytes,
                p2p_bytes: s.p2p_bytes,
                p2p_up_bytes: s.p2p_up_bytes,
                r_http_bytes: s.r_http_bytes,
                r_p2p_bytes: s.r_p2p_bytes,
                r_p2p_up_bytes: s.r_p2p_up_bytes,
                peers: s.peers,
                ip_total,
                last_active_secs: now.duration_since(s.last_active).as_secs(),
            }
        })
        .collect();

    Json(SessionsResponse { data, total })
}

async fn api_ip_stats(axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>) -> Json<IpStatsResponse> {
    let limit: usize = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50).min(200);
    let offset: usize = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
    let sort_by = params.get("sort").map(|s| s.as_str()).unwrap_or("total");
    let search = params.get("search").map(|s| s.to_lowercase());

    let sessions = SESSIONS.read();
    let ip_totals = IP_TOTALS.read();

    // IP별로 그룹핑
    let mut ip_map: HashMap<String, (u64, u64, u64, u64)> = HashMap::new();
    for (_, s) in sessions.iter().filter(|(_, s)| s.initialized) {
        let entry = ip_map.entry(s.user_ip.clone()).or_insert((0, 0, 0, 0));
        entry.0 += 1;  // session count
        entry.1 += s.http_bytes;
        entry.2 += s.p2p_bytes;
        entry.3 += s.p2p_up_bytes;
    }

    // 검색 필터 및 정렬
    let has_search = search.as_ref().map(|s| !s.is_empty()).unwrap_or(false);
    let mut items: Vec<_> = ip_map.into_iter()
        .filter(|(ip, _)| !has_search || ip.to_lowercase().contains(search.as_ref().unwrap()))
        .map(|(ip, (sessions, http, p2p, p2p_up))| {
            let total = *ip_totals.get(&ip).unwrap_or(&0);
            let key = sort_by.trim_start_matches('-');
            let sort_key = match key {
                "sessions" => sessions as i64,
                "http_bytes" => http as i64,
                "p2p_bytes" => p2p as i64,
                "p2p_up_bytes" => p2p_up as i64,
                _ => total as i64,
            };
            (ip, sessions, http, p2p, p2p_up, total, sort_key)
        })
        .collect();

    let total_count = items.len();

    // 정렬
    let ascending = sort_by.starts_with('-');
    if ascending {
        items.sort_by(|a, b| a.6.cmp(&b.6));
    } else {
        items.sort_by(|a, b| b.6.cmp(&a.6));
    }

    let data: Vec<_> = items.into_iter()
        .skip(offset)
        .take(limit)
        .map(|(ip, sessions, http, p2p, p2p_up, total, _)| IpStatsItem {
            ip,
            sessions,
            http_bytes: http,
            p2p_bytes: p2p,
            p2p_up_bytes: p2p_up,
            total,
        })
        .collect();

    Json(IpStatsResponse { data, total: total_count })
}

async fn stats() -> Json<serde_json::Value> {
    let start = START_TIME.get_or_init(Instant::now);
    let uptime = start.elapsed().as_secs();

    let sys_mutex = SYSTEM.get_or_init(|| {
        Mutex::new(System::new_with_specifics(
            RefreshKind::new()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything()),
        ))
    });

    let (cpu_usage, mem_used, mem_total) = {
        let mut sys = sys_mutex.lock();
        sys.refresh_cpu();
        sys.refresh_memory();
        let cpu = sys.global_cpu_info().cpu_usage();
        let mem_used = sys.used_memory() / 1024 / 1024;
        let mem_total = sys.total_memory() / 1024 / 1024;
        (cpu, mem_used, mem_total)
    };

    let p2p = P2P_STATS.read();

    Json(serde_json::json!({
        "current_connections": TOTAL_CONNECTIONS.load(Ordering::Relaxed),
        "max_connections": MAX_CONNECTIONS,
        "viewers": p2p.viewers,
        "total_http_bytes": p2p.http_bytes,
        "total_p2p_bytes": p2p.p2p_bytes,
        "cpu_usage": cpu_usage,
        "memory_used_mb": mem_used,
        "memory_total_mb": mem_total,
        "uptime_seconds": uptime,
        "workers": WORKER_THREADS,
        "active_swarms": p2p.swarms.len(),
    }))
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<SocketAddr>,
) -> Response {
    // CF-Connecting-IP (Cloudflare) 우선, 없으면 소켓 IP
    let client_ip = headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    ws.on_upgrade(move |socket| handle_socket(socket, client_ip))
}

async fn handle_socket(socket: WebSocket, client_ip: String) {
    let total = TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if total >= MAX_CONNECTIONS {
        TOTAL_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let session_id = format!("{}_{:016x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
        rand::random::<u64>());

    // Create session with client IP from socket connection
    let mut new_session = Session::default();
    new_session.user_ip = client_ip;
    SESSIONS.write().insert(session_id.clone(), new_session);

    match std::panic::AssertUnwindSafe(handle_socket_inner(socket, session_id.clone()))
        .catch_unwind()
        .await
    {
        Ok(_) => {},
        Err(e) => {
            let msg = e.downcast_ref::<&str>().map(|s| s.to_string())
                .or_else(|| e.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            eprintln!("[PANIC] session {}: {}", session_id, msg);
        }
    }

    cleanup_session(&session_id);
    TOTAL_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

fn cleanup_session(session_id: &str) {
    let session = {
        let mut sessions = SESSIONS.write();
        sessions.remove(session_id)
    };

    if let Some(sess) = session {
        if sess.initialized {
            // 락 밖에서 문자열 연산 수행 (락 범위 최소화)
            let dev = sess.device.to_lowercase();
            let net = sess.net_type.to_lowercase();

            let mut stats = P2P_STATS.write();
            stats.viewers = stats.viewers.saturating_sub(1);
            stats.peers = stats.peers.saturating_sub(sess.peers);

            // Player stats
            if sess.player_id == 1 {
                stats.player1.viewers = stats.player1.viewers.saturating_sub(1);
                if !sess.user_ip.is_empty() {
                    if let Some(count) = stats.player1.unique_ips.get_mut(&sess.user_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            stats.player1.unique_ips.remove(&sess.user_ip);
                        }
                    }
                }
            } else if sess.player_id == 2 {
                stats.player2.viewers = stats.player2.viewers.saturating_sub(1);
                if !sess.user_ip.is_empty() {
                    if let Some(count) = stats.player2.unique_ips.get_mut(&sess.user_ip) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            stats.player2.unique_ips.remove(&sess.user_ip);
                        }
                    }
                }
            }

            // Device stats
            if dev.contains("mobile") || dev.contains("phone") {
                stats.devices.mobile = stats.devices.mobile.saturating_sub(1);
            } else if dev.contains("tablet") || dev.contains("ipad") {
                stats.devices.tablet = stats.devices.tablet.saturating_sub(1);
            } else if dev.contains("desktop") || dev.contains("pc") || dev.contains("web") {
                stats.devices.desktop = stats.devices.desktop.saturating_sub(1);
            } else {
                stats.devices.unknown = stats.devices.unknown.saturating_sub(1);
            }

            // Device name stats
            if !sess.device_name.is_empty() {
                if let Some(count) = stats.device_names.get_mut(&sess.device_name) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        stats.device_names.remove(&sess.device_name);
                    }
                }
            }

            // Network stats
            match net.as_str() {
                "wifi" => stats.networks.wifi = stats.networks.wifi.saturating_sub(1),
                "cellular" => stats.networks.cellular = stats.networks.cellular.saturating_sub(1),
                "4g" => stats.networks.g4 = stats.networks.g4.saturating_sub(1),
                "5g" => stats.networks.g5 = stats.networks.g5.saturating_sub(1),
                "ethernet" => stats.networks.ethernet = stats.networks.ethernet.saturating_sub(1),
                _ => stats.networks.unknown = stats.networks.unknown.saturating_sub(1),
            }

            // Browser
            if !sess.browser.is_empty() {
                if let Some(count) = stats.browsers.get_mut(&sess.browser) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        stats.browsers.remove(&sess.browser);
                    }
                }
            }

            // Referrer
            if !sess.referrer.is_empty() {
                if let Some(count) = stats.referrers.get_mut(&sess.referrer) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        stats.referrers.remove(&sess.referrer);
                    }
                }
            }

            // Unique IP (카운트 감소, 0이면 삭제)
            if !sess.user_ip.is_empty() {
                if let Some(count) = stats.unique_ips.get_mut(&sess.user_ip) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        stats.unique_ips.remove(&sess.user_ip);
                    }
                }
            }

            // Swarm
            if !sess.swarm_id.is_empty() {
                // 서버별 고유 IP 감소
                let server_name = sess.swarm_id.split('.').next().unwrap_or("unknown").to_string();
                if !sess.user_ip.is_empty() {
                    if let Some(server_ips) = stats.server_unique_ips.get_mut(&server_name) {
                        if let Some(count) = server_ips.get_mut(&sess.user_ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                server_ips.remove(&sess.user_ip);
                            }
                        }
                        if server_ips.is_empty() {
                            stats.server_unique_ips.remove(&server_name);
                        }
                    }
                }

                if let Some(swarm) = stats.swarms.get_mut(&sess.swarm_id) {
                    swarm.viewers = swarm.viewers.saturating_sub(1);
                    // IP 카운트 감소
                    if !sess.user_ip.is_empty() {
                        if let Some(count) = swarm.unique_ips.get_mut(&sess.user_ip) {
                            *count = count.saturating_sub(1);
                            if *count == 0 {
                                swarm.unique_ips.remove(&sess.user_ip);
                            }
                        }
                    }
                    if swarm.viewers == 0 {
                        stats.swarms.remove(&sess.swarm_id);
                    }
                }
            }
        }

        // IP_TOTALS 정리: unique_ips에서 해당 IP가 제거되었으면 IP_TOTALS도 제거
        if !sess.user_ip.is_empty() {
            let stats = P2P_STATS.read();
            if !stats.unique_ips.contains_key(&sess.user_ip) {
                drop(stats);
                IP_TOTALS.write().remove(&sess.user_ip);
            }
        }

        // 세션 종료 시 visitor_logs에 트래픽 정보 포함하여 저장
        let mut logs = VISITOR_LOGS.lock();
        if logs.len() >= 10000 {
            let drop_count = logs.len() - 5000;
            eprintln!(
                "[WARN] VISITOR_LOGS overflow: {} entries, dropping oldest {}",
                logs.len(), drop_count
            );
            logs.drain(0..drop_count);
        }
        logs.push(VisitorLog {
            ip: sess.user_ip,
            session_id: session_id.to_string(),
            swarm_id: sess.swarm_id,
            filename: sess.filename,
            device: sess.device,
            device_name: sess.device_name,
            browser: sess.browser,
            referrer: sess.referrer,
            net_type: sess.net_type,
            player_id: sess.player_id,
            http_bytes: sess.http_bytes,
            p2p_bytes: sess.p2p_bytes,
            p2p_up_bytes: sess.p2p_up_bytes,
        });
    }
}

async fn handle_socket_inner(socket: WebSocket, session_id: String) {
    let (mut sender, mut receiver) = socket.split();
    let mut ping_interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
    let idle_deadline = tokio::time::sleep(Duration::from_secs(IDLE_TIMEOUT_SECS));
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            _ = &mut idle_deadline => {
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
            _ = ping_interval.tick() => {
                if sender.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
            incoming = receiver.next() => {
                match incoming {
                    Some(Ok(message)) => {
                        idle_deadline.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(IDLE_TIMEOUT_SECS));
                        match &message {
                            Message::Text(text) => {
                                if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(text) {
                                    if client_msg.msg_type == "ping" {
                                        let _ = sender.send(Message::Text(r#"{"type":"pong"}"#.to_string())).await;
                                    } else {
                                        handle_client_message(&session_id, client_msg);
                                    }
                                }
                            }
                            Message::Ping(data) => {
                                let _ = sender.send(Message::Pong(data.clone())).await;
                            }
                            Message::Close(_) => break,
                            _ => {}
                        }
                    }
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
}

fn handle_client_message(session_id: &str, msg: ClientMessage) {
    match msg.msg_type.as_str() {
        "init" => handle_init(session_id, msg),
        "stats" => handle_stats_update(session_id, msg),
        _ => {}
    }
}

fn handle_init(session_id: &str, msg: ClientMessage) {
    // 세션 데이터를 먼저 복사하고 락 해제 (레이스 컨디션 방지 + 락 범위 최소화)
    let session_data = {
        let mut sessions = SESSIONS.write();
        let session = match sessions.get_mut(session_id) {
            Some(s) => s,
            None => return,
        };

        if session.initialized {
            return; // Already initialized
        }

        session.swarm_id = msg.swarm_id.unwrap_or_default();
        session.player_id = msg.player_id.unwrap_or(0);
        session.filename = msg.filename.unwrap_or_default();
        session.device = msg.device.unwrap_or_else(|| "unknown".to_string());
        session.device_name = msg.device_name.unwrap_or_default();
        session.net_type = msg.net_type.unwrap_or_else(|| "unknown".to_string());
        session.browser = msg.browser.unwrap_or_default();
        session.referrer = extract_hostname(&msg.referrer.unwrap_or_default());
        session.initialized = true;

        // 필요한 데이터 복사 (락 해제 전)
        (
            session.player_id,
            session.user_ip.clone(),
            session.device.clone(),
            session.device_name.clone(),
            session.net_type.clone(),
            session.browser.clone(),
            session.referrer.clone(),
            session.swarm_id.clone(),
            session.filename.clone(),
        )
    }; // SESSIONS 락 해제

    let (player_id, user_ip, device, device_name, net_type, browser, referrer, swarm_id, filename) = session_data;

    // P2P_STATS 업데이트 (복사된 데이터 사용)
    let mut stats = P2P_STATS.write();
    stats.viewers += 1;

    // Player stats
    if player_id == 1 {
        stats.player1.viewers += 1;
        if !user_ip.is_empty() {
            *stats.player1.unique_ips.entry(user_ip.clone()).or_insert(0) += 1;
        }
    } else if player_id == 2 {
        stats.player2.viewers += 1;
        if !user_ip.is_empty() {
            *stats.player2.unique_ips.entry(user_ip.clone()).or_insert(0) += 1;
        }
    }

    // Device stats
    let dev = device.to_lowercase();
    if dev.contains("mobile") || dev.contains("phone") {
        stats.devices.mobile += 1;
    } else if dev.contains("tablet") || dev.contains("ipad") {
        stats.devices.tablet += 1;
    } else if dev.contains("desktop") || dev.contains("pc") || dev.contains("web") {
        stats.devices.desktop += 1;
    } else {
        stats.devices.unknown += 1;
    }

    if !device_name.is_empty() && stats.device_names.len() < MAX_TRACKING_ENTRIES {
        *stats.device_names.entry(device_name).or_insert(0) += 1;
    }

    // Network stats
    let net = net_type.to_lowercase();
    match net.as_str() {
        "wifi" => stats.networks.wifi += 1,
        "cellular" => stats.networks.cellular += 1,
        "4g" => stats.networks.g4 += 1,
        "5g" => stats.networks.g5 += 1,
        "ethernet" => stats.networks.ethernet += 1,
        _ => stats.networks.unknown += 1,
    }

    if !browser.is_empty() && stats.browsers.len() < MAX_TRACKING_ENTRIES {
        *stats.browsers.entry(browser).or_insert(0) += 1;
    }

    if !referrer.is_empty() && stats.referrers.len() < MAX_TRACKING_ENTRIES {
        *stats.referrers.entry(referrer).or_insert(0) += 1;
    }

    // Unique IP (카운트 증가)
    if !user_ip.is_empty() {
        *stats.unique_ips.entry(user_ip.clone()).or_insert(0) += 1;
    }

    // Swarm
    if !swarm_id.is_empty() {
        // 서버별 고유 IP 추적 (swarm_id에서 서버 이름 추출)
        let server_name = swarm_id.split('.').next().unwrap_or("unknown").to_string();
        if !user_ip.is_empty() {
            let server_ips = stats.server_unique_ips.entry(server_name).or_insert_with(HashMap::new);
            *server_ips.entry(user_ip.clone()).or_insert(0) += 1;
        }

        let swarm = stats.swarms.entry(swarm_id).or_insert_with(|| SwarmStats {
            filename,
            ..Default::default()
        });
        swarm.viewers += 1;
        if !user_ip.is_empty() {
            *swarm.unique_ips.entry(user_ip).or_insert(0) += 1;
        }
    }
}

fn handle_stats_update(session_id: &str, msg: ClientMessage) {
    let mut sessions = SESSIONS.write();
    let session = match sessions.get_mut(session_id) {
        Some(s) => s,
        None => return,
    };

    if !session.initialized {
        return;
    }

    let new_peers = msg.peers.unwrap_or(0);
    let peer_diff = new_peers as i64 - session.peers as i64;
    session.peers = new_peers;

    const MAX_DELTA: u64 = 512 * 1024 * 1024; // 512MB per report — clamp untrusted input
    let http_diff = msg.r_http_bytes.unwrap_or(0).min(MAX_DELTA);
    let p2p_diff = msg.r_p2p_bytes.unwrap_or(0).min(MAX_DELTA);
    let up_diff = msg.r_p2p_up_bytes.unwrap_or(0).min(MAX_DELTA);

    session.http_bytes = session.http_bytes.saturating_add(http_diff);
    session.p2p_bytes = session.p2p_bytes.saturating_add(p2p_diff);
    session.p2p_up_bytes = session.p2p_up_bytes.saturating_add(up_diff);
    // Update session delta bytes (for real-time speed display)
    session.r_http_bytes = http_diff;
    session.r_p2p_bytes = p2p_diff;
    session.r_p2p_up_bytes = up_diff;
    // Update last active time
    session.last_active = Instant::now();

    let player_id = session.player_id;
    let swarm_id = session.swarm_id.clone();
    let user_ip = session.user_ip.clone();

    drop(sessions);

    let total_diff = http_diff.saturating_add(p2p_diff);
    if total_diff > 0 {
        let mut ip_totals = IP_TOTALS.write();
        let entry = ip_totals.entry(user_ip).or_insert(0);
        *entry = entry.saturating_add(total_diff);
    }

    let mut stats = P2P_STATS.write();
    stats.http_bytes = stats.http_bytes.saturating_add(http_diff);
    stats.p2p_bytes = stats.p2p_bytes.saturating_add(p2p_diff);
    stats.p2p_up_bytes = stats.p2p_up_bytes.saturating_add(up_diff);
    stats.r_http_bytes = stats.r_http_bytes.saturating_add(http_diff);
    stats.r_p2p_bytes = stats.r_p2p_bytes.saturating_add(p2p_diff);
    stats.r_p2p_up_bytes = stats.r_p2p_up_bytes.saturating_add(up_diff);
    if peer_diff > 0 {
        stats.peers += peer_diff as u64;
    } else {
        stats.peers = stats.peers.saturating_sub((-peer_diff) as u64);
    }

    if player_id == 1 {
        stats.player1.http_bytes = stats.player1.http_bytes.saturating_add(http_diff);
        stats.player1.p2p_bytes = stats.player1.p2p_bytes.saturating_add(p2p_diff);
        stats.player1.p2p_up_bytes = stats.player1.p2p_up_bytes.saturating_add(up_diff);
        stats.player1.r_http_bytes = stats.player1.r_http_bytes.saturating_add(http_diff);
        stats.player1.r_p2p_bytes = stats.player1.r_p2p_bytes.saturating_add(p2p_diff);
        stats.player1.r_p2p_up_bytes = stats.player1.r_p2p_up_bytes.saturating_add(up_diff);
    } else if player_id == 2 {
        stats.player2.http_bytes = stats.player2.http_bytes.saturating_add(http_diff);
        stats.player2.p2p_bytes = stats.player2.p2p_bytes.saturating_add(p2p_diff);
        stats.player2.p2p_up_bytes = stats.player2.p2p_up_bytes.saturating_add(up_diff);
        stats.player2.r_http_bytes = stats.player2.r_http_bytes.saturating_add(http_diff);
        stats.player2.r_p2p_bytes = stats.player2.r_p2p_bytes.saturating_add(p2p_diff);
        stats.player2.r_p2p_up_bytes = stats.player2.r_p2p_up_bytes.saturating_add(up_diff);
    }

    if !swarm_id.is_empty() {
        if let Some(swarm) = stats.swarms.get_mut(&swarm_id) {
            swarm.http_bytes = swarm.http_bytes.saturating_add(http_diff);
            swarm.p2p_bytes = swarm.p2p_bytes.saturating_add(p2p_diff);
            swarm.p2p_up_bytes = swarm.p2p_up_bytes.saturating_add(up_diff);
            swarm.r_http_bytes = swarm.r_http_bytes.saturating_add(http_diff);
            swarm.r_p2p_bytes = swarm.r_p2p_bytes.saturating_add(p2p_diff);
            swarm.r_p2p_up_bytes = swarm.r_p2p_up_bytes.saturating_add(up_diff);
        }
    }
}

fn escape_sql(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

fn extract_hostname(url: &str) -> String {
    if url.is_empty() {
        return "direct".to_string();
    }
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("direct")
        .to_string()
}
