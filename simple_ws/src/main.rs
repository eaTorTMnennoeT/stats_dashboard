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
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};
use tokio::time::timeout;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tower_http::cors::CorsLayer;

const WORKER_THREADS: usize = 72;
const BLOCKING_THREADS: usize = 128;
const MAX_CONNECTIONS: usize = 1_000_000;
const IDLE_TIMEOUT_SECS: u64 = 120;
const PING_INTERVAL_SECS: u64 = 15;
const QUESTDB_ILP_ADDR: &str = "127.0.0.1:9019";
const QUESTDB_FLUSH_SECS: u64 = 1;

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

#[derive(Default)]
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
    }));

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
    // Spawn QuestDB flush task
    tokio::spawn(questdb_flush_task());

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

    server.await.unwrap();
}

async fn questdb_flush_task() {
    let mut interval = tokio::time::interval(Duration::from_secs(QUESTDB_FLUSH_SECS));

    loop {
        interval.tick().await;

        if let Err(e) = flush_to_questdb().await {
            eprintln!("QuestDB flush error: {}", e);
        }
    }
}

async fn flush_to_questdb() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();

    // Collect all data while holding lock, then release
    let lines = {
        let stats = P2P_STATS.read().unwrap();
        let mut lines = Vec::new();

        // p2p_stats - main aggregate stats (cumulative + delta)
        lines.push(format!(
            "p2p_stats viewers={}i,unique_users={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i,peers={}i,swarms={}i,r_http_bytes={}i,r_p2p_bytes={}i,r_p2p_up_bytes={}i {}\n",
            stats.viewers,
            stats.unique_ips.len(),
            stats.http_bytes,
            stats.p2p_bytes,
            stats.p2p_up_bytes,
            stats.peers,
            stats.swarms.len(),
            stats.r_http_bytes,
            stats.r_p2p_bytes,
            stats.r_p2p_up_bytes,
            now_ns
        ));

        // p2p_swarms - per swarm stats (top 50)
        let mut swarms: Vec<_> = stats.swarms.iter().collect();
        swarms.sort_by(|a, b| b.1.unique_ips.len().cmp(&a.1.unique_ips.len()));

        for (swarm_id, swarm) in swarms.iter().take(50) {
            let safe_id = swarm_id.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=");
            let safe_filename = swarm.filename.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=");
            lines.push(format!(
                "p2p_swarms,swarm_id={} filename=\"{}\",viewers={}i,http_bytes={}i,p2p_bytes={}i {}\n",
                safe_id,
                safe_filename.replace("\"", "\\\""),
                swarm.unique_ips.len(),
                swarm.http_bytes,
                swarm.p2p_bytes,
                now_ns
            ));
        }

        // p2p_servers - 서버별 합계 통계 (cumulative + delta)
        let mut server_stats: std::collections::HashMap<String, (u64, u64, u64, u64, u64, u64, u64, std::collections::HashSet<String>)> = std::collections::HashMap::new();
        for (swarm_id, swarm) in stats.swarms.iter() {
            // swarm_id에서 서버명 추출 (예: "every5.poorcdn.com/..." -> "every5")
            let server = swarm_id.split('.').next().unwrap_or("unknown").to_string();
            let entry = server_stats.entry(server).or_insert((0, 0, 0, 0, 0, 0, 0, std::collections::HashSet::new()));
            entry.0 += swarm.http_bytes;
            entry.1 += swarm.p2p_bytes;
            entry.2 += swarm.p2p_up_bytes;
            entry.3 += swarm.r_http_bytes;
            entry.4 += swarm.r_p2p_bytes;
            entry.5 += swarm.r_p2p_up_bytes;
            entry.6 += swarm.unique_ips.len() as u64;
            for ip in swarm.unique_ips.keys() {
                entry.7.insert(ip.clone());
            }
        }
        for (server, (http, p2p, p2p_up, r_http, r_p2p, r_p2p_up, viewers, unique_ips)) in &server_stats {
            lines.push(format!(
                "p2p_servers,server={} viewers={}i,unique_ips={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i,r_http_bytes={}i,r_p2p_bytes={}i,r_p2p_up_bytes={}i {}\n",
                server, viewers, unique_ips.len(), http, p2p, p2p_up, r_http, r_p2p, r_p2p_up, now_ns
            ));
        }

        // p2p_players - 플레이어별 통계
        lines.push(format!(
            "p2p_players,player=1 viewers={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i,r_http_bytes={}i,r_p2p_bytes={}i,r_p2p_up_bytes={}i {}\n",
            stats.player1.viewers, stats.player1.http_bytes, stats.player1.p2p_bytes, stats.player1.p2p_up_bytes,
            stats.player1.r_http_bytes, stats.player1.r_p2p_bytes, stats.player1.r_p2p_up_bytes, now_ns
        ));
        lines.push(format!(
            "p2p_players,player=2 viewers={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i,r_http_bytes={}i,r_p2p_bytes={}i,r_p2p_up_bytes={}i {}\n",
            stats.player2.viewers, stats.player2.http_bytes, stats.player2.p2p_bytes, stats.player2.p2p_up_bytes,
            stats.player2.r_http_bytes, stats.player2.r_p2p_bytes, stats.player2.r_p2p_up_bytes, now_ns
        ));

        // p2p_analytics - devices
        let devices = [
            ("device", "mobile", stats.devices.mobile),
            ("device", "desktop", stats.devices.desktop),
            ("device", "tablet", stats.devices.tablet),
            ("device", "unknown", stats.devices.unknown),
        ];
        for (cat, name, count) in devices {
            if count > 0 {
                lines.push(format!("p2p_analytics,category={},name={} count={}i {}\n", cat, name, count, now_ns));
            }
        }

        // p2p_analytics - networks
        let networks = [
            ("network", "wifi", stats.networks.wifi),
            ("network", "cellular", stats.networks.cellular),
            ("network", "4g", stats.networks.g4),
            ("network", "5g", stats.networks.g5),
            ("network", "ethernet", stats.networks.ethernet),
        ];
        for (cat, name, count) in networks {
            if count > 0 {
                lines.push(format!("p2p_analytics,category={},name={} count={}i {}\n", cat, name, count, now_ns));
            }
        }

        // p2p_analytics - browsers (top 10)
        let mut browsers: Vec<_> = stats.browsers.iter().collect();
        browsers.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in browsers.iter().take(10) {
            let safe_name = name.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=");
            lines.push(format!("p2p_analytics,category=browser,name={} count={}i {}\n", safe_name, count, now_ns));
        }

        // p2p_analytics - referrers (top 10)
        let mut referrers: Vec<_> = stats.referrers.iter().collect();
        referrers.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in referrers.iter().take(10) {
            let safe_name = name.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=");
            lines.push(format!("p2p_analytics,category=referrer,name={} count={}i {}\n", safe_name, count, now_ns));
        }

        lines
    }; // Lock released here

    // Collect visitor logs
    let visitor_lines: Vec<String> = {
        let mut logs = VISITOR_LOGS.lock().unwrap();
        let collected: Vec<_> = logs.drain(..).collect();
        collected.into_iter().map(|log| {
            let safe_ip = log.ip.replace(" ", "\\ ").replace(",", "\\,").replace("=", "\\=");
            let safe_filename = log.filename.replace("\"", "\\\"").replace("\n", " ");
            let safe_device = log.device.replace(" ", "\\ ").replace(",", "\\,");
            let safe_browser = log.browser.replace(" ", "\\ ").replace(",", "\\,");
            let safe_referrer = log.referrer.replace(" ", "\\ ").replace(",", "\\,");
            format!(
                "visitor_logs,ip={} session_id=\"{}\",swarm_id=\"{}\",filename=\"{}\",device=\"{}\",device_name=\"{}\",browser=\"{}\",referrer=\"{}\",net_type=\"{}\",player_id={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i {}\n",
                safe_ip, log.session_id, log.swarm_id, safe_filename, safe_device, log.device_name, safe_browser, safe_referrer, log.net_type, log.player_id, log.http_bytes, log.p2p_bytes, log.p2p_up_bytes, now_ns
            )
        }).collect()
    };

    // Now write to stream without holding the lock
    let mut stream = TcpStream::connect(QUESTDB_ILP_ADDR).await?;
    for line in lines {
        stream.write_all(line.as_bytes()).await?;
    }
    for line in visitor_lines {
        stream.write_all(line.as_bytes()).await?;
    }
    stream.flush().await?;

    // Save last speed values before reset, then reset delta values
    {
        let mut stats = P2P_STATS.write().unwrap();
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Calculate actual elapsed time (avoid divide by zero)
        let elapsed_ms = if stats.last_reset_ms > 0 { now_ms - stats.last_reset_ms } else { 1000 };
        let elapsed_secs = (elapsed_ms as f64 / 1000.0).max(0.1); // Minimum 0.1s to avoid huge numbers

        // Normalize speed: bytes accumulated / actual elapsed seconds = bytes per second
        stats.player1.last_http_speed = (stats.player1.r_http_bytes as f64 / elapsed_secs) as u64;
        stats.player1.last_p2p_speed = (stats.player1.r_p2p_bytes as f64 / elapsed_secs) as u64;
        stats.player1.last_p2p_up_speed = (stats.player1.r_p2p_up_bytes as f64 / elapsed_secs) as u64;
        stats.player2.last_http_speed = (stats.player2.r_http_bytes as f64 / elapsed_secs) as u64;
        stats.player2.last_p2p_speed = (stats.player2.r_p2p_bytes as f64 / elapsed_secs) as u64;
        stats.player2.last_p2p_up_speed = (stats.player2.r_p2p_up_bytes as f64 / elapsed_secs) as u64;

        // Update reset timestamp
        stats.last_reset_ms = now_ms;

        // Reset main delta values
        stats.r_http_bytes = 0;
        stats.r_p2p_bytes = 0;
        stats.r_p2p_up_bytes = 0;
        // Reset per-swarm delta values
        for swarm in stats.swarms.values_mut() {
            swarm.r_http_bytes = 0;
            swarm.r_p2p_bytes = 0;
            swarm.r_p2p_up_bytes = 0;
        }
        // Reset per-player delta values
        stats.player1.r_http_bytes = 0;
        stats.player1.r_p2p_bytes = 0;
        stats.player1.r_p2p_up_bytes = 0;
        stats.player2.r_http_bytes = 0;
        stats.player2.r_p2p_bytes = 0;
        stats.player2.r_p2p_up_bytes = 0;
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

async fn api_realtime() -> Json<RealtimeResponse> {
    let stats = P2P_STATS.read().unwrap();

    // Use pre-computed unique IPs from P2P_STATS (faster than iterating sessions)
    let unique_user_count = stats.unique_ips.len() as u64;

    let total_traffic = stats.http_bytes + stats.p2p_bytes;
    let p2p_ratio = if total_traffic > 0 {
        format!("{:.1}", (stats.p2p_bytes as f64 / total_traffic as f64) * 100.0)
    } else {
        "0".to_string()
    };

    let p1_total = stats.player1.http_bytes + stats.player1.p2p_bytes;
    let p1_ratio = if p1_total > 0 {
        format!("{:.1}", (stats.player1.p2p_bytes as f64 / p1_total as f64) * 100.0)
    } else {
        "0".to_string()
    };

    let p2_total = stats.player2.http_bytes + stats.player2.p2p_bytes;
    let p2_ratio = if p2_total > 0 {
        format!("{:.1}", (stats.player2.p2p_bytes as f64 / p2_total as f64) * 100.0)
    } else {
        "0".to_string()
    };

    let mut browsers: Vec<_> = stats.browsers.iter()
        .map(|(k, v)| NameCount { name: k.clone(), count: *v })
        .collect();
    browsers.sort_by(|a, b| b.count.cmp(&a.count));
    browsers.truncate(10);

    let mut referrers: Vec<_> = stats.referrers.iter()
        .map(|(k, v)| NameCount { name: k.clone(), count: *v })
        .collect();
    referrers.sort_by(|a, b| b.count.cmp(&a.count));
    referrers.truncate(10);

    // 서버별 스웜 통계 (swarm_id에서 서버명 추출)
    let mut server_stats: HashMap<String, (u64, u64, std::collections::HashSet<String>)> = HashMap::new();
    for (swarm_id, swarm) in stats.swarms.iter() {
        let server = swarm_id.split('.').next().unwrap_or("unknown").to_string();
        let entry = server_stats.entry(server).or_insert((0, 0, std::collections::HashSet::new()));
        entry.0 += 1; // swarm count
        entry.1 += swarm.unique_ips.len() as u64; // viewers
        for ip in swarm.unique_ips.keys() {
            entry.2.insert(ip.clone()); // unique IPs
        }
    }
    let mut servers: Vec<ServerSwarmStats> = server_stats.into_iter()
        .map(|(name, (swarms, viewers, unique_ips))| ServerSwarmStats {
            name,
            swarms,
            viewers,
            unique_users: unique_ips.len() as u64,
        })
        .collect();
    servers.sort_by(|a, b| b.swarms.cmp(&a.swarms));

    let current_connections = TOTAL_CONNECTIONS.load(Ordering::Relaxed) as u64;

    Json(RealtimeResponse {
        total: TotalStats {
            viewers: current_connections,
            unique_users: unique_user_count,
            http_bytes: stats.http_bytes,
            p2p_bytes: stats.p2p_bytes,
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
            // Always use last_speed for stable per-second rate
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
            // Always use last_speed for stable per-second rate
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
        device_names: {
            let mut dn: Vec<_> = stats.device_names.iter()
                .map(|(k, v)| NameCount { name: k.clone(), count: *v })
                .collect();
            dn.sort_by(|a, b| b.count.cmp(&a.count));
            dn.truncate(10);
            dn
        },
        networks: NetworksResponse {
            wifi: stats.networks.wifi,
            cellular: stats.networks.cellular,
            g4: stats.networks.g4,
            g5: stats.networks.g5,
            ethernet: stats.networks.ethernet,
            unknown: stats.networks.unknown,
        },
        browsers,
        referrers,
        servers,
    })
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

    let stats = P2P_STATS.read().unwrap();
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

    let sessions = SESSIONS.read().unwrap();
    let ip_totals = IP_TOTALS.read().unwrap();

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

    let sessions = SESSIONS.read().unwrap();
    let ip_totals = IP_TOTALS.read().unwrap();

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
        let mut sys = sys_mutex.lock().unwrap();
        sys.refresh_all();
        let cpu = sys.global_cpu_info().cpu_usage();
        let mem_used = sys.used_memory() / 1024 / 1024;
        let mem_total = sys.total_memory() / 1024 / 1024;
        (cpu, mem_used, mem_total)
    };

    let p2p = P2P_STATS.read().unwrap();

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

    let session_id = format!("{}_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
        rand::random::<u32>());

    // Create session with client IP from socket connection
    let mut new_session = Session::default();
    new_session.user_ip = client_ip;
    SESSIONS.write().unwrap().insert(session_id.clone(), new_session);

    let _ = std::panic::AssertUnwindSafe(handle_socket_inner(socket, session_id.clone()))
        .catch_unwind()
        .await;

    cleanup_session(&session_id);
    TOTAL_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
}

fn cleanup_session(session_id: &str) {
    let session = {
        let mut sessions = SESSIONS.write().unwrap();
        sessions.remove(session_id)
    };

    if let Some(sess) = session {
        if sess.initialized {
            let mut stats = P2P_STATS.write().unwrap();
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
            let dev = sess.device.to_lowercase();
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
            let net = sess.net_type.to_lowercase();
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

        // 세션 종료 시 visitor_logs에 트래픽 정보 포함하여 저장
        if let Ok(mut logs) = VISITOR_LOGS.lock() {
            if logs.len() < 10000 {
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
    }
}

async fn handle_socket_inner(socket: WebSocket, session_id: String) {
    let (mut sender, mut receiver) = socket.split();
    let (ping_tx, mut ping_rx) = tokio::sync::mpsc::channel::<()>(1);

    let ping_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(PING_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if ping_tx.send(()).await.is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            msg = timeout(Duration::from_secs(IDLE_TIMEOUT_SECS), receiver.next()) => {
                match msg {
                    Ok(Some(Ok(message))) => {
                        match &message {
                            Message::Text(text) => {
                                if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(text) {
                                    // ping 메시지면 pong 응답
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
                    Ok(Some(Err(_))) | Ok(None) => break,
                    Err(_) => {
                        let _ = sender.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
            _ = ping_rx.recv() => {
                if sender.send(Message::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    }

    ping_task.abort();
}

fn handle_client_message(session_id: &str, msg: ClientMessage) {
    match msg.msg_type.as_str() {
        "init" => handle_init(session_id, msg),
        "stats" => handle_stats_update(session_id, msg),
        _ => {}
    }
}

fn handle_init(session_id: &str, msg: ClientMessage) {
    let mut sessions = SESSIONS.write().unwrap();
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
    // user_ip is set from CF-Connecting-IP header at connection time
    session.initialized = true;

    drop(sessions);

    // Update global stats
    let mut stats = P2P_STATS.write().unwrap();
    stats.viewers += 1;

    // Player stats
    let session = SESSIONS.read().unwrap();
    let sess = session.get(session_id).unwrap();

    if sess.player_id == 1 {
        stats.player1.viewers += 1;
        if !sess.user_ip.is_empty() {
            *stats.player1.unique_ips.entry(sess.user_ip.clone()).or_insert(0) += 1;
        }
    } else if sess.player_id == 2 {
        stats.player2.viewers += 1;
        if !sess.user_ip.is_empty() {
            *stats.player2.unique_ips.entry(sess.user_ip.clone()).or_insert(0) += 1;
        }
    }

    // Device stats
    let dev = sess.device.to_lowercase();
    if dev.contains("mobile") || dev.contains("phone") {
        stats.devices.mobile += 1;
    } else if dev.contains("tablet") || dev.contains("ipad") {
        stats.devices.tablet += 1;
    } else if dev.contains("desktop") || dev.contains("pc") || dev.contains("web") {
        stats.devices.desktop += 1;
    } else {
        stats.devices.unknown += 1;
    }

    // Device name stats
    if !sess.device_name.is_empty() {
        *stats.device_names.entry(sess.device_name.clone()).or_insert(0) += 1;
    }

    // Network stats
    let net = sess.net_type.to_lowercase();
    match net.as_str() {
        "wifi" => stats.networks.wifi += 1,
        "cellular" => stats.networks.cellular += 1,
        "4g" => stats.networks.g4 += 1,
        "5g" => stats.networks.g5 += 1,
        "ethernet" => stats.networks.ethernet += 1,
        _ => stats.networks.unknown += 1,
    }

    // Browser
    if !sess.browser.is_empty() {
        *stats.browsers.entry(sess.browser.clone()).or_insert(0) += 1;
    }

    // Referrer
    if !sess.referrer.is_empty() {
        *stats.referrers.entry(sess.referrer.clone()).or_insert(0) += 1;
    }

    // Unique IP (카운트 증가)
    if !sess.user_ip.is_empty() {
        *stats.unique_ips.entry(sess.user_ip.clone()).or_insert(0) += 1;
    }

    // Swarm
    if !sess.swarm_id.is_empty() {
        let swarm = stats.swarms.entry(sess.swarm_id.clone()).or_insert_with(|| SwarmStats {
            filename: sess.filename.clone(),
            ..Default::default()
        });
        swarm.viewers += 1;
        if !sess.user_ip.is_empty() {
            *swarm.unique_ips.entry(sess.user_ip.clone()).or_insert(0) += 1;
        }
    }

    // visitor_logs는 세션 종료 시 cleanup_session에서 저장 (트래픽 정보 포함)
}

fn handle_stats_update(session_id: &str, msg: ClientMessage) {
    let mut sessions = SESSIONS.write().unwrap();
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

    // r* 필드만 사용 (delta) - 구 클라이언트는 무시됨
    let http_diff = msg.r_http_bytes.unwrap_or(0);
    let p2p_diff = msg.r_p2p_bytes.unwrap_or(0);
    let up_diff = msg.r_p2p_up_bytes.unwrap_or(0);

    // Update session cumulative bytes
    session.http_bytes += http_diff;
    session.p2p_bytes += p2p_diff;
    session.p2p_up_bytes += up_diff;
    // Update session delta bytes (for real-time speed display)
    session.r_http_bytes = http_diff;
    session.r_p2p_bytes = p2p_diff;
    session.r_p2p_up_bytes = up_diff;

    let player_id = session.player_id;
    let swarm_id = session.swarm_id.clone();
    let user_ip = session.user_ip.clone();

    drop(sessions);

    // Update IP totals (서버 시작 후 IP별 누적)
    let total_diff = http_diff + p2p_diff;
    if total_diff > 0 {
        let mut ip_totals = IP_TOTALS.write().unwrap();
        *ip_totals.entry(user_ip).or_insert(0) += total_diff;
    }

    // Update global stats
    let mut stats = P2P_STATS.write().unwrap();
    stats.http_bytes += http_diff;
    stats.p2p_bytes += p2p_diff;
    stats.p2p_up_bytes += up_diff;
    // Delta tracking for current interval
    stats.r_http_bytes += http_diff;
    stats.r_p2p_bytes += p2p_diff;
    stats.r_p2p_up_bytes += up_diff;
    if peer_diff > 0 {
        stats.peers += peer_diff as u64;
    } else {
        stats.peers = stats.peers.saturating_sub((-peer_diff) as u64);
    }

    // Player stats
    if player_id == 1 {
        stats.player1.http_bytes += http_diff;
        stats.player1.p2p_bytes += p2p_diff;
        stats.player1.p2p_up_bytes += up_diff;
        stats.player1.r_http_bytes += http_diff;
        stats.player1.r_p2p_bytes += p2p_diff;
        stats.player1.r_p2p_up_bytes += up_diff;
    } else if player_id == 2 {
        stats.player2.http_bytes += http_diff;
        stats.player2.p2p_bytes += p2p_diff;
        stats.player2.p2p_up_bytes += up_diff;
        stats.player2.r_http_bytes += http_diff;
        stats.player2.r_p2p_bytes += p2p_diff;
        stats.player2.r_p2p_up_bytes += up_diff;
    }

    // Swarm stats
    if !swarm_id.is_empty() {
        if let Some(swarm) = stats.swarms.get_mut(&swarm_id) {
            swarm.http_bytes += http_diff;
            swarm.p2p_bytes += p2p_diff;
            swarm.p2p_up_bytes += up_diff;
            swarm.r_http_bytes += http_diff;
            swarm.r_p2p_bytes += p2p_diff;
            swarm.r_p2p_up_bytes += up_diff;
        }
    }
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
