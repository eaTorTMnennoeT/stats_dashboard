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
const IDLE_TIMEOUT_SECS: u64 = 60;
const PING_INTERVAL_SECS: u64 = 30;
const QUESTDB_ILP_ADDR: &str = "127.0.0.1:9019";
const QUESTDB_FLUSH_SECS: u64 = 10;

// Global stats
static TOTAL_CONNECTIONS: AtomicUsize = AtomicUsize::new(0);
static SYSTEM: std::sync::OnceLock<Mutex<System>> = std::sync::OnceLock::new();
static START_TIME: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

// P2P Stats
lazy_static::lazy_static! {
    static ref P2P_STATS: Arc<RwLock<P2PStats>> = Arc::new(RwLock::new(P2PStats::default()));
    static ref SESSIONS: Arc<RwLock<HashMap<String, Session>>> = Arc::new(RwLock::new(HashMap::new()));
}

#[derive(Default)]
struct P2PStats {
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    peers: u64,
    player1: PlayerStats,
    player2: PlayerStats,
    devices: DeviceStats,
    device_names: HashMap<String, u64>,
    networks: NetworkStats,
    browsers: HashMap<String, u64>,
    referrers: HashMap<String, u64>,
    swarms: HashMap<String, SwarmStats>,
    unique_ips: std::collections::HashSet<String>,
}

#[derive(Default, Clone)]
struct PlayerStats {
    viewers: u64,
    http_bytes: u64,
    p2p_bytes: u64,
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
    unique_ips: std::collections::HashSet<String>,
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
        .layer(CorsLayer::permissive());

    let tls_config = RustlsConfig::from_pem_file("certs/cert.pem", "certs/key.pem")
        .await
        .expect("Failed to load TLS config");

    let addr = SocketAddr::from(([0, 0, 0, 0], 8443));
    eprintln!("WSS server listening on {} (workers: {})", addr, WORKER_THREADS);

    let server = axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service());

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

        // p2p_stats - main aggregate stats
        lines.push(format!(
            "p2p_stats viewers={}i,unique_users={}i,http_bytes={}i,p2p_bytes={}i,p2p_up_bytes={}i,peers={}i,swarms={}i {}\n",
            stats.viewers,
            stats.unique_ips.len(),
            stats.http_bytes,
            stats.p2p_bytes,
            stats.p2p_up_bytes,
            stats.peers,
            stats.swarms.len(),
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

    // Now write to stream without holding the lock
    let mut stream = TcpStream::connect(QUESTDB_ILP_ADDR).await?;
    for line in lines {
        stream.write_all(line.as_bytes()).await?;
    }
    stream.flush().await?;
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
    #[serde(rename = "httpBytes")]
    http_bytes: u64,
    #[serde(rename = "p2pBytes")]
    p2p_bytes: u64,
    #[serde(rename = "p2pRatio")]
    p2p_ratio: String,
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

async fn api_realtime() -> Json<RealtimeResponse> {
    let stats = P2P_STATS.read().unwrap();

    // Calculate real-time unique users from active sessions
    let realtime_unique_ips: std::collections::HashSet<String> = {
        let sessions = SESSIONS.read().unwrap();
        sessions.values()
            .filter(|s| s.initialized && !s.user_ip.is_empty())
            .map(|s| s.user_ip.clone())
            .collect()
    };

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

    let current_connections = TOTAL_CONNECTIONS.load(Ordering::Relaxed) as u64;

    Json(RealtimeResponse {
        total: TotalStats {
            viewers: current_connections,
            unique_users: realtime_unique_ips.len() as u64,
            http_bytes: stats.http_bytes,
            p2p_bytes: stats.p2p_bytes,
            p2p_up_bytes: stats.p2p_up_bytes,
            peers: stats.peers,
            p2p_ratio,
        },
        player1: PlayerStatsResponse {
            viewers: stats.player1.viewers,
            http_bytes: stats.player1.http_bytes,
            p2p_bytes: stats.player1.p2p_bytes,
            p2p_ratio: p1_ratio,
        },
        player2: PlayerStatsResponse {
            viewers: stats.player2.viewers,
            http_bytes: stats.player2.http_bytes,
            p2p_bytes: stats.player2.p2p_bytes,
            p2p_ratio: p2_ratio,
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
            viewers: s.unique_ips.len() as u64,
            http_bytes: s.http_bytes,
            p2p_bytes: s.p2p_bytes,
        })
        .collect();

    swarms.sort_by(|a, b| b.viewers.cmp(&a.viewers));
    let total = swarms.len();
    let data: Vec<_> = swarms.into_iter().skip(offset).take(limit).collect();

    Json(LiveResponse { data, total })
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

async fn ws_handler(ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(handle_socket)
}

async fn handle_socket(socket: WebSocket) {
    let total = TOTAL_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    if total >= MAX_CONNECTIONS {
        TOTAL_CONNECTIONS.fetch_sub(1, Ordering::Relaxed);
        return;
    }

    let session_id = format!("{}_{}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis(),
        rand::random::<u32>());

    SESSIONS.write().unwrap().insert(session_id.clone(), Session::default());

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
            } else if sess.player_id == 2 {
                stats.player2.viewers = stats.player2.viewers.saturating_sub(1);
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

            // Swarm
            if !sess.swarm_id.is_empty() {
                if let Some(swarm) = stats.swarms.get_mut(&sess.swarm_id) {
                    swarm.viewers = swarm.viewers.saturating_sub(1);
                    if swarm.viewers == 0 {
                        stats.swarms.remove(&sess.swarm_id);
                    }
                }
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
                                    handle_client_message(&session_id, client_msg);
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
    session.user_ip = msg.user_ip.unwrap_or_default();
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
    } else if sess.player_id == 2 {
        stats.player2.viewers += 1;
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

    // Unique IP
    if !sess.user_ip.is_empty() {
        stats.unique_ips.insert(sess.user_ip.clone());
    }

    // Swarm
    if !sess.swarm_id.is_empty() {
        let swarm = stats.swarms.entry(sess.swarm_id.clone()).or_insert_with(|| SwarmStats {
            filename: sess.filename.clone(),
            ..Default::default()
        });
        swarm.viewers += 1;
        if !sess.user_ip.is_empty() {
            swarm.unique_ips.insert(sess.user_ip.clone());
        }
    }
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

    let new_http = msg.http_bytes.unwrap_or(0);
    let new_p2p = msg.p2p_bytes.unwrap_or(0);
    let new_up = msg.p2p_up_bytes.unwrap_or(0);
    let new_peers = msg.peers.unwrap_or(0);

    let http_diff = new_http.saturating_sub(session.http_bytes);
    let p2p_diff = new_p2p.saturating_sub(session.p2p_bytes);
    let up_diff = new_up.saturating_sub(session.p2p_up_bytes);
    let peer_diff = new_peers as i64 - session.peers as i64;

    session.http_bytes = new_http;
    session.p2p_bytes = new_p2p;
    session.p2p_up_bytes = new_up;
    session.peers = new_peers;

    let player_id = session.player_id;
    let swarm_id = session.swarm_id.clone();

    drop(sessions);

    // Update global stats
    let mut stats = P2P_STATS.write().unwrap();
    stats.http_bytes += http_diff;
    stats.p2p_bytes += p2p_diff;
    stats.p2p_up_bytes += up_diff;
    if peer_diff > 0 {
        stats.peers += peer_diff as u64;
    } else {
        stats.peers = stats.peers.saturating_sub((-peer_diff) as u64);
    }

    // Player stats
    if player_id == 1 {
        stats.player1.http_bytes += http_diff;
        stats.player1.p2p_bytes += p2p_diff;
    } else if player_id == 2 {
        stats.player2.http_bytes += http_diff;
        stats.player2.p2p_bytes += p2p_diff;
    }

    // Swarm stats
    if !swarm_id.is_empty() {
        if let Some(swarm) = stats.swarms.get_mut(&swarm_id) {
            swarm.http_bytes += http_diff;
            swarm.p2p_bytes += p2p_diff;
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
