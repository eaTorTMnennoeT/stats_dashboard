use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Query, State,
    },
    http::{Request, StatusCode, HeaderMap},
    response::{IntoResponse, Response, Redirect},
    routing::{get, post},
    middleware::{self, Next},
    body::Body,
    Json, Router,
};
use chrono::{Datelike, FixedOffset, Timelike, Utc};
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use redis::AsyncCommands;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Semaphore};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::{cors::CorsLayer, services::ServeDir};

const SIMPLE_WS_URL: &str = "http://127.0.0.1:8444";
const QUESTDB_URL: &str = "http://127.0.0.1:9002";
const DRAGONFLY_URL: &str = "redis://127.0.0.1:6379";

// 캐시 엔트리
struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

// 전역 상태
lazy_static::lazy_static! {
    // 외부 서버 관리
    static ref EXTERNAL_SERVERS: Arc<RwLock<HashMap<String, ExternalServer>>> = Arc::new(RwLock::new(HashMap::new()));
    // Abuser API 캐시 (period -> (data, expires_at))
    static ref ABUSER_CACHE: Arc<RwLock<HashMap<String, CacheEntry<serde_json::Value>>>> = Arc::new(RwLock::new(HashMap::new()));
    // Summary API 캐시 (10초 TTL)
    static ref SUMMARY_CACHE: Arc<RwLock<Option<CacheEntry<serde_json::Value>>>> = Arc::new(RwLock::new(None));
    // 무거운 쿼리 동시 실행 제한 (최대 2개)
    static ref HEAVY_QUERY_SEMAPHORE: Arc<Semaphore> = Arc::new(Semaphore::new(2));
    // 에이전트 최신 버전
    static ref AGENT_LATEST_VERSION: Arc<RwLock<String>> = Arc::new(RwLock::new("37".to_string()));
    // 서버 이벤트 (메모리)
    static ref SERVER_EVENTS: Arc<RwLock<Vec<ServerEvent>>> = Arc::new(RwLock::new(Vec::new()));
    // Cloudflare 설정
    static ref CF_SETTINGS: Arc<RwLock<CloudflareSettings>> = Arc::new(RwLock::new(CloudflareSettings::default()));
    // 차단 대기 명령
    static ref PENDING_BLOCKS: Arc<RwLock<HashMap<String, BlockCommand>>> = Arc::new(RwLock::new(HashMap::new()));
    // IP별 차단된 서버 목록
    static ref BLOCKED_SERVERS: Arc<RwLock<HashMap<String, BlockCommand>>> = Arc::new(RwLock::new(HashMap::new()));
    // 세션 저장소 (session_id -> username)
    static ref SESSIONS: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    // 에이전트 시크릿 키
    static ref AGENT_SECRET: Arc<RwLock<String>> = Arc::new(RwLock::new(String::new()));
}

#[derive(Clone, serde::Serialize, serde::Deserialize, Default)]
struct ExternalServer {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    blocked_ips: Vec<String>,
    // 시스템 상태
    #[serde(default)]
    cpu: f64,
    #[serde(default)]
    memory_used: u64,
    #[serde(default)]
    memory_total: u64,
    #[serde(default)]
    disk_used: u64,
    #[serde(default)]
    disk_total: u64,
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    connections: u64,
    #[serde(default)]
    uptime: u64,
    #[serde(default)]
    online: bool,
}

#[derive(Clone, serde::Serialize)]
struct ServerEvent {
    server: String,
    message: String,
    timestamp: u64,
}

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
struct CloudflareSettings {
    enabled: bool,
    email: String,
    api_key: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BlockCommand {
    ip: String,
    reason: String,
    created_at: String,
    cf_blocked: bool,
    servers_blocked: Vec<String>,
}

// 비밀번호 해시
fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hex::encode(hasher.finalize())
}

// DB에서 인증 확인
async fn verify_credentials(username: &str, password: &str) -> bool {
    let client = reqwest::Client::new();
    let password_hash = hash_password(password);
    let query = format!(
        "SELECT password_hash FROM dashboard_users WHERE username = '{}' LIMIT 1",
        username.replace("'", "''")
    );
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(rows) = data.get("dataset").and_then(|d| d.as_array()) {
                if let Some(row) = rows.first() {
                    if let Some(stored_hash) = row.get(0).and_then(|v| v.as_str()) {
                        return stored_hash == password_hash;
                    }
                }
            }
        }
    }
    false
}

// 사용자 테이블 초기화
async fn ensure_users_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS dashboard_users (username STRING, password_hash STRING, created_at TIMESTAMP) timestamp(created_at)";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;

    // admin 계정 확인
    let check_query = "SELECT count() FROM dashboard_users WHERE username = 'admin'";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(check_query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(count) = data.get("dataset").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_i64()) {
                if count == 0 {
                    let pw_hash = hash_password("tlqkf123@");
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
                    let insert = format!(
                        "INSERT INTO dashboard_users VALUES('admin', '{}', '{}')",
                        pw_hash, now
                    );
                    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&insert));
                    let _ = client.get(&url).send().await;
                }
            }
        }
    }
}

// 서버 이벤트 테이블 초기화
async fn ensure_server_events_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS server_events (timestamp TIMESTAMP, server STRING, message STRING) timestamp(timestamp)";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;
}

// 에이전트 설정 테이블 초기화
async fn ensure_agent_settings_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS agent_settings (key STRING, value STRING, updated_at TIMESTAMP) timestamp(updated_at)";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;

    // 기본 시크릿 생성
    let check_query = "SELECT count() FROM agent_settings WHERE key = 'secret'";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(check_query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(count) = data.get("dataset").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_i64()) {
                if count == 0 {
                    let secret = format!("{:x}", rand::random::<u128>());
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
                    let insert = format!(
                        "INSERT INTO agent_settings VALUES('secret', '{}', '{}')",
                        secret, now
                    );
                    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&insert));
                    let _ = client.get(&url).send().await;
                }
            }
        }
    }
}

// 에이전트 시크릿 로드
async fn load_agent_secret(client: &Client) {
    let query = "SELECT value FROM agent_settings WHERE key = 'secret' LIMIT 1";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(secret) = data.get("dataset").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_str()) {
                let mut s = AGENT_SECRET.write();
                *s = secret.to_string();
            }
        }
    }
}

// CF 설정 로드 (파일에서)
fn load_cf_settings() {
    if let Ok(content) = std::fs::read_to_string("data/cf_settings.json") {
        if let Ok(settings) = serde_json::from_str::<CloudflareSettings>(&content) {
            *CF_SETTINGS.write() = settings;
        }
    }
}

// 블랙리스트 로드 (파일에서)
fn load_blocked_list() {
    if let Ok(content) = std::fs::read_to_string("data/blocked_ips.json") {
        if let Ok(map) = serde_json::from_str::<HashMap<String, BlockCommand>>(&content) {
            *BLOCKED_SERVERS.write() = map;
        }
    }
}

// 서버 테이블 초기화
async fn ensure_servers_table(client: &Client) {
    // 서버 정보 테이블 (LATEST BY로 최신 값만 조회)
    let create_query = "CREATE TABLE IF NOT EXISTS dashboard_servers (\
        server_id STRING, name STRING, ip STRING, url STRING, version STRING, \
        updated_at TIMESTAMP) timestamp(updated_at) PARTITION BY MONTH";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;
}

// 세션 테이블 초기화
async fn ensure_sessions_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS dashboard_sessions (\
        session_id STRING, username STRING, created_at TIMESTAMP) timestamp(created_at) PARTITION BY MONTH";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;
}

// 세션 로드 (DB에서) - 최근 7일 세션만
async fn load_sessions_from_db(client: &Client) {
    let query = "SELECT session_id, username FROM dashboard_sessions \
        WHERE created_at > dateadd('d', -7, now())";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(query));

    match client.get(&url).send().await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(data) => {
                    if let Some(rows) = data.get("dataset").and_then(|d| d.as_array()) {
                        let mut sessions = SESSIONS.write();
                        for row in rows {
                            let session_id = row.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                            let username = row.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                            if !session_id.is_empty() {
                                sessions.insert(session_id, username);
                            }
                        }
                        eprintln!("Loaded {} sessions from database", sessions.len());
                    } else {
                        eprintln!("No dataset in sessions response");
                    }
                }
                Err(e) => eprintln!("Failed to parse sessions JSON: {}", e),
            }
        }
        Err(e) => eprintln!("Failed to load sessions: {}", e),
    }
}

// 세션 저장 (DB로)
fn save_session_to_db(session_id: &str, username: &str) {
    let session_id = session_id.to_string();
    let username = username.to_string();
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let query = format!(
            "INSERT INTO dashboard_sessions VALUES('{}', '{}', '{}')",
            session_id.replace("'", "''"),
            username.replace("'", "''"),
            now
        );
        let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));
        let _ = client.get(&url).send().await;
    });
}

// 서버 목록 로드 (DB에서)
async fn load_servers_from_db(client: &Client) {
    let query = "SELECT server_id, name, ip, url, version FROM dashboard_servers LATEST BY server_id";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(rows) = data.get("dataset").and_then(|d| d.as_array()) {
                let mut server_map = EXTERNAL_SERVERS.write();
                for row in rows {
                    let server_id = row.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let name = row.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let ip = row.get(2).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let url = row.get(3).and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let version = row.get(4).and_then(|v| v.as_str()).unwrap_or("").to_string();

                    if !server_id.is_empty() {
                        server_map.insert(server_id.clone(), ExternalServer {
                            id: server_id,
                            name,
                            ip,
                            url,
                            version,
                            online: false,
                            ..Default::default()
                        });
                    }
                }
                eprintln!("Loaded {} servers from database", server_map.len());
            }
        }
    }
}

// 서버 정보 저장 (DB로) - 백그라운드 태스크로 실행
fn save_server_to_db(server: &ExternalServer) {
    let server_id = server.id.clone();
    let name = server.name.clone();
    let ip = server.ip.clone();
    let url = server.url.clone();
    let version = server.version.clone();

    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
        let query = format!(
            "INSERT INTO dashboard_servers VALUES('{}', '{}', '{}', '{}', '{}', '{}')",
            server_id.replace("'", "''"),
            name.replace("'", "''"),
            ip.replace("'", "''"),
            url.replace("'", "''"),
            version.replace("'", "''"),
            now
        );
        let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));
        let _ = client.get(&url).send().await;
    });
}

// 에이전트 시크릿 검증
fn verify_agent_secret(provided: &str) -> bool {
    let secret = AGENT_SECRET.read();
    !secret.is_empty() && secret.as_str() == provided
}

// 서버 이벤트 추가
fn add_server_event(server: &str, message: &str) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let event = ServerEvent {
        server: server.to_string(),
        message: message.to_string(),
        timestamp,
    };

    let mut events = SERVER_EVENTS.write();
    events.push(event);
    if events.len() > 100 {
        events.remove(0);
    }

    // QuestDB에 영구 저장
    let srv = server.replace("'", "''");
    let msg = message.replace("'", "''");
    tokio::spawn(async move {
        let query = format!(
            "INSERT INTO server_events VALUES({}000, '{}', '{}')",
            timestamp, srv, msg
        );
        let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));
        let _ = reqwest::Client::new().get(&url).send().await;
    });
}

#[derive(Clone)]
struct AppState {
    client: Client,
    tx: broadcast::Sender<String>,
    redis: redis::aio::ConnectionManager,
}

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(60))  // 복잡한 쿼리를 위해 60초로 증가
        .build()
        .unwrap();

    // Dragonfly (Redis) 연결
    let redis_client = redis::Client::open(DRAGONFLY_URL).expect("Invalid Redis URL");
    let redis = redis::aio::ConnectionManager::new(redis_client)
        .await
        .expect("Failed to connect to Dragonfly");

    let (tx, _) = broadcast::channel::<String>(100);
    let state = AppState {
        client: client.clone(),
        tx: tx.clone(),
        redis,
    };

    // 데이터 디렉토리 생성
    let _ = std::fs::create_dir_all("data");

    // 테이블 초기화
    ensure_hourly_stats_table(&client).await;
    ensure_users_table(&client).await;
    ensure_server_events_table(&client).await;
    ensure_agent_settings_table(&client).await;
    ensure_servers_table(&client).await;
    ensure_sessions_table(&client).await;

    // 설정 로드
    load_agent_secret(&client).await;
    load_cf_settings();
    load_blocked_list();
    load_servers_from_db(&client).await;
    load_sessions_from_db(&client).await;

    eprintln!("All tables and settings initialized");

    // Background task: 과거 데이터 디비화 - 일시 비활성화
    // 이미 hourly_stats에 5500+ 행 있음, 나중에 필요하면 재활성화
    eprintln!("Historical data aggregation DISABLED (data already exists)");

    // Background task: poll simple_ws and broadcast to all clients
    let poll_client = client.clone();
    let poll_tx = tx.clone();
    tokio::spawn(async move {
        loop {
            if let Ok(resp) = poll_client
                .get(format!("{}/api/realtime", SIMPLE_WS_URL))
                .send()
                .await
            {
                if let Ok(body) = resp.text().await {
                    let _ = poll_tx.send(body);
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    });

    // Background task: 캐시 정리 (5분마다)
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await;
            // Abuser 캐시 정리
            {
                let mut cache = ABUSER_CACHE.write();
                let now = Instant::now();
                cache.retain(|_, entry| entry.expires_at > now);
            }
        }
    });


    // Background task: 일별 집계 + 오래된 파티션 삭제 (1시간마다)
    let agg_client = client.clone();
    tokio::spawn(async move {
        // 시작 시 2분 대기 (서버 안정화)
        tokio::time::sleep(Duration::from_secs(120)).await;
        loop {
            // 1. 어제 데이터를 일별 집계 테이블로 저장
            let daily_agg_query = r#"
                INSERT INTO nginx_daily_agg
                SELECT
                    timestamp_floor('d', timestamp) as day,
                    client_ip,
                    count() as total_requests,
                    sum(bytes_sent) as total_bytes,
                    count_distinct(path) as unique_paths,
                    count_distinct(server_id) as server_count,
                    0 as max_burst,
                    min(timestamp) as first_seen,
                    max(timestamp) as last_seen
                FROM nginx_logs
                WHERE timestamp >= dateadd('d', -2, timestamp_floor('d', now()))
                  AND timestamp < timestamp_floor('d', now())
                GROUP BY day, client_ip
            "#;

            if let Ok(resp) = agg_client.get("http://localhost:9002/exec")
                .query(&[("query", daily_agg_query)])
                .timeout(Duration::from_secs(300))
                .send()
                .await
            {
                if resp.status().is_success() {
                    eprintln!("[Aggregation] Daily aggregation completed");
                }
            }

            // 2. 2일 이상 된 파티션 삭제 (집계 완료된 데이터)
            let partitions_query = "SELECT name FROM table_partitions('nginx_logs')";
            if let Ok(resp) = agg_client.get("http://localhost:9002/exec")
                .query(&[("query", partitions_query)])
                .timeout(Duration::from_secs(30))
                .send()
                .await
            {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    if let Some(dataset) = data["dataset"].as_array() {
                        let cutoff = (chrono::Utc::now() - chrono::Duration::days(2))
                            .format("%Y-%m-%d").to_string();

                        for row in dataset {
                            if let Some(name) = row[0].as_str() {
                                // YYYY-MM-DD 형식만 처리 (조각 파티션 제외)
                                if name.len() == 10 && name < cutoff.as_str() {
                                    let drop_query = format!(
                                        "ALTER TABLE nginx_logs DROP PARTITION LIST '{}'", name
                                    );
                                    if let Ok(_) = agg_client.get("http://localhost:9002/exec")
                                        .query(&[("query", &drop_query)])
                                        .timeout(Duration::from_secs(60))
                                        .send()
                                        .await
                                    {
                                        eprintln!("[Cleanup] Dropped old partition: {} (aggregated)", name);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 1시간마다 실행
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        // 인증
        .route("/login", get(login_page))
        .route("/auth/login", post(auth_login))
        .route("/auth/logout", post(auth_logout))
        .route("/auth/check", get(auth_check))
        // 기존 API
        .route("/api/realtime", get(proxy_realtime))
        .route("/api/live", get(proxy_live))
        .route("/api/sessions", get(proxy_sessions))
        .route("/api/ip_stats", get(proxy_ip_stats))
        .route("/api/stats", get(proxy_stats))
        .route("/api/history/stats", get(history_stats))
        .route("/api/history/swarms", get(history_swarms))
        .route("/api/history/hourly", get(history_hourly))
        .route("/api/popular", get(api_popular))
        .route("/api/summary", get(api_summary))
        .route("/api/init-data", get(api_init_data))
        .route("/api/visitors", get(api_visitors))
        .route("/api/traffic", get(api_traffic))
        .route("/api/servers/realtime", get(api_servers_realtime))
        .route("/api/server-time", get(api_server_time))
        .route("/api/ip-analysis", get(api_ip_analysis))
        // 서버 관리
        .route("/api/servers", get(api_servers_list))
        .route("/api/servers/status", post(api_servers_status))
        .route("/api/servers/report", post(api_servers_status))  // 에이전트 호환
        .route("/api/servers/events", get(api_servers_events))
        .route("/api/servers/:id/name", axum::routing::put(api_server_update_name))
        // 블랙리스트
        .route("/api/blacklist", get(api_blacklist_list))
        .route("/api/blacklist/block", post(api_blacklist_block))
        .route("/api/blacklist/unblock", post(api_blacklist_unblock))
        .route("/api/blacklist/pending", get(api_blacklist_pending))
        .route("/api/blacklist/confirm", post(api_blacklist_confirm))
        // Cloudflare 설정
        .route("/api/settings/cloudflare", get(api_cf_settings_get))
        .route("/api/settings/cloudflare", post(api_cf_settings_set))
        // 에이전트
        .route("/api/agent/version", get(api_agent_version))
        .route("/agent/server_agent.sh", get(serve_agent_script))
        .route("/agent/server_agent.sh.sha256", get(serve_agent_checksum))
        // 어뷰저 탐지
        .route("/api/servers/logs/abusers", get(api_logs_abusers))
        // 로그 리스트
        .route("/api/servers/logs", get(api_logs_list).post(api_logs_receive))
        .route("/api/servers/logs/ip/:ip", get(api_logs_by_ip))
        .route("/api/servers/logs/stats", get(api_logs_stats_summary))
        // 로그 통계
        .route("/api/servers/logs/stats/ips", get(api_logs_stats_ips))
        .route("/api/servers/logs/stats/timeline", get(api_logs_stats_timeline))
        .route("/api/servers/logs/stats/daily", get(api_logs_stats_daily))
        .route("/api/servers/logs/stats/daily/servers", get(api_logs_stats_daily_servers))
        .route("/api/servers/logs/stats/hourly", get(api_logs_stats_hourly))
        .route("/api/servers/logs/stats/servers", get(api_logs_stats_servers))
        .nest_service("/", ServeDir::new("static"))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    eprintln!("P2P Stats Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(_)) = receiver.next().await {}
    });

    tokio::select! {
        _ = send_task => {},
        _ = recv_task => {},
    }
}

async fn proxy_realtime(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let cache_secs: u64 = params.get("cache").and_then(|s| s.parse().ok()).unwrap_or(0) * 60;
    proxy_get_cached(&state.client, state.redis.clone(), "/api/realtime", "", cache_secs).await
}

async fn proxy_live(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let cache_secs: u64 = params.get("cache").and_then(|s| s.parse().ok()).unwrap_or(0) * 60;
    let mut pairs: Vec<_> = params
        .iter()
        .filter(|(k, _)| k.as_str() != "cache")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    pairs.sort();
    let query = if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) };
    proxy_get_cached(&state.client, state.redis.clone(), "/api/live", &query, cache_secs).await
}

async fn proxy_sessions(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    // 세션 API는 캐싱 없이 실시간 갱신
    let mut pairs: Vec<_> = params
        .iter()
        .filter(|(k, _)| k.as_str() != "cache")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    pairs.sort();
    let query = if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) };
    proxy_get(&state.client, "/api/sessions", &query).await
}

async fn proxy_ip_stats(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let mut pairs: Vec<_> = params
        .iter()
        .filter(|(k, _)| k.as_str() != "cache")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    pairs.sort();
    let query = if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) };
    proxy_get(&state.client, "/api/ip_stats", &query).await
}

async fn proxy_stats(State(state): State<AppState>) -> Response {
    proxy_get(&state.client, "/stats", "").await
}

async fn proxy_get(client: &Client, path: &str, query: &str) -> Response {
    let url = format!("{}{}{}", SIMPLE_WS_URL, path, query);

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default();

            Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            (StatusCode::BAD_GATEWAY, axum::Json(error)).into_response()
        }
    }
}

// Dragonfly 캐시 적용 proxy
async fn proxy_get_cached(
    client: &Client,
    mut redis: redis::aio::ConnectionManager,
    path: &str,
    query: &str,
    cache_secs: u64
) -> Response {
    let cache_key = format!("p2p:{}{}", path, query);

    // 캐시 확인
    if cache_secs > 0 {
        if let Ok(cached) = redis.get::<_, Option<String>>(&cache_key).await {
            if let Some(data) = cached {
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("access-control-allow-origin", "*")
                    .header("access-control-expose-headers", "x-cache")
                    .header("x-cache", "HIT")
                    .body(axum::body::Body::from(data))
                    .unwrap();
            }
        }
    }

    let url = format!("{}{}{}", SIMPLE_WS_URL, path, query);

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();

            // 캐시 저장 (SETEX - TTL 자동 만료)
            if cache_secs > 0 && status == 200 {
                let _: Result<(), _> = redis.set_ex(&cache_key, &body, cache_secs).await;
            }

            Response::builder()
                .status(StatusCode::from_u16(status).unwrap_or(StatusCode::OK))
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .header("access-control-expose-headers", "x-cache")
                .header("x-cache", "MISS")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            (StatusCode::BAD_GATEWAY, axum::Json(error)).into_response()
        }
    }
}

fn period_to_micros(period: &str) -> i64 {
    match period {
        "5m" => 300_000_000,
        "15m" => 900_000_000,
        "30m" => 1_800_000_000,
        "1h" => 3_600_000_000,
        "6h" => 21_600_000_000,
        "1d" | "24h" => 86_400_000_000,
        "7d" => 604_800_000_000,
        "30d" => 2_592_000_000_000,
        _ => 300_000_000,
    }
}

// hourly_stats 테이블 생성 (디비화)
async fn ensure_hourly_stats_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS hourly_stats (\
        ts TIMESTAMP, viewers LONG, unique_users LONG, http_bytes LONG, \
        p2p_bytes LONG, p2p_up_bytes LONG, peers LONG, swarms LONG, \
        plays LONG, unique_visitors LONG, tvmon LONG, tvwiki LONG, \
        tvhot LONG, mobile LONG, pc LONG) timestamp(ts) PARTITION BY DAY";
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;
}

// 특정 날짜 데이터가 hourly_stats에 있는지 확인
async fn has_hourly_stats_for_date(client: &Client, date: &str) -> bool {
    let query = format!(
        "SELECT count() FROM hourly_stats WHERE ts >= '{}T00:00:00Z' AND ts < '{}T00:00:00Z' + 86400000000L",
        date, date
    );
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(count) = json.get("dataset")
                .and_then(|d| d.as_array())
                .and_then(|a| a.first())
                .and_then(|r| r.as_array())
                .and_then(|r| r.first())
                .and_then(|v| v.as_i64())
            {
                return count > 0;
            }
        }
    }
    false
}

// 특정 날짜 데이터를 hourly_stats 테이블에 저장
async fn store_hourly_stats(client: &Client, date: &str) -> bool {
    // 먼저 해당 날짜의 기존 데이터 삭제 (중복 방지)
    let delete_query = format!(
        "DELETE FROM hourly_stats WHERE ts >= '{}T00:00:00Z' AND ts < '{}T00:00:00Z' + 86400000000L",
        date, date
    );
    let delete_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&delete_query));
    let _ = client.get(&delete_url).send().await;

    // 일별 데이터 조회 후 INSERT
    if let Some(day_data) = query_daily_stats(client, date).await {
        if let Some(dataset) = day_data.get("dataset").and_then(|d| d.as_array()) {
            for row in dataset {
                if let Some(arr) = row.as_array() {
                    // ts, viewers, unique_users, http_bytes, p2p_bytes, p2p_up_bytes, peers, swarms, plays, unique_visitors, tvmon, tvwiki, tvhot, mobile, pc
                    let ts = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                    let viewers = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                    let unique_users = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                    let http_bytes = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                    let p2p_bytes = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
                    let p2p_up_bytes = arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0);
                    let peers = arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0);
                    let swarms = arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0);
                    let plays = arr.get(8).and_then(|v| v.as_i64()).unwrap_or(0);
                    let unique_visitors = arr.get(9).and_then(|v| v.as_i64()).unwrap_or(0);
                    let tvmon = arr.get(10).and_then(|v| v.as_i64()).unwrap_or(0);
                    let tvwiki = arr.get(11).and_then(|v| v.as_i64()).unwrap_or(0);
                    let tvhot = arr.get(12).and_then(|v| v.as_i64()).unwrap_or(0);
                    let mobile = arr.get(13).and_then(|v| v.as_i64()).unwrap_or(0);
                    let pc = arr.get(14).and_then(|v| v.as_i64()).unwrap_or(0);

                    let insert_query = format!(
                        "INSERT INTO hourly_stats VALUES ('{}', {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {})",
                        ts, viewers, unique_users, http_bytes, p2p_bytes, p2p_up_bytes,
                        peers, swarms, plays, unique_visitors, tvmon, tvwiki, tvhot, mobile, pc
                    );
                    let insert_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&insert_query));
                    let _ = client.get(&insert_url).send().await;
                }
            }
            return true;
        }
    }
    false
}

// hourly_stats 테이블에서 기간별 데이터 조회
async fn query_hourly_stats_range(client: &Client, start_date: &str, end_date: &str) -> Option<serde_json::Value> {
    let query = format!(
        "SELECT ts, viewers, unique_users, http_bytes, p2p_bytes, p2p_up_bytes, \
         peers, swarms, plays, unique_visitors, tvmon, tvwiki, tvhot, mobile, pc \
         FROM hourly_stats WHERE ts >= '{}T00:00:00Z' AND ts <= '{}T23:59:59Z' \
         ORDER BY ts",
        start_date, end_date
    );
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));
    if let Ok(resp) = client.get(&url).send().await {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            return Some(json);
        }
    }
    None
}

// 일별 통계 조회 (하루치 데이터) - 시간별(1h) 샘플링
async fn query_daily_stats(
    client: &reqwest::Client,
    date: &str,  // "2026-01-18" 형식 (UTC)
) -> Option<serde_json::Value> {
    let start = format!("'{} 00:00:00'", date);
    let end = format!("'{} 23:59:59'", date);

    // r_* 필드로 델타 합산 (누적값 first/last 대신)
    let stats_query = format!(
        "SELECT ts, last(viewers) as viewers, last(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, last(peers) as peers, last(swarms) as swarms \
         FROM p2p_stats WHERE ts >= {} AND ts <= {} \
         SAMPLE BY 1h ALIGN TO CALENDAR",
        start, end
    );

    let visits_query = format!(
        "SELECT timestamp as ts, count() as plays, count_distinct(ip) as unique_visitors \
         FROM visitor_logs WHERE timestamp >= {} AND timestamp <= {} \
         SAMPLE BY 1h ALIGN TO CALENDAR",
        start, end
    );

    // 고유 방문자(UV) 기준 - 5개 쿼리 병렬 실행
    let tvmon_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp >= {} AND timestamp <= {} AND referrer ~ 'tvmon' SAMPLE BY 1h ALIGN TO CALENDAR", start, end);
    let tvwiki_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp >= {} AND timestamp <= {} AND referrer ~ 'tvwiki' SAMPLE BY 1h ALIGN TO CALENDAR", start, end);
    let tvhot_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp >= {} AND timestamp <= {} AND referrer ~ 'tvhot' SAMPLE BY 1h ALIGN TO CALENDAR", start, end);
    let mobile_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp >= {} AND timestamp <= {} AND device !~ 'PC' SAMPLE BY 1h ALIGN TO CALENDAR", start, end);
    let pc_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp >= {} AND timestamp <= {} AND device ~ 'PC' SAMPLE BY 1h ALIGN TO CALENDAR", start, end);

    let (stats_result, visits_result, tvmon_result, tvwiki_result, tvhot_result, mobile_result, pc_result) = tokio::join!(
        questdb_query_json(client, &stats_query),
        questdb_query_json(client, &visits_query),
        questdb_query_json(client, &tvmon_query),
        questdb_query_json(client, &tvwiki_query),
        questdb_query_json(client, &tvhot_query),
        questdb_query_json(client, &mobile_query),
        questdb_query_json(client, &pc_query)
    );

    if let (Ok(mut stats_json), Ok(visits_json)) = (stats_result, visits_result) {
        let mut plays_map: HashMap<String, i64> = HashMap::new();
        let mut visitors_map: HashMap<String, i64> = HashMap::new();
        if let Some(data) = visits_json.get("dataset").and_then(|d| d.as_array()) {
            for row in data {
                if let Some(arr) = row.as_array() {
                    if let Some(ts) = arr.get(0).and_then(|v| v.as_str()) {
                        plays_map.insert(ts.to_string(), arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0));
                        visitors_map.insert(ts.to_string(), arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0));
                    }
                }
            }
        }

        // 5개 쿼리 결과를 각각 HashMap으로 변환
        fn extract_map(result: &Result<serde_json::Value, String>) -> HashMap<String, i64> {
            let mut map = HashMap::new();
            if let Ok(json) = result {
                if let Some(data) = json.get("dataset").and_then(|d| d.as_array()) {
                    for row in data {
                        if let Some(arr) = row.as_array() {
                            if let Some(ts) = arr.get(0).and_then(|v| v.as_str()) {
                                map.insert(ts.to_string(), arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0));
                            }
                        }
                    }
                }
            }
            map
        }
        let tvmon_map = extract_map(&tvmon_result);
        let tvwiki_map = extract_map(&tvwiki_result);
        let tvhot_map = extract_map(&tvhot_result);
        let mobile_map = extract_map(&mobile_result);
        let pc_map = extract_map(&pc_result);

        if let Some(dataset) = stats_json.get_mut("dataset").and_then(|d| d.as_array_mut()) {
            for row in dataset.iter_mut() {
                if let Some(arr) = row.as_array_mut() {
                    let ts = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                    let plays = plays_map.get(ts).copied().unwrap_or(0);
                    let visitors = visitors_map.get(ts).copied().unwrap_or(0);
                    let tvmon = tvmon_map.get(ts).copied().unwrap_or(0);
                    let tvwiki = tvwiki_map.get(ts).copied().unwrap_or(0);
                    let tvhot = tvhot_map.get(ts).copied().unwrap_or(0);
                    let mobile = mobile_map.get(ts).copied().unwrap_or(0);
                    let pc = pc_map.get(ts).copied().unwrap_or(0);
                    arr.push(serde_json::json!(plays)); arr.push(serde_json::json!(visitors));
                    arr.push(serde_json::json!(tvmon)); arr.push(serde_json::json!(tvwiki)); arr.push(serde_json::json!(tvhot));
                    arr.push(serde_json::json!(mobile)); arr.push(serde_json::json!(pc));
                }
            }
        }
        Some(stats_json)
    } else {
        None
    }
}

async fn history_stats(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let sample = params.get("sample").map(|s| s.as_str()).unwrap_or("1m");
    let nocache = params.get("nocache").map(|s| s == "1").unwrap_or(false);
    let micros = period_to_micros(period);
    let mut redis = state.redis.clone();

    // 7d 이상은 디비화된 hourly_stats 테이블 사용
    let use_db_table = matches!(period, "7d" | "30d" | "365d");

    if use_db_table {
        let days: i64 = match period { "7d" => 7, "30d" => 30, "365d" => 365, _ => 7 };
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let start_date = (chrono::Utc::now() - chrono::Duration::days(days - 1)).format("%Y-%m-%d").to_string();
        let yesterday = (chrono::Utc::now() - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let mut all_data: Vec<serde_json::Value> = Vec::new();

        // 1. 과거 데이터 (어제까지): hourly_stats 테이블에서 조회
        if let Some(hist_data) = query_hourly_stats_range(&state.client, &start_date, &yesterday).await {
            if let Some(dataset) = hist_data.get("dataset").and_then(|d| d.as_array()) {
                all_data.extend(dataset.clone());
            }
        }

        // 2. 오늘 데이터: 실시간 쿼리 (nocache=1이면 캐시 스킵)
        let today_cache_key = format!("daily_stats:{}", today);
        let mut today_data: Option<serde_json::Value> = None;

        if !nocache {
            if let Ok(Some(cached)) = redis.get::<_, Option<String>>(&today_cache_key).await {
                if let Ok(cached_json) = serde_json::from_str::<serde_json::Value>(&cached) {
                    today_data = Some(cached_json);
                }
            }
        }

        if today_data.is_none() {
            if let Some(day_data) = query_daily_stats(&state.client, &today).await {
                if !nocache {
                    let _: Result<(), _> = redis.set_ex(&today_cache_key, &day_data.to_string(), 300).await;
                }
                today_data = Some(day_data);
            }
        }

        if let Some(td) = today_data {
            if let Some(dataset) = td.get("dataset").and_then(|d| d.as_array()) {
                all_data.extend(dataset.clone());
            }
        }

        all_data.sort_by(|a, b| {
            let ts_a = a.as_array().and_then(|arr| arr.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            let ts_b = b.as_array().and_then(|arr| arr.get(0)).and_then(|v| v.as_str()).unwrap_or("");
            ts_a.cmp(ts_b)
        });

        let columns = serde_json::json!([
            {"name": "ts", "type": "TIMESTAMP"}, {"name": "viewers", "type": "LONG"},
            {"name": "unique_users", "type": "LONG"}, {"name": "http_bytes", "type": "LONG"},
            {"name": "p2p_bytes", "type": "LONG"}, {"name": "p2p_up_bytes", "type": "LONG"},
            {"name": "peers", "type": "LONG"}, {"name": "swarms", "type": "LONG"},
            {"name": "plays", "type": "LONG"}, {"name": "unique_visitors", "type": "LONG"},
            {"name": "tvmon", "type": "LONG"}, {"name": "tvwiki", "type": "LONG"},
            {"name": "tvhot", "type": "LONG"}, {"name": "mobile", "type": "LONG"},
            {"name": "pc", "type": "LONG"}
        ]);

        let result = serde_json::json!({ "columns": columns, "dataset": all_data, "count": all_data.len() });
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "DB")
            .body(axum::body::Body::from(result.to_string()))
            .unwrap();
    }

    // 기존 방식 (24h 이하)
    let cache_key = format!("history_stats:{}:{}", period, sample);
    if let Ok(Some(data)) = redis.get::<_, Option<String>>(&cache_key).await {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "HIT")
            .body(axum::body::Body::from(data))
            .unwrap();
    }

    // r_* 필드로 델타 합산
    let stats_query = format!(
        "SELECT ts, last(viewers) as viewers, last(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, last(peers) as peers, last(swarms) as swarms \
         FROM p2p_stats WHERE ts > systimestamp() - {}L SAMPLE BY {} ALIGN TO CALENDAR",
        micros, sample
    );
    let visits_query = format!(
        "SELECT timestamp as ts, count() as plays, count_distinct(ip) as unique_visitors \
         FROM visitor_logs WHERE timestamp > systimestamp() - {}L SAMPLE BY {} ALIGN TO CALENDAR",
        micros, sample
    );
    // 고유 방문자(UV) 기준 - 5개 쿼리 병렬 실행
    let tvmon_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp > systimestamp() - {}L AND referrer ~ 'tvmon' SAMPLE BY {} ALIGN TO CALENDAR", micros, sample);
    let tvwiki_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp > systimestamp() - {}L AND referrer ~ 'tvwiki' SAMPLE BY {} ALIGN TO CALENDAR", micros, sample);
    let tvhot_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp > systimestamp() - {}L AND referrer ~ 'tvhot' SAMPLE BY {} ALIGN TO CALENDAR", micros, sample);
    let mobile_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp > systimestamp() - {}L AND device !~ 'PC' SAMPLE BY {} ALIGN TO CALENDAR", micros, sample);
    let pc_query = format!(
        "SELECT timestamp as ts, count_distinct(ip) as cnt FROM visitor_logs \
         WHERE timestamp > systimestamp() - {}L AND device ~ 'PC' SAMPLE BY {} ALIGN TO CALENDAR", micros, sample);

    let (stats_result, visits_result, tvmon_result, tvwiki_result, tvhot_result, mobile_result, pc_result) = tokio::join!(
        questdb_query_json(&state.client, &stats_query),
        questdb_query_json(&state.client, &visits_query),
        questdb_query_json(&state.client, &tvmon_query),
        questdb_query_json(&state.client, &tvwiki_query),
        questdb_query_json(&state.client, &tvhot_query),
        questdb_query_json(&state.client, &mobile_query),
        questdb_query_json(&state.client, &pc_query)
    );

    match (stats_result, visits_result) {
        (Ok(mut stats_json), Ok(visits_json)) => {
            let mut plays_map: HashMap<String, i64> = HashMap::new();
            let mut visitors_map: HashMap<String, i64> = HashMap::new();
            if let Some(data) = visits_json.get("dataset").and_then(|d| d.as_array()) {
                for row in data {
                    if let Some(arr) = row.as_array() {
                        if let Some(ts) = arr.get(0).and_then(|v| v.as_str()) {
                            plays_map.insert(ts.to_string(), arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0));
                            visitors_map.insert(ts.to_string(), arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0));
                        }
                    }
                }
            }

            // 5개 쿼리 결과를 각각 HashMap으로 변환
            fn extract_map2(result: &Result<serde_json::Value, String>) -> HashMap<String, i64> {
                let mut map = HashMap::new();
                if let Ok(json) = result {
                    if let Some(data) = json.get("dataset").and_then(|d| d.as_array()) {
                        for row in data {
                            if let Some(arr) = row.as_array() {
                                if let Some(ts) = arr.get(0).and_then(|v| v.as_str()) {
                                    map.insert(ts.to_string(), arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0));
                                }
                            }
                        }
                    }
                }
                map
            }
            let tvmon_map = extract_map2(&tvmon_result);
            let tvwiki_map = extract_map2(&tvwiki_result);
            let tvhot_map = extract_map2(&tvhot_result);
            let mobile_map = extract_map2(&mobile_result);
            let pc_map = extract_map2(&pc_result);

            if let Some(dataset) = stats_json.get_mut("dataset").and_then(|d| d.as_array_mut()) {
                for row in dataset.iter_mut() {
                    if let Some(arr) = row.as_array_mut() {
                        let ts = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                        let plays = plays_map.get(ts).copied().unwrap_or(0);
                        let visitors = visitors_map.get(ts).copied().unwrap_or(0);
                        let tvmon = tvmon_map.get(ts).copied().unwrap_or(0);
                        let tvwiki = tvwiki_map.get(ts).copied().unwrap_or(0);
                        let tvhot = tvhot_map.get(ts).copied().unwrap_or(0);
                        let mobile = mobile_map.get(ts).copied().unwrap_or(0);
                        let pc = pc_map.get(ts).copied().unwrap_or(0);
                        arr.push(serde_json::json!(plays)); arr.push(serde_json::json!(visitors));
                        arr.push(serde_json::json!(tvmon)); arr.push(serde_json::json!(tvwiki)); arr.push(serde_json::json!(tvhot));
                        arr.push(serde_json::json!(mobile)); arr.push(serde_json::json!(pc));
                    }
                }
            }

            if let Some(columns) = stats_json.get_mut("columns").and_then(|c| c.as_array_mut()) {
                columns.push(serde_json::json!({"name": "plays", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "unique_visitors", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "tvmon", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "tvwiki", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "tvhot", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "mobile", "type": "LONG"}));
                columns.push(serde_json::json!({"name": "pc", "type": "LONG"}));
            }

            let body = stats_json.to_string();
            let _: Result<(), _> = redis.set_ex::<_, _, ()>(&cache_key, &body, 60).await;
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .header("x-cache", "MISS")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Query failed").into_response()
    }
}
async fn history_swarms(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let limit = params.get("limit").map(|s| s.as_str()).unwrap_or("20");
    let micros = period_to_micros(period);

    let query = format!(
        "SELECT swarm_id, filename, sum(viewers) as total_viewers, \
         sum(http_bytes) as http_bytes, sum(p2p_bytes) as p2p_bytes \
         FROM p2p_swarms \
         WHERE ts > systimestamp() - {}L \
         GROUP BY swarm_id, filename \
         ORDER BY total_viewers DESC \
         LIMIT {}",
        micros, limit
    );

    questdb_query(&state.client, &query).await
}

// 시간대별 히트맵용 API
async fn history_hourly(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let days = params
        .get("days")
        .and_then(|s| s.parse().ok())
        .unwrap_or(7i64);
    let micros = days * 86_400_000_000;

    let query = format!(
        "SELECT hour(ts) as hour, avg(viewers) as avg_viewers \
         FROM p2p_stats \
         WHERE ts > systimestamp() - {}L \
         GROUP BY hour(ts) \
         ORDER BY hour",
        micros
    );

    questdb_query(&state.client, &query).await
}

// 인기파일 API (고유 IP + 트래픽) - 캐싱 및 최적화
async fn api_popular(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("all");
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20).min(100);
    let offset: i64 = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    // 캐시 키 (30초 TTL)
    let cache_key = format!("popular:{}:{}:{}", period, limit, offset);
    let mut redis = state.redis.clone();
    if let Ok(cached) = redis.get::<_, String>(&cache_key).await {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "HIT")
            .body(axum::body::Body::from(cached))
            .unwrap();
    }

    // 한국시간(KST=UTC+9) 자정 기준 타임스탬프 계산 (마이크로초)
    use std::time::{SystemTime, UNIX_EPOCH};
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
    let kst_offset: i64 = 9 * 3600;
    let kst_midnight_us = (((now_secs + kst_offset) / 86400) * 86400 - kst_offset) * 1_000_000;

    let time_filter = match period {
        "daily" => format!("WHERE timestamp > cast({} as timestamp)", kst_midnight_us),
        "weekly" => format!("WHERE timestamp > cast({} as timestamp)", kst_midnight_us - 7 * 86400 * 1_000_000),
        "monthly" => format!("WHERE timestamp > cast({} as timestamp)", kst_midnight_us - 30 * 86400 * 1_000_000_i64),
        _ => String::new(),
    };

    // 1단계: 조회수 상위 swarm_id 조회 (최적화: LIMIT만 적용)
    let views_query = format!(
        "SELECT swarm_id, last(filename) as filename, count_distinct(ip) as views \
         FROM visitor_logs {} GROUP BY swarm_id ORDER BY views DESC LIMIT {}, {}",
        time_filter, offset, limit
    );

    let views_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&views_query));
    let views_data: serde_json::Value = match state.client.get(&views_url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    // swarm_id 목록 추출
    let mut swarm_ids: Vec<String> = Vec::new();
    let mut views_map: HashMap<String, (String, i64)> = HashMap::new();
    if let Some(dataset) = views_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let swarm_id = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let filename = arr.get(1).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let views = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                if !swarm_id.is_empty() {
                    swarm_ids.push(swarm_id.clone());
                    views_map.insert(swarm_id, (filename, views));
                }
            }
        }
    }

    // 2단계: 해당 swarm_id들의 트래픽만 조회 (최적화: IN 절 사용)
    let mut traffic_map: HashMap<String, (i64, i64)> = HashMap::new();
    if !swarm_ids.is_empty() {
        let ids_str = swarm_ids.iter().map(|s| format!("'{}'", s.replace("'", "''"))).collect::<Vec<_>>().join(",");
        let traffic_query = format!(
            "SELECT swarm_id, max(http_bytes), max(p2p_bytes) FROM p2p_swarms WHERE swarm_id IN ({}) GROUP BY swarm_id",
            ids_str
        );
        let traffic_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&traffic_query));
        if let Ok(resp) = state.client.get(&traffic_url).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data.get("dataset").and_then(|d| d.as_array()) {
                    for row in dataset {
                        if let Some(arr) = row.as_array() {
                            let sid = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                            let http = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                            let p2p = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                            traffic_map.insert(sid.to_string(), (http, p2p));
                        }
                    }
                }
            }
        }
    }

    // 결과 병합 (순서 유지)
    let result_dataset: Vec<serde_json::Value> = swarm_ids.iter().filter_map(|sid| {
        views_map.get(sid).map(|(filename, views)| {
            let (http, p2p) = traffic_map.get(sid).copied().unwrap_or((0, 0));
            serde_json::json!([sid, filename, views, http, p2p])
        })
    }).collect();

    let result = serde_json::json!({
        "columns": [
            {"name": "swarm_id", "type": "STRING"},
            {"name": "filename", "type": "STRING"},
            {"name": "views", "type": "LONG"},
            {"name": "http_bytes", "type": "LONG"},
            {"name": "p2p_bytes", "type": "LONG"}
        ],
        "dataset": result_dataset
    });

    let body = result.to_string();

    // 캐시 저장 (30초 TTL)
    let _: Result<(), _> = redis.set_ex(&cache_key, &body, 30).await;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("x-cache", "MISS")
        .body(axum::body::Body::from(body))
        .unwrap()
}

// 종합통계 (오늘/어제 비교) - hourly_stats에서 미리 계산된 값 사용
async fn api_summary(State(state): State<AppState>) -> Response {
    // ========== 캐시 확인 (30초 TTL) ==========
    {
        let cache = SUMMARY_CACHE.read();
        if let Some(ref entry) = *cache {
            if entry.expires_at > Instant::now() {
                return Response::builder()
                    .header("content-type", "application/json")
                    .header("x-cache", "HIT")
                    .body(Body::from(entry.data.to_string()))
                    .unwrap();
            }
        }
    }

    // p2p_stats에서 피크값, 트래픽
    let today_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= timestamp_floor('d', now())";

    let yesterday_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= dateadd('d', -1, timestamp_floor('d', now())) AND ts < timestamp_floor('d', now())";

    // hourly_stats에서 오늘/어제 재생수, 순방문자 (GROUP BY로 중복 제거 후 합산)
    let today_hourly_query = "SELECT sum(plays) as plays, sum(unique_visitors) as unique_visitors \
        FROM (SELECT ts, max(plays) as plays, max(unique_visitors) as unique_visitors FROM hourly_stats WHERE ts >= timestamp_floor('d', now()) GROUP BY ts)";

    let yesterday_hourly_query = "SELECT sum(plays) as plays, sum(unique_visitors) as unique_visitors \
        FROM (SELECT ts, max(plays) as plays, max(unique_visitors) as unique_visitors FROM hourly_stats WHERE ts >= dateadd('d', -1, timestamp_floor('d', now())) AND ts < timestamp_floor('d', now()) GROUP BY ts)";

    let (today_res, yesterday_res, today_hourly_res, yesterday_hourly_res) = tokio::join!(
        questdb_query_json(&state.client, today_query),
        questdb_query_json(&state.client, yesterday_query),
        questdb_query_json(&state.client, today_hourly_query),
        questdb_query_json(&state.client, yesterday_hourly_query)
    );

    // QuestDB 응답에서 첫 번째 행 추출 헬퍼
    fn extract_row(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        json.get("dataset")?.as_array()?.first()?.as_array()
    }

    // 오늘 데이터 파싱
    let today_row = today_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_hourly_row = today_hourly_res.as_ref().ok().and_then(|j| extract_row(j));

    let today_data = serde_json::json!({
        "max_viewers": today_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": today_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": today_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": today_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": today_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": today_hourly_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": today_hourly_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    // 어제 데이터 파싱
    let yesterday_row = yesterday_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_hourly_row = yesterday_hourly_res.as_ref().ok().and_then(|j| extract_row(j));

    let yesterday_data = serde_json::json!({
        "max_viewers": yesterday_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": yesterday_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": yesterday_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": yesterday_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": yesterday_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": yesterday_hourly_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": yesterday_hourly_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    let body = serde_json::json!({
        "today": today_data,
        "yesterday": yesterday_data
    });

    // ========== 결과 캐시 (30초 TTL) ==========
    {
        let mut cache = SUMMARY_CACHE.write();
        *cache = Some(CacheEntry {
            data: body.clone(),
            expires_at: Instant::now() + Duration::from_secs(30),
        });
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("x-cache", "MISS")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap()
}

// 방문자 로그 API (QuestDB 최적화)
async fn api_visitors(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100).min(1000);
    let offset: i64 = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);
    let ip_filter = params.get("ip");

    // IP 필터가 있으면 조건 추가
    let ip_condition = if let Some(ip) = ip_filter {
        format!(" AND ip ~ '{}'", ip.replace("'", "''"))
    } else {
        String::new()
    };

    // 기간별 시간 문자열 (QuestDB dateadd 사용)
    let time_filter = match period {
        "1h" => "dateadd('h', -1, now())",
        "6h" => "dateadd('h', -6, now())",
        "1d" => "dateadd('d', -1, now())",
        "7d" => "dateadd('d', -7, now())",
        "30d" => "dateadd('d', -30, now())",
        _ => "dateadd('h', -1, now())",
    };

    // QuestDB 최적화: designated timestamp + LIMIT 활용
    let query = format!(
        "SELECT timestamp, ip, session_id, swarm_id, filename, device, device_name, browser, referrer, net_type, player_id \
         FROM visitor_logs \
         WHERE timestamp > {}{} \
         ORDER BY timestamp DESC \
         LIMIT {},{}",
        time_filter, ip_condition, offset, limit
    );

    questdb_query(&state.client, &query).await
}

async fn questdb_query(client: &Client, query: &str) -> Response {
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));

    match client.get(&url).send().await {
        Ok(resp) => {
            let body = resp.bytes().await.unwrap_or_default();
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            (StatusCode::BAD_GATEWAY, axum::Json(error)).into_response()
        }
    }
}

async fn questdb_query_json(client: &Client, query: &str) -> Result<serde_json::Value, String> {
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));

    let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

// 초기 데이터 API (summary + daily + monthly)
async fn api_init_data(State(state): State<AppState>) -> Response {
    let client = &state.client;

    // 오늘/어제 summary (p2p_stats에서 피크값, 트래픽)
    let today_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= timestamp_floor('d', now())";
    let yesterday_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= dateadd('d', -1, timestamp_floor('d', now())) AND ts < timestamp_floor('d', now())";

    // hourly_stats에서 오늘/어제 재생수, 순방문자 (GROUP BY로 중복 제거 후 합산)
    let today_hourly_query = "SELECT sum(plays) as plays, sum(unique_visitors) as unique_visitors \
        FROM (SELECT ts, max(plays) as plays, max(unique_visitors) as unique_visitors FROM hourly_stats WHERE ts >= timestamp_floor('d', now()) GROUP BY ts)";
    let yesterday_hourly_query = "SELECT sum(plays) as plays, sum(unique_visitors) as unique_visitors \
        FROM (SELECT ts, max(plays) as plays, max(unique_visitors) as unique_visitors FROM hourly_stats WHERE ts >= dateadd('d', -1, timestamp_floor('d', now())) AND ts < timestamp_floor('d', now()) GROUP BY ts)";

    let (today_res, yesterday_res, today_visitors_res, yesterday_visitors_res) = tokio::join!(
        questdb_query_json(client, today_query),
        questdb_query_json(client, yesterday_query),
        questdb_query_json(client, today_hourly_query),
        questdb_query_json(client, yesterday_hourly_query)
    );

    // QuestDB 응답에서 첫 번째 행 추출 헬퍼
    fn extract_row(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        json.get("dataset")?.as_array()?.first()?.as_array()
    }

    // 오늘 데이터 파싱: [max_viewers, max_users, http_bytes, p2p_bytes, swarms]
    let today_row = today_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_visitors_row = today_visitors_res.as_ref().ok().and_then(|j| extract_row(j));

    let today_data = serde_json::json!({
        "max_viewers": today_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": today_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": today_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": today_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": today_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": today_visitors_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": today_visitors_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    // 어제 데이터 파싱
    let yesterday_row = yesterday_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_visitors_row = yesterday_visitors_res.as_ref().ok().and_then(|j| extract_row(j));

    let yesterday_data = serde_json::json!({
        "max_viewers": yesterday_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": yesterday_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": yesterday_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": yesterday_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": yesterday_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": yesterday_visitors_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": yesterday_visitors_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    let summary = serde_json::json!({
        "today": today_data,
        "yesterday": yesterday_data
    });

    // 일별 통계 (최근 30일) - GROUP BY로 중복 제거
    let daily_query = "SELECT ts, max(viewers) as viewers, max(unique_users) as unique_users, \
        max(http_bytes) as http_bytes, max(p2p_bytes) as p2p_bytes, max(p2p_up_bytes) as p2p_up_bytes, \
        max(peers) as peers, max(swarms) as swarms, max(plays) as plays, max(unique_visitors) as unique_visitors, \
        max(tvmon) as tvmon, max(tvwiki) as tvwiki, max(tvhot) as tvhot, max(mobile) as mobile, max(pc) as pc \
        FROM hourly_stats WHERE ts >= dateadd('d', -30, now()) GROUP BY ts ORDER BY ts";
    let daily_stats = questdb_query_json(client, daily_query).await.unwrap_or(serde_json::json!({}));

    // 월별 통계 - 서브쿼리로 중복 제거 후 집계
    let monthly_query = "SELECT timestamp_floor('M', ts) as month, \
        max(viewers) as peak_viewers, max(unique_users) as peak_users, \
        sum(http_bytes) as total_http, sum(p2p_bytes) as total_p2p \
        FROM (SELECT ts, max(viewers) as viewers, max(unique_users) as unique_users, max(http_bytes) as http_bytes, max(p2p_bytes) as p2p_bytes FROM hourly_stats GROUP BY ts) GROUP BY month ORDER BY month DESC LIMIT 12";
    let monthly_stats = questdb_query_json(client, monthly_query).await.unwrap_or(serde_json::json!({}));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({
            "summary": summary,
            "daily_stats": daily_stats,
            "monthly_stats": monthly_stats
        }).to_string()))
        .unwrap()
}

// 트래픽 통계 API (클라우드플레어 스타일)
async fn api_traffic(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("24h");

    // 캐시 키 (1분 TTL)
    let cache_key = format!("traffic:{}", period);
    let mut redis = state.redis.clone();
    if let Ok(cached) = redis.get::<_, String>(&cache_key).await {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "HIT")
            .body(axum::body::Body::from(cached))
            .unwrap();
    }

    // 기간별 설정 (7d: 1시간별, 30d: 6시간별)
    let (time_filter, sample_interval) = match period {
        "realtime" => ("ts > dateadd('m', -10, now())", "10s"),
        "1h" => ("ts > dateadd('h', -1, now())", "1m"),
        "6h" => ("ts > dateadd('h', -6, now())", "5m"),
        "24h" => ("ts > dateadd('d', -1, now())", "10m"),
        "7d" => ("ts > dateadd('d', -7, now())", "1h"),
        "30d" => ("ts > dateadd('d', -30, now())", "6h"),
        _ => ("ts > dateadd('d', -1, now())", "10m"),
    };

    // 1. 시계열 데이터 (트래픽 추이) - SAMPLE BY로 시간 간격 샘플링, 0값 제외
    let timeline_query = format!(
        "SELECT ts, avg(viewers) as viewers, avg(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, avg(peers) as peers, avg(swarms) as swarms \
         FROM p2p_stats WHERE {} SAMPLE BY {} ALIGN TO CALENDAR ORDER BY ts",
        time_filter, sample_interval
    );

    // 2. 피크값 통계
    let total_query = format!(
        "SELECT max(viewers) as peak_viewers, max(unique_users) as peak_users, \
         max(peers) as peak_peers, max(swarms) as peak_swarms \
         FROM p2p_stats WHERE {}",
        time_filter
    );

    // 3. 정확한 트래픽 총합 계산 (r_* 델타 합산)
    let traffic_query = format!(
        "SELECT sum(r_http_bytes) as total_http, sum(r_p2p_bytes) as total_p2p, \
         sum(r_p2p_up_bytes) as total_up \
         FROM p2p_stats WHERE {}",
        time_filter
    );

    // 4. 실시간 속도 계산 (최근 30초간 r_* 합산)
    let speed_query = "SELECT sum(r_http_bytes) as http, sum(r_p2p_bytes) as p2p, sum(r_p2p_up_bytes) as p2p_up \
         FROM p2p_stats WHERE ts > dateadd('s', -30, now())";

    // 5. CDN 서버별 통계 (p2p_servers에서 트래픽 + visitor_logs에서 접속자)
    let server_traffic_query = format!(
        "SELECT server, first(http_bytes) as first_http, last(http_bytes) as last_http, \
         first(p2p_bytes) as first_p2p, last(p2p_bytes) as last_p2p, \
         first(p2p_up_bytes) as first_up, last(p2p_up_bytes) as last_up, \
         max(viewers) as peak_viewers \
         FROM p2p_servers WHERE {} GROUP BY server ORDER BY last_http DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    let visitor_query = format!(
        "SELECT left(swarm_id, strpos(swarm_id, '.') - 1) as server, \
         count_distinct(ip) as visitors, count() as requests \
         FROM visitor_logs WHERE {} GROUP BY server ORDER BY visitors DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    // 6. 서버별 실시간 속도 (최근 30초간 r_* 합산)
    let server_speed_query = "SELECT server, sum(r_http_bytes) as r_http, sum(r_p2p_bytes) as r_p2p, sum(r_p2p_up_bytes) as r_p2p_up \
         FROM p2p_servers WHERE timestamp > dateadd('s', -30, now()) GROUP BY server";

    // 7. 플레이어별 실시간 속도 (최근 30초간 r_* 합산)
    let player_speed_query = "SELECT player, sum(r_http_bytes) as r_http, sum(r_p2p_bytes) as r_p2p, sum(r_p2p_up_bytes) as r_p2p_up \
         FROM p2p_players WHERE timestamp > dateadd('s', -30, now()) GROUP BY player";

    // 병렬 쿼리 실행 (QuestDB + simple_ws)
    let timeline_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&timeline_query));
    let total_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&total_query));
    let traffic_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&traffic_query));
    let speed_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(speed_query));
    let server_traffic_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&server_traffic_query));
    let visitor_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&visitor_query));
    let server_speed_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(server_speed_query));
    let player_speed_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(player_speed_query));
    let realtime_url = format!("{}/api/realtime", SIMPLE_WS_URL);

    let (timeline_res, total_res, traffic_res, speed_res, server_traffic_res, visitor_res, server_speed_res, player_speed_res, realtime_res) = tokio::join!(
        state.client.get(&timeline_url).send(),
        state.client.get(&total_url).send(),
        state.client.get(&traffic_url).send(),
        state.client.get(&speed_url).send(),
        state.client.get(&server_traffic_url).send(),
        state.client.get(&visitor_url).send(),
        state.client.get(&server_speed_url).send(),
        state.client.get(&player_speed_url).send(),
        state.client.get(&realtime_url).send()
    );

    let mut timeline_data: serde_json::Value = match timeline_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };


    let total_data: serde_json::Value = match total_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let traffic_data: serde_json::Value = match traffic_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let speed_data: serde_json::Value = match speed_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let server_traffic_data: serde_json::Value = match server_traffic_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let visitor_data: serde_json::Value = match visitor_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let server_speed_data: serde_json::Value = match server_speed_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let player_speed_data: serde_json::Value = match player_speed_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let realtime_data: serde_json::Value = match realtime_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    // 정확한 총합 계산 (r_* 델타 합산 - 간단함)
    let (total_http, total_p2p, total_p2p_up) = if let Some(dataset) = traffic_data.get("dataset").and_then(|d| d.as_array()) {
        if let Some(row) = dataset.first().and_then(|r| r.as_array()) {
            (
                row.get(0).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
                row.get(1).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
                row.get(2).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
            )
        } else {
            (0, 0, 0)
        }
    } else {
        (0, 0, 0)
    };

    // 시계열 데이터 가공 (r_* 델타 합산이라 바로 사용)
    let mut timeline: Vec<serde_json::Value> = Vec::new();
    if let Some(dataset) = timeline_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset.iter() {
            if let Some(arr) = row.as_array() {
                timeline.push(serde_json::json!({
                    "ts": arr.get(0),
                    "viewers": arr.get(1).and_then(|v| v.as_f64()).map(|v| v as i64),
                    "uniqueUsers": arr.get(2).and_then(|v| v.as_f64()).map(|v| v as i64),
                    "httpBytes": arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
                    "p2pBytes": arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
                    "p2pUpBytes": arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0),
                    "peers": arr.get(6).and_then(|v| v.as_f64()).map(|v| v as i64),
                    "swarms": arr.get(7).and_then(|v| v.as_f64()).map(|v| v as i64)
                }));
            }
        }
    }

    // 실시간 속도 계산 (GB/s) - simple_ws의 rHttpBytes 등 사용 (이미 bytes/sec)
    let empty_player = serde_json::json!({});
    let (http_gbps, p2p_gbps, p2p_up_gbps) = {
        let p1 = realtime_data.get("player1").unwrap_or(&empty_player);
        let p2 = realtime_data.get("player2").unwrap_or(&empty_player);
        let r_http = p1.get("rHttpBytes").and_then(|v| v.as_i64()).unwrap_or(0)
                  + p2.get("rHttpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p = p1.get("rP2pBytes").and_then(|v| v.as_i64()).unwrap_or(0)
                  + p2.get("rP2pBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p_up = p1.get("rP2pUpBytes").and_then(|v| v.as_i64()).unwrap_or(0)
                     + p2.get("rP2pUpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        // bytes/sec -> GB/s
        let http_gbs = (r_http as f64) / 1_073_741_824.0;
        let p2p_gbs = (r_p2p as f64) / 1_073_741_824.0;
        let p2p_up_gbs = (r_p2p_up as f64) / 1_073_741_824.0;
        (http_gbs, p2p_gbs, p2p_up_gbs)
    };

    let mut totals = serde_json::json!({
        "totalHttp": total_http,
        "totalP2p": total_p2p,
        "totalP2pUp": total_p2p_up,
        "httpGbps": format!("{:.2}", http_gbps),
        "p2pGbps": format!("{:.2}", p2p_gbps),
        "p2pUpGbps": format!("{:.2}", p2p_up_gbps)
    });
    if let Some(dataset) = total_data.get("dataset").and_then(|d| d.as_array()) {
        if let Some(row) = dataset.first().and_then(|r| r.as_array()) {
            totals = serde_json::json!({
                "peakViewers": row.get(0),
                "peakUsers": row.get(1),
                "totalHttp": total_http,
                "totalP2p": total_p2p,
                "totalP2pUp": total_p2p_up,
                "httpGbps": format!("{:.2}", http_gbps),
                "p2pGbps": format!("{:.2}", p2p_gbps),
                "p2pUpGbps": format!("{:.2}", p2p_up_gbps),
                "peakPeers": row.get(2),
                "peakSwarms": row.get(3)
            });
        }
    }

    // 서버별 통계 가공 (CDN 서버만)
    let mut servers: Vec<serde_json::Value> = Vec::new();

    // CDN 서버별 트래픽 맵 구성 (p2p_servers에서 first/last 델타)
    let mut server_traffic_map: std::collections::HashMap<String, (i64, i64, i64, i64)> = std::collections::HashMap::new();
    if let Some(dataset) = server_traffic_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let first_http = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let last_http = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let first_p2p = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let last_p2p = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
                let first_up = arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0);
                let last_up = arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0);
                let peak_viewers = arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0);
                // 리셋 감지: last < first면 리셋 후 누적량(last) 사용
                let http_delta = if last_http >= first_http { last_http - first_http } else { last_http };
                let p2p_delta = if last_p2p >= first_p2p { last_p2p - first_p2p } else { last_p2p };
                let up_delta = if last_up >= first_up { last_up - first_up } else { last_up };
                server_traffic_map.insert(server, (http_delta, p2p_delta, up_delta, peak_viewers));
            }
        }
    }

    // 3. 접속자 맵 구성
    let mut visitor_map: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
    if let Some(dataset) = visitor_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let visitors = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let requests = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                visitor_map.insert(server, (visitors, requests));
            }
        }
    }

    // 4. 서버별 속도 맵 구성 (r_* 합산 / 30 = GB/s)
    let mut server_speed_map: std::collections::HashMap<String, (f64, f64, f64)> = std::collections::HashMap::new();
    if let Some(dataset) = server_speed_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let r_http = arr.get(1).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p = arr.get(2).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p_up = arr.get(3).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                // bytes/30sec -> GB/s
                let http_gbs = (r_http as f64) / 30.0 / 1_073_741_824.0;
                let p2p_gbs = (r_p2p as f64) / 30.0 / 1_073_741_824.0;
                let p2p_up_gbs = (r_p2p_up as f64) / 30.0 / 1_073_741_824.0;
                server_speed_map.insert(server, (http_gbs, p2p_gbs, p2p_up_gbs));
            }
        }
    }

    // 5. CDN 서버 병합 (트래픽 기준 정렬)
    let mut all_servers: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in server_traffic_map.keys() { all_servers.insert(s.clone()); }
    for s in visitor_map.keys() { all_servers.insert(s.clone()); }

    let mut cdn_servers: Vec<(String, i64, i64, i64, i64, i64, i64, f64, f64, f64)> = all_servers.iter()
        .filter(|s| !s.is_empty() && *s != "unknown")
        .map(|s| {
            let (http, p2p, p2p_up, peak) = server_traffic_map.get(s).copied().unwrap_or((0, 0, 0, 0));
            let (visitors, requests) = visitor_map.get(s).copied().unwrap_or((0, 0));
            let (http_gbs, p2p_gbs, p2p_up_gbs) = server_speed_map.get(s).copied().unwrap_or((0.0, 0.0, 0.0));
            (s.clone(), http, p2p, p2p_up, peak, visitors, requests, http_gbs, p2p_gbs, p2p_up_gbs)
        })
        .collect();
    cdn_servers.sort_by(|a, b| b.1.cmp(&a.1)); // HTTP 내림차순

    for (server, http, p2p, p2p_up, _peak, visitors, requests, http_gbs, p2p_gbs, p2p_up_gbs) in cdn_servers {
        servers.push(serde_json::json!({
            "server": server,
            "http": http,
            "p2p": p2p,
            "p2pUp": p2p_up,
            "httpGbps": format!("{:.2}", http_gbs),
            "p2pGbps": format!("{:.2}", p2p_gbs),
            "p2pUpGbps": format!("{:.2}", p2p_up_gbs),
            "visitors": visitors,
            "requests": requests
        }));
    }

    // 플레이어별 속도 계산 - simple_ws realtime_data 사용 (bytes/sec -> GB/s)
    let mut player_speeds: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
    for (key, player_key) in [("player1", "player1"), ("player2", "player2")] {
        if let Some(p) = realtime_data.get(player_key) {
            let r_http = p.get("rHttpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
            let r_p2p = p.get("rP2pBytes").and_then(|v| v.as_i64()).unwrap_or(0);
            let r_p2p_up = p.get("rP2pUpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
            // bytes/sec -> GB/s
            let http_gbs = (r_http as f64) / 1_073_741_824.0;
            let p2p_gbs = (r_p2p as f64) / 1_073_741_824.0;
            let p2p_up_gbs = (r_p2p_up as f64) / 1_073_741_824.0;
            player_speeds.insert(key.to_string(), serde_json::json!({
                "httpGbps": format!("{:.2}", http_gbs),
                "p2pGbps": format!("{:.2}", p2p_gbs),
                "p2pUpGbps": format!("{:.2}", p2p_up_gbs)
            }));
        }
    }

    let result = serde_json::json!({
        "period": period,
        "timeline": timeline,
        "totals": totals,
        "servers": servers,
        "playerSpeeds": player_speeds
    });

    let body = result.to_string();

    // 캐시 저장 (realtime: 1초, 그 외: 1분 TTL)
    let cache_ttl = if period == "realtime" { 1 } else { 60 };
    let _: Result<(), _> = redis.set_ex(&cache_key, &body, cache_ttl).await;

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .header("x-cache", "MISS")
        .body(axum::body::Body::from(body))
        .unwrap()
}

// 서버별 트래픽 시계열 (기간별)
async fn api_servers_realtime(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("realtime");

    // 기간에 따른 시간 필터와 샘플링
    let (time_filter, sample_by) = match period {
        "1h" => ("timestamp > dateadd('h', -1, now())", "SAMPLE BY 1m"),
        "6h" => ("timestamp > dateadd('h', -6, now())", "SAMPLE BY 5m"),
        "24h" => ("timestamp > dateadd('d', -1, now())", "SAMPLE BY 15m"),
        "7d" => ("timestamp > dateadd('d', -7, now())", "SAMPLE BY 1h"),
        "30d" => ("timestamp > dateadd('d', -30, now())", "SAMPLE BY 4h"),
        _ => ("timestamp > dateadd('m', -10, now())", ""), // realtime: 최근 10분, 샘플링 없음
    };

    // SAMPLE BY 대신 LIMIT으로 데이터 제한
    let limit = match period {
        "realtime" => 1000,
        "1h" => 2000,
        "6h" => 3000,
        "24h" => 5000,
        "7d" => 10000,
        "30d" => 15000,
        _ => 1000,
    };
    let query = format!(
        "SELECT timestamp, server, http_bytes, p2p_bytes, viewers \
         FROM p2p_servers WHERE {} ORDER BY timestamp, server LIMIT {}",
        time_filter, limit
    );
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&query));

    let data: serde_json::Value = match state.client.get(&url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    // 서버별 시계열 구성 (델타 계산)
    let mut server_timelines: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    let mut prev_values: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();

    if let Some(dataset) = data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let ts = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                let server = arr.get(1).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let http = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let viewers = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);

                // 델타 계산
                let (prev_http, prev_p2p) = prev_values.get(&server).copied().unwrap_or((http, p2p));
                let http_delta = (http - prev_http).max(0);
                let p2p_delta = (p2p - prev_p2p).max(0);
                prev_values.insert(server.clone(), (http, p2p));

                let timeline = server_timelines.entry(server.clone()).or_insert(Vec::new());
                timeline.push(serde_json::json!({
                    "ts": ts,
                    "http": http_delta,
                    "p2p": p2p_delta,
                    "viewers": viewers
                }));
            }
        }
    }

    let result = serde_json::json!({ "servers": server_timelines });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(result.to_string()))
        .unwrap()
}

// 서버 시간 API (KST 기준)
async fn api_server_time() -> Json<serde_json::Value> {
    let kst = FixedOffset::east_opt(9 * 3600).unwrap(); // UTC+9
    let now = Utc::now().with_timezone(&kst);
    Json(serde_json::json!({
        "iso": now.format("%Y-%m-%dT%H:%M:%S+09:00").to_string(),
        "timestamp": now.timestamp_millis(),
        "year": now.year(),
        "month": now.month(),
        "day": now.day(),
        "hour": now.hour(),
        "minute": now.minute(),
        "second": now.second(),
        "timezone": "KST",
        "offset": 9
    }))
}

// IP별 사용량 분석 API (실시간 세션 + 기간별 조회)
async fn api_ip_analysis(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(100);
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("realtime");

    // 실시간이 아닌 경우 QuestDB에서 조회
    if period != "realtime" {
        return api_ip_analysis_historical(&state, period, limit).await;
    }

    // 실시간: simple_ws에서 여러 페이지 병렬로 가져오기
    let page_size = 200;
    let num_pages = 50;
    let mut handles = Vec::new();

    for page in 0..num_pages {
        let url = format!("{}/api/sessions?limit={}&offset={}", SIMPLE_WS_URL, page_size, page * page_size);
        let client = state.client.clone();
        handles.push(tokio::spawn(async move {
            match client.get(&url).send().await {
                Ok(r) => r.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({})),
                Err(_) => serde_json::json!({}),
            }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }

    // 모든 페이지의 세션을 합침
    let mut all_sessions: Vec<serde_json::Value> = Vec::new();
    let mut total_sessions: i64 = 0;

    for sessions_data in results {
        if let Some(total) = sessions_data.get("total").and_then(|v| v.as_i64()) {
            total_sessions = total;
        }
        if let Some(data) = sessions_data.get("data").and_then(|d| d.as_array()) {
            all_sessions.extend(data.clone());
        }
    }

    // IP별 트래픽 집계 (서버, 파일명 포함)
    #[derive(Default)]
    struct IpStats {
        sessions: i64,
        http: i64,
        p2p: i64,
        p2p_up: i64,
        server: String,
        filename: String,
    }

    let mut ip_map: std::collections::HashMap<String, IpStats> = std::collections::HashMap::new();
    let mut total_http: i64 = 0;
    let mut total_p2p: i64 = 0;
    let mut total_p2p_up: i64 = 0;

    for session in &all_sessions {
        let ip = session.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if ip.is_empty() { continue; }

        let http = session.get("http_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let p2p = session.get("p2p_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let p2p_up = session.get("p2p_up_bytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let swarm_id = session.get("swarm_id").and_then(|v| v.as_str()).unwrap_or("");
        let server = swarm_id.split('/').next().unwrap_or("").to_string();
        let filename = session.get("filename").and_then(|v| v.as_str()).unwrap_or("").to_string();

        total_http += http;
        total_p2p += p2p;
        total_p2p_up += p2p_up;

        let entry = ip_map.entry(ip).or_default();
        entry.sessions += 1;
        entry.http += http;
        entry.p2p += p2p;
        entry.p2p_up += p2p_up;
        if !server.is_empty() {
            entry.server = server;
        }
        if !filename.is_empty() {
            entry.filename = filename;
        }
    }

    // 총 트래픽 기준 정렬
    let mut ip_list: Vec<_> = ip_map.into_iter().collect();
    ip_list.sort_by(|a, b| (b.1.http + b.1.p2p).cmp(&(a.1.http + a.1.p2p)));

    let unique_ips = ip_list.len() as i64;

    let ips: Vec<serde_json::Value> = ip_list.into_iter()
        .take(limit)
        .map(|(ip, stats)| {
            serde_json::json!({
                "ip": ip,
                "sessions": stats.sessions,
                "httpBytes": stats.http,
                "p2pBytes": stats.p2p,
                "p2pUpBytes": stats.p2p_up,
                "totalBytes": stats.http + stats.p2p,
                "server": stats.server,
                "filename": stats.filename
            })
        })
        .collect();

    let result = serde_json::json!({
        "period": "realtime",
        "totals": {
            "totalSessions": total_sessions,
            "uniqueIps": unique_ips,
            "totalHttp": total_http,
            "totalP2p": total_p2p,
            "totalP2pUp": total_p2p_up
        },
        "ips": ips
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(result.to_string()))
        .unwrap()
}

// 기간별 IP 분석 (QuestDB visitor_logs 기반)
async fn api_ip_analysis_historical(state: &AppState, period: &str, limit: usize) -> Response {
    // timestamp_floor('d', now()) = 오늘 00:00:00 UTC
    let time_filter = match period {
        "1h" => "timestamp > dateadd('h', -1, now())".to_string(),
        "6h" => "timestamp > dateadd('h', -6, now())".to_string(),
        "24h" => "timestamp > dateadd('d', -1, now())".to_string(),
        "today" => "timestamp >= timestamp_floor('d', now())".to_string(),
        "yesterday" => "timestamp >= dateadd('d', -1, timestamp_floor('d', now())) AND timestamp < timestamp_floor('d', now())".to_string(),
        "7d" => "timestamp > dateadd('d', -7, now())".to_string(),
        "this_week" => "timestamp >= timestamp_floor('w', now())".to_string(),
        "last_week" => "timestamp >= dateadd('w', -1, timestamp_floor('w', now())) AND timestamp < timestamp_floor('w', now())".to_string(),
        "30d" => "timestamp > dateadd('d', -30, now())".to_string(),
        "this_month" => "timestamp >= timestamp_floor('M', now())".to_string(),
        "last_month" => "timestamp >= dateadd('M', -1, timestamp_floor('M', now())) AND timestamp < timestamp_floor('M', now())".to_string(),
        _ => "timestamp > dateadd('d', -1, now())".to_string(),
    };

    // IP별 요청수, 트래픽, 마지막 서버
    let ip_query = format!(
        "SELECT ip, count() as sessions, sum(http_bytes) as http, sum(p2p_bytes) as p2p, sum(p2p_up_bytes) as p2p_up, last(swarm_id) as last_swarm \
         FROM visitor_logs WHERE {} AND ip != '' AND ip IS NOT NULL \
         GROUP BY ip ORDER BY (sum(http_bytes) + sum(p2p_bytes)) DESC LIMIT {}",
        time_filter, limit
    );

    // 전체 통계
    let total_query = format!(
        "SELECT count() as total_sessions, sum(http_bytes) as total_http, sum(p2p_bytes) as total_p2p, sum(p2p_up_bytes) as total_p2p_up FROM visitor_logs WHERE {}",
        time_filter
    );

    let unique_query = format!(
        "SELECT count() FROM (SELECT ip FROM visitor_logs WHERE {} GROUP BY ip)",
        time_filter
    );

    // 병렬 쿼리
    let ip_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&ip_query));
    let total_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&total_query));
    let unique_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(&unique_query));

    let (ip_res, total_res, unique_res) = tokio::join!(
        state.client.get(&ip_url).send(),
        state.client.get(&total_url).send(),
        state.client.get(&unique_url).send()
    );

    let ip_data: serde_json::Value = match ip_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let (total_sessions, total_http, total_p2p, total_p2p_up) = match total_res {
        Ok(r) => {
            let data: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({}));
            let row = data.get("dataset").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.as_array());
            if let Some(arr) = row {
                (
                    arr.get(0).and_then(|v| v.as_i64()).unwrap_or(0),
                    arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0),
                    arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0),
                    arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
                )
            } else {
                (0, 0, 0, 0)
            }
        }
        Err(_) => (0, 0, 0, 0),
    };

    let unique_ips = match unique_res {
        Ok(r) => {
            let data: serde_json::Value = r.json().await.unwrap_or(serde_json::json!({}));
            data.get("dataset").and_then(|d| d.as_array()).and_then(|a| a.first())
                .and_then(|r| r.as_array()).and_then(|r| r.first()).and_then(|v| v.as_i64()).unwrap_or(0)
        }
        Err(_) => 0,
    };

    let mut ips: Vec<serde_json::Value> = Vec::new();
    if let Some(dataset) = ip_data.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let ip = arr.get(0).and_then(|v| v.as_str()).unwrap_or("-");
                if ip.is_empty() { continue; }
                let sessions = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let http_bytes = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_bytes = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_up_bytes = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
                let last_swarm = arr.get(5).and_then(|v| v.as_str()).unwrap_or("");
                let server = last_swarm.split('/').next().unwrap_or("").to_string();

                ips.push(serde_json::json!({
                    "ip": ip,
                    "sessions": sessions,
                    "httpBytes": http_bytes,
                    "p2pBytes": p2p_bytes,
                    "p2pUpBytes": p2p_up_bytes,
                    "totalBytes": http_bytes + p2p_bytes,
                    "server": server
                }));
            }
        }
    }

    let result = serde_json::json!({
        "period": period,
        "totals": {
            "totalSessions": total_sessions,
            "totalHttp": total_http,
            "totalP2p": total_p2p,
            "totalP2pUp": total_p2p_up,
            "uniqueIps": unique_ips
        },
        "ips": ips
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(result.to_string()))
        .unwrap()
}

// ============ 인증 시스템 ============

async fn login_page() -> impl IntoResponse {
    axum::response::Html(r#"<!DOCTYPE html>
<html><head>
<meta charset="utf-8"><title>Admin Login</title>
<style>
body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #eee; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
.login-box { background: #16213e; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
h1 { margin: 0 0 30px; text-align: center; color: #00d9ff; }
input { width: 100%; padding: 12px; margin: 10px 0; border: none; border-radius: 5px; background: #1a1a2e; color: #eee; box-sizing: border-box; }
button { width: 100%; padding: 12px; margin-top: 20px; border: none; border-radius: 5px; background: #00d9ff; color: #000; font-weight: bold; cursor: pointer; }
button:hover { background: #00b8d4; }
.error { color: #ff6b6b; text-align: center; margin-top: 15px; }
</style>
</head><body>
<div class="login-box">
<h1>🔐 Admin Login</h1>
<form id="loginForm">
<input type="text" id="username" placeholder="Username" required>
<input type="password" id="password" placeholder="Password" required>
<button type="submit">Login</button>
<div id="error" class="error"></div>
</form>
</div>
<script>
document.getElementById('loginForm').onsubmit = async (e) => {
    e.preventDefault();
    const res = await fetch('/auth/login', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        credentials: 'same-origin',
        body: JSON.stringify({
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        })
    });
    const data = await res.json();
    if (data.success) {
        window.location.href = '/';
    } else {
        document.getElementById('error').textContent = data.error || 'Login failed';
    }
};
</script>
</body></html>"#)
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

async fn auth_login(cookies: Cookies, Json(req): Json<LoginRequest>) -> impl IntoResponse {
    if verify_credentials(&req.username, &req.password).await {
        let session_id = format!("{:x}", rand::random::<u128>());
        SESSIONS.write().insert(session_id.clone(), req.username.clone());
        save_session_to_db(&session_id, &req.username);

        let cookie = Cookie::build(("session", session_id))
            .path("/")
            .http_only(true)
            .same_site(tower_cookies::cookie::SameSite::Lax)
            .max_age(time::Duration::days(7))
            .build();
        cookies.add(cookie);

        Json(serde_json::json!({"success": true}))
    } else {
        Json(serde_json::json!({"success": false, "error": "Invalid credentials"}))
    }
}

async fn auth_logout(cookies: Cookies) -> impl IntoResponse {
    if let Some(session) = cookies.get("session") {
        SESSIONS.write().remove(session.value());
    }
    cookies.remove(Cookie::from("session"));
    Json(serde_json::json!({"success": true}))
}

async fn auth_check(cookies: Cookies) -> impl IntoResponse {
    let authenticated = cookies.get("session")
        .map(|c| SESSIONS.read().contains_key(c.value()))
        .unwrap_or(false);
    Json(serde_json::json!({"authenticated": authenticated}))
}

async fn auth_middleware(
    State(_state): State<AppState>,
    cookies: Cookies,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path();

    let method = request.method().clone();

    // 공개 경로 (인증 불필요)
    let public_paths = [
        "/login", "/auth/", "/api/agent/", "/agent/",
        "/api/servers/status", "/api/servers/report", "/api/servers/logs",  // 에이전트 상태 보고 (자체 시크릿 검증)
        "/api/blacklist/pending", "/api/blacklist/confirm",  // 에이전트 차단 폴링/확인
        // 읽기 전용 API
        "/api/realtime", "/api/live", "/api/sessions", "/api/ip_stats", "/api/stats",
        "/api/history/", "/api/popular", "/api/summary", "/api/visitors", "/api/traffic",
        "/api/server-time", "/api/ip-analysis", "/api/init-data", "/ws"
    ];
    if public_paths.iter().any(|p| path.starts_with(p)) {
        return next.run(request).await;
    }

    // GET 요청만 허용하는 경로
    let public_get_paths = ["/api/servers", "/api/blacklist", "/api/settings/cloudflare"];
    if method == axum::http::Method::GET && public_get_paths.iter().any(|p| path.starts_with(p)) {
        return next.run(request).await;
    }

    // 정적 파일
    if path.starts_with("/static/") || path == "/favicon.ico" || path == "/" || path.ends_with(".html") || path.ends_with(".js") || path.ends_with(".css") {
        return next.run(request).await;
    }

    // 세션 확인
    let authenticated = cookies.get("session")
        .map(|c| SESSIONS.read().contains_key(c.value()))
        .unwrap_or(false);

    if !authenticated {
        if path.starts_with("/api/") {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"error":"Unauthorized"}"#))
                .unwrap();
        }
        return Redirect::to("/login").into_response();
    }

    next.run(request).await
}

// ============ 블랙리스트 API ============

async fn api_blacklist_list() -> impl IntoResponse {
    // 먼저 데이터 복사 (락 빠르게 해제)
    let (blocked_data, pending_data, server_id_to_name): (Vec<_>, Vec<_>, HashMap<String, String>) = {
        let blocked = BLOCKED_SERVERS.read();
        let pending = PENDING_BLOCKS.read();
        let servers = EXTERNAL_SERVERS.read();
        let b: Vec<_> = blocked.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        let p: Vec<_> = pending.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        // 서버 ID → 이름 매핑 (컨테이너ID → 서버번호)
        let id_map: HashMap<String, String> = servers.iter()
            .map(|(_, s)| (s.id.clone(), s.name.clone()))
            .collect();
        (b, p, id_map)
    };

    // 서버 ID 정규화 함수 (컨테이너 ID → 서버 이름, 중복 제거)
    let normalize_servers = |servers: &[String]| -> Vec<String> {
        let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for s in servers {
            // 컨테이너 ID면 서버 이름으로 변환, 아니면 그대로 사용
            let name = server_id_to_name.get(s).cloned().unwrap_or_else(|| s.clone());
            names.insert(name);
        }
        let mut result: Vec<String> = names.into_iter().collect();
        // 숫자 정렬 시도
        result.sort_by(|a, b| {
            match (a.parse::<i32>(), b.parse::<i32>()) {
                (Ok(na), Ok(nb)) => na.cmp(&nb),
                _ => a.cmp(b)
            }
        });
        result
    };

    // 모든 IP 수집
    let all_ips: Vec<String> = blocked_data.iter().map(|(k, _)| k.clone())
        .chain(pending_data.iter().map(|(k, _)| k.clone()))
        .collect();

    // IP별 first_seen, last_seen 조회
    let mut ip_times: HashMap<String, (String, String)> = HashMap::new();
    if !all_ips.is_empty() {
        let ips_filter = all_ips.iter()
            .map(|ip| format!("'{}'", ip))
            .collect::<Vec<_>>()
            .join(",");

        let query = format!(r#"
            SELECT client_ip, min(timestamp) as first_seen, max(timestamp) as last_seen
            FROM nginx_logs
            WHERE client_ip IN ({})
            GROUP BY client_ip
        "#, ips_filter);

        let client = reqwest::Client::new();
        if let Ok(resp) = client.get("http://localhost:9002/exec")
            .query(&[("query", &query)])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data["dataset"].as_array() {
                    for row in dataset {
                        let ip = row[0].as_str().unwrap_or("").to_string();
                        let first = row[1].as_str().unwrap_or("").to_string();
                        let last = row[2].as_str().unwrap_or("").to_string();
                        ip_times.insert(ip, (first, last));
                    }
                }
            }
        }
    }

    let mut items: Vec<serde_json::Value> = Vec::new();

    for (ip, cmd) in blocked_data {
        let (first_seen, last_seen) = ip_times.get(&ip)
            .cloned()
            .unwrap_or_default();
        let normalized = normalize_servers(&cmd.servers_blocked);
        items.push(serde_json::json!({
            "ip": ip,
            "reason": cmd.reason,
            "blocked_at": cmd.created_at,
            "cf_blocked": cmd.cf_blocked,
            "blocked_servers": normalized,
            "status": "blocked",
            "first_seen": first_seen,
            "last_seen": last_seen
        }));
    }

    for (ip, cmd) in pending_data {
        let (first_seen, last_seen) = ip_times.get(&ip)
            .cloned()
            .unwrap_or_default();
        let normalized = normalize_servers(&cmd.servers_blocked);
        items.push(serde_json::json!({
            "ip": ip,
            "reason": cmd.reason,
            "blocked_at": cmd.created_at,
            "cf_blocked": cmd.cf_blocked,
            "blocked_servers": normalized,
            "status": "pending",
            "first_seen": first_seen,
            "last_seen": last_seen
        }));
    }

    Json(serde_json::json!({"blacklist": items}))
}

#[derive(Deserialize)]
struct BlockRequest {
    ip: String,
    reason: String,
}

async fn api_blacklist_block(Json(req): Json<BlockRequest>) -> Json<serde_json::Value> {
    let ip = req.ip.trim().to_string();
    let reason = req.reason.trim().to_string();

    // IP 형식 검증
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Json(serde_json::json!({"success": false, "error": "Invalid IP format"}));
    }

    // 이미 차단된 경우
    if BLOCKED_SERVERS.read().contains_key(&ip) {
        return Json(serde_json::json!({"success": false, "error": "IP already blocked"}));
    }

    let cmd = BlockCommand {
        ip: ip.clone(),
        reason: reason.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        cf_blocked: false,
        servers_blocked: Vec::new(),
    };

    PENDING_BLOCKS.write().insert(ip.clone(), cmd);

    // Cloudflare 차단 시도
    let cf_result = block_ip_cloudflare(&ip, &reason).await;

    // 서버 개수 확인
    let server_count = EXTERNAL_SERVERS.read().len();

    // pending에서 blocked로 이동 (에이전트가 confirm하면 servers_blocked 업데이트됨)
    PENDING_BLOCKS.write().remove(&ip);

    let final_cmd = BlockCommand {
        ip: ip.clone(),
        reason: reason.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
        cf_blocked: cf_result,
        servers_blocked: Vec::new(), // 에이전트가 confirm하면 채워짐
    };

    BLOCKED_SERVERS.write().insert(ip.clone(), final_cmd);
    save_blocked_list();

    // 이벤트 기록
    add_server_event("system", &format!("IP {} 차단됨 (CF: {}, 에이전트: {}대 대기)", ip, cf_result, server_count));

    Json(serde_json::json!({
        "success": true,
        "cf_blocked": cf_result,
        "servers_pending": server_count
    }))
}

async fn api_blacklist_unblock(Json(req): Json<BlockRequest>) -> Json<serde_json::Value> {
    let ip = req.ip.trim().to_string();

    // 차단 해제
    let was_blocked = BLOCKED_SERVERS.write().remove(&ip).is_some();
    PENDING_BLOCKS.write().remove(&ip);

    if !was_blocked {
        return Json(serde_json::json!({"success": false, "error": "IP not in blacklist"}));
    }

    // Cloudflare 해제
    let _ = unblock_ip_cloudflare(&ip).await;

    // 모든 서버에 해제 명령
    let servers: Vec<(String, String)> = {
        let guard = EXTERNAL_SERVERS.read();
        guard.iter().map(|(_name, s)| (s.url.clone(), s.ip.clone())).collect()
    };
    let secret = AGENT_SECRET.read().clone();
    let client = reqwest::Client::new();

    for (server_url, server_ip) in &servers {
        let base_url = if !server_url.is_empty() {
            server_url.clone()
        } else if !server_ip.is_empty() {
            format!("http://{}:8081", server_ip)
        } else {
            continue;
        };
        let url = format!("{}/unblock", base_url);
        let _ = client.post(&url)
            .header("X-Agent-Secret", secret.clone())
            .json(&serde_json::json!({"ip": ip}))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
    }

    save_blocked_list();
    add_server_event("system", &format!("IP {} 차단 해제됨", ip));

    Json(serde_json::json!({"success": true}))
}

fn save_blocked_list() {
    // 락을 짧게 유지하고 복사본으로 저장 (데드락 방지)
    let data: HashMap<String, BlockCommand> = BLOCKED_SERVERS.read().clone();
    if let Ok(json) = serde_json::to_string_pretty(&data) {
        let _ = std::fs::write("data/blocked_ips.json", json);
    }
}

// ============ Cloudflare API ============

async fn block_ip_cloudflare(ip: &str, reason: &str) -> bool {
    let (enabled, email, api_key) = {
        let settings = CF_SETTINGS.read();
        (settings.enabled, settings.email.clone(), settings.api_key.clone())
    };

    if !enabled || email.is_empty() || api_key.is_empty() {
        return false;
    }

    let client = reqwest::Client::new();
    // User-level Global API
    let url = "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules";

    let res = client.post(url)
        .header("X-Auth-Email", &email)
        .header("X-Auth-Key", &api_key)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({
            "mode": "block",
            "configuration": {
                "target": "ip",
                "value": ip
            },
            "notes": format!("Auto-blocked: {}", reason)
        }))
        .send()
        .await;

    match res {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

async fn unblock_ip_cloudflare(ip: &str) -> bool {
    let (enabled, email, api_key) = {
        let settings = CF_SETTINGS.read();
        (settings.enabled, settings.email.clone(), settings.api_key.clone())
    };

    if !enabled || email.is_empty() || api_key.is_empty() {
        return false;
    }

    let client = reqwest::Client::new();

    // User-level API로 규칙 ID 찾기
    let list_url = format!(
        "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules?configuration.value={}",
        ip
    );

    let res = client.get(&list_url)
        .header("X-Auth-Email", &email)
        .header("X-Auth-Key", &api_key)
        .send()
        .await;

    if let Ok(resp) = res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(rules) = data["result"].as_array() {
                for rule in rules {
                    if let Some(id) = rule["id"].as_str() {
                        let delete_url = format!(
                            "https://api.cloudflare.com/client/v4/user/firewall/access_rules/rules/{}",
                            id
                        );
                        let _ = client.delete(&delete_url)
                            .header("X-Auth-Email", &email)
                            .header("X-Auth-Key", &api_key)
                            .send()
                            .await;
                    }
                }
                return true;
            }
        }
    }

    false
}

async fn api_cf_settings_get() -> impl IntoResponse {
    let settings = CF_SETTINGS.read();
    // 프론트엔드 호환: accounts 배열 형식
    let accounts = if settings.enabled && !settings.email.is_empty() && !settings.api_key.is_empty() {
        vec![serde_json::json!({
            "email": settings.email,
            "has_key": true
        })]
    } else {
        vec![]
    };
    Json(serde_json::json!({
        "status": "ok",
        "enabled": settings.enabled,
        "email": settings.email,
        "has_key": !settings.api_key.is_empty(),
        "accounts": accounts
    }))
}

#[derive(Deserialize)]
struct CfSettingsRequest {
    enabled: Option<bool>,
    email: Option<String>,
    api_key: Option<String>,
}

async fn api_cf_settings_set(Json(req): Json<CfSettingsRequest>) -> impl IntoResponse {
    let mut settings = CF_SETTINGS.write();

    if let Some(enabled) = req.enabled {
        settings.enabled = enabled;
    }
    if let Some(email) = req.email {
        settings.email = email;
    }
    if let Some(api_key) = req.api_key {
        if !api_key.is_empty() {
            settings.api_key = api_key;
        }
    }

    // 저장
    let save_data = serde_json::json!({
        "enabled": settings.enabled,
        "email": settings.email,
        "api_key": settings.api_key
    });
    let _ = std::fs::write("data/cf_settings.json", save_data.to_string());

    Json(serde_json::json!({"success": true}))
}

// ============ 에이전트 API ============

#[derive(Deserialize)]
struct AgentReportRequest {
    server_name: String,
    status: String,
    #[serde(default)]
    blocked_ips: Vec<String>,
}

async fn api_agent_report(
    headers: HeaderMap,
    Json(req): Json<AgentReportRequest>,
) -> impl IntoResponse {
    // 시크릿 검증
    let secret = headers.get("X-Agent-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_agent_secret(secret) {
        return Json(serde_json::json!({"error": "Invalid secret"}));
    }

    // 서버 정보 업데이트
    let mut servers = EXTERNAL_SERVERS.write();
    if let Some(server) = servers.get_mut(&req.server_name) {
        server.last_seen = Some(chrono::Utc::now());
        server.blocked_ips = req.blocked_ips;
    }

    // 대기 중인 차단 명령 반환
    let pending: Vec<serde_json::Value> = PENDING_BLOCKS.read()
        .iter()
        .map(|(ip, cmd)| serde_json::json!({"ip": ip, "reason": &cmd.reason}))
        .collect();

    Json(serde_json::json!({
        "success": true,
        "pending_blocks": pending
    }))
}

async fn api_agent_register(
    headers: HeaderMap,
    Json(req): Json<serde_json::Value>,
) -> impl IntoResponse {
    let secret = headers.get("X-Agent-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_agent_secret(secret) {
        return Json(serde_json::json!({"error": "Invalid secret"}));
    }

    let server_name = req["server_name"].as_str().unwrap_or("unknown").to_string();
    let url = req["url"].as_str().unwrap_or("").to_string();

    let server = ExternalServer {
        id: server_name.clone(),
        name: server_name.clone(),
        url,
        last_seen: Some(chrono::Utc::now()),
        online: true,
        ..Default::default()
    };

    EXTERNAL_SERVERS.write().insert(server_name.clone(), server);
    add_server_event(&server_name, "에이전트 등록됨");

    Json(serde_json::json!({"success": true}))
}

// ============ 어뷰저 탐지 API ============

async fn api_logs_abusers(Query(params): Query<HashMap<String, String>>) -> Json<serde_json::Value> {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(30i32);
    let cache_key = format!("{}_{}", period, limit);

    // ========== 캐시 확인 (30초 TTL) ==========
    {
        let cache = ABUSER_CACHE.read();
        if let Some(entry) = cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                return Json(entry.data.clone());
            }
        }
    }

    // ========== 동시 쿼리 제한 (최대 2개) ==========
    let _permit = match HEAVY_QUERY_SEMAPHORE.try_acquire() {
        Ok(permit) => Some(permit),
        Err(_) => {
            // 이미 2개 쿼리 실행 중 - 캐시된 값 반환 (만료되어도)
            let cache = ABUSER_CACHE.read();
            if let Some(entry) = cache.get(&cache_key) {
                return Json(entry.data.clone());
            }
            // 캐시도 없으면 빈 결과 반환 (과부하 방지)
            return Json(serde_json::json!({"abusers": [], "cached": false, "busy": true}));
        }
    };

    // 다시 캐시 확인 (다른 요청이 캐시를 채웠을 수 있음)
    {
        let cache = ABUSER_CACHE.read();
        if let Some(entry) = cache.get(&cache_key) {
            if entry.expires_at > Instant::now() {
                return Json(entry.data.clone());
            }
        }
    }

    let client = reqwest::Client::new();

    let time_filter = match period {
        "1h" => "dateadd('h', -1, now())",
        "3h" => "dateadd('h', -3, now())",
        "6h" => "dateadd('h', -6, now())",
        "12h" => "dateadd('h', -12, now())",
        "24h" => "dateadd('d', -1, now())",
        _ => "dateadd('h', -6, now())",
    };

    let period_seconds = match period {
        "1h" => 3600.0,
        "3h" => 10800.0,
        "6h" => 21600.0,
        "12h" => 43200.0,
        "24h" => 86400.0,
        _ => 21600.0,
    };

    // ========== 고도화된 쿼리들 (병렬 실행) ==========
    // count_distinct는 GROUP BY와 함께 사용 시 매우 느림 - 제거

    // 1. 기본 트래픽 통계 (count_distinct 제거)
    let query = format!(r#"
        SELECT client_ip, count() as requests, sum(bytes_sent) as total_bytes,
               min(timestamp) as first_seen, max(timestamp) as last_seen
        FROM nginx_logs
        WHERE timestamp > {} AND status = 200
        GROUP BY client_ip
        ORDER BY total_bytes DESC
        LIMIT {}
    "#, time_filter, (limit * 5).max(150));

    // 2. IP별 서버 목록 (5000개 - 더 많은 IP 커버리지)
    let servers_query = format!(r#"
        SELECT client_ip, server_id, count() as cnt
        FROM nginx_logs
        WHERE timestamp > {} AND status = 200
        GROUP BY client_ip, server_id
        ORDER BY cnt DESC
        LIMIT 5000
    "#, time_filter);

    // 3. 100초 단위 버스트 분석 - 최대 6시간 (속도 최적화)
    let burst_time = match period {
        "1h" => "dateadd('h', -1, now())",
        "3h" => "dateadd('h', -3, now())",
        _ => "dateadd('h', -6, now())",  // 6h 이상은 6h로 제한
    };
    let max100s_query = format!(r#"
        SELECT client_ip, max(cnt) as max_req
        FROM (
            SELECT client_ip, count() as cnt
            FROM nginx_logs
            WHERE timestamp > {} AND status = 200
            SAMPLE BY 100s ALIGN TO CALENDAR
        )
        GROUP BY client_ip
        ORDER BY max_req DESC
        LIMIT 300
    "#, burst_time);

    // 4. 동일 경로 반복 접근 (단일 비디오 어뷰즈) - 최대 3시간 (속도 최적화)
    let single_path_time = match period {
        "1h" => "dateadd('h', -1, now())",
        _ => "dateadd('h', -3, now())",  // 모든 기간 3h로 제한 (속도)
    };
    let single_path_query = format!(r#"
        SELECT client_ip, path, count() as cnt, sum(bytes_sent) as bytes
        FROM nginx_logs
        WHERE timestamp > {} AND status = 200
        GROUP BY client_ip, path
        ORDER BY cnt DESC
        LIMIT 300
    "#, single_path_time);

    // 5. 캐시 우회 탐지 (세그먼트 파일에 쿼리스트링 추가 - .gif? 패턴)
    let cache_bypass_query = format!(r#"
        SELECT client_ip, count() as cnt
        FROM nginx_logs
        WHERE timestamp > {} AND status = 200
          AND path ~ '\.gif\?'
        GROUP BY client_ip
        ORDER BY cnt DESC
        LIMIT 200
    "#, time_filter);

    // 모든 쿼리 병렬 실행
    let (res, servers_res, max100s_res, single_path_res, cache_bypass_res) = tokio::join!(
        client.get("http://localhost:9002/exec")
            .query(&[("query", &query)])
            .timeout(std::time::Duration::from_secs(20))
            .send(),
        client.get("http://localhost:9002/exec")
            .query(&[("query", &servers_query)])
            .timeout(std::time::Duration::from_secs(20))
            .send(),
        client.get("http://localhost:9002/exec")
            .query(&[("query", &max100s_query)])
            .timeout(std::time::Duration::from_secs(20))
            .send(),
        client.get("http://localhost:9002/exec")
            .query(&[("query", &single_path_query)])
            .timeout(std::time::Duration::from_secs(20))
            .send(),
        client.get("http://localhost:9002/exec")
            .query(&[("query", &cache_bypass_query)])
            .timeout(std::time::Duration::from_secs(10))
            .send()
    );

    // ========== 데이터 파싱 ==========

    // IP -> 100초 최대 요청
    let mut ip_max100s: HashMap<String, i64> = HashMap::new();
    if let Ok(resp) = max100s_res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["dataset"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("").to_string();
                    let max_req = row[1].as_i64().unwrap_or(0);
                    ip_max100s.insert(ip, max_req);
                }
            }
        }
    }

    // IP -> 단일 경로 최대 반복 횟수 + 경로 수
    let mut ip_max_single_path: HashMap<String, (i64, i64)> = HashMap::new(); // (횟수, 바이트)
    let mut ip_path_count: HashMap<String, i64> = HashMap::new(); // IP별 고유 경로 수
    if let Ok(resp) = single_path_res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["dataset"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("").to_string();
                    let cnt = row[2].as_i64().unwrap_or(0);
                    let bytes = row[3].as_i64().unwrap_or(0);
                    // 고유 경로 수 카운트
                    *ip_path_count.entry(ip.clone()).or_insert(0) += 1;
                    // 최대 반복 경로 추적
                    let entry = ip_max_single_path.entry(ip).or_insert((0, 0));
                    if cnt > entry.0 {
                        *entry = (cnt, bytes);
                    }
                }
            }
        }
    }

    // IP -> 캐시 우회 요청 수 (.gif? 패턴)
    let mut ip_cache_bypass: HashMap<String, i64> = HashMap::new();
    if let Ok(resp) = cache_bypass_res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["dataset"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("").to_string();
                    let cnt = row[1].as_i64().unwrap_or(0);
                    ip_cache_bypass.insert(ip, cnt);
                }
            }
        }
    }

    // server_id -> server_name
    let server_name_map: HashMap<String, String> = {
        let servers = EXTERNAL_SERVERS.read();
        servers.iter().map(|(_, s)| (s.id.clone(), s.name.clone())).collect()
    };
    let total_servers = server_name_map.len();

    // IP -> 서버 목록
    let mut ip_servers: HashMap<String, Vec<String>> = HashMap::new();
    if let Ok(resp) = servers_res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["dataset"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("").to_string();
                    let server_id = row[1].as_str().unwrap_or("").to_string();
                    if !server_id.is_empty() {
                        let server_name = server_name_map.get(&server_id)
                            .cloned()
                            .unwrap_or_else(|| server_id.chars().take(6).collect());
                        ip_servers.entry(ip).or_default().push(server_name);
                    }
                }
            }
        }
    }

    // ========== 점수 계산 ==========
    let mut abusers = Vec::new();

    if let Ok(resp) = res {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["dataset"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("");
                    let requests = row[1].as_i64().unwrap_or(0);
                    let total_bytes = row[2].as_i64().unwrap_or(0);
                    let first_seen = row[3].as_str().unwrap_or("");
                    let last_seen = row[4].as_str().unwrap_or("");
                    // unique_paths와 unique_agents는 single_path와 servers 쿼리에서 추정
                    let unique_paths = ip_path_count.get(ip).copied().unwrap_or(1) as i64;
                    let unique_agents = ip_servers.get(ip).map(|s| s.len()).unwrap_or(1) as i64;

                    let gb = total_bytes as f64 / 1024.0 / 1024.0 / 1024.0;
                    if gb < 0.1 { continue; }  // 0.1GB (100MB) 미만 스킵

                    let mut score: i32 = 0;
                    let mut reasons = Vec::new();
                    let mut flags = Vec::new();

                    // ===== 패턴 1: 트래픽 양 (최대 60점) =====
                    if gb > 30.0 {
                        score += 60;
                        reasons.push(format!("🔴 극대용량: {:.1}GB", gb));
                        flags.push("EXTREME_TRAFFIC");
                    } else if gb > 15.0 {
                        score += 45;
                        reasons.push(format!("🟠 대용량: {:.1}GB", gb));
                        flags.push("HIGH_TRAFFIC");
                    } else if gb > 8.0 {
                        score += 30;
                        reasons.push(format!("🟡 높은 트래픽: {:.1}GB", gb));
                    } else if gb > 3.0 {
                        score += 15;
                        reasons.push(format!("중간 트래픽: {:.1}GB", gb));
                    }

                    // ===== 패턴 2: 100초 버스트 (최대 80점) =====
                    let max_req_100s = ip_max100s.get(ip).copied().unwrap_or(0);
                    if max_req_100s > 500 {
                        score += 80;
                        reasons.push(format!("🔴 극심한 버스트: {}req/100s", max_req_100s));
                        flags.push("EXTREME_BURST");
                    } else if max_req_100s > 200 {
                        score += 50;
                        reasons.push(format!("🟠 높은 버스트: {}req/100s", max_req_100s));
                        flags.push("HIGH_BURST");
                    } else if max_req_100s > 100 {
                        score += 30;
                        reasons.push(format!("🟡 버스트: {}req/100s", max_req_100s));
                    }

                    // ===== 패턴 3: 단일 비디오 어뷰즈 (최대 100점) =====
                    if let Some((single_cnt, single_bytes)) = ip_max_single_path.get(ip) {
                        let single_ratio = *single_cnt as f64 / requests.max(1) as f64;
                        let single_gb = *single_bytes as f64 / 1024.0 / 1024.0 / 1024.0;

                        if single_ratio > 0.8 && single_gb > 5.0 {
                            score += 100;
                            reasons.push(format!("🔴 단일비디오 어뷰즈: {:.0}% ({:.1}GB)", single_ratio * 100.0, single_gb));
                            flags.push("SINGLE_VIDEO_ABUSE");
                        } else if single_ratio > 0.6 && single_gb > 2.0 {
                            score += 60;
                            reasons.push(format!("🟠 반복다운로드: {:.0}%", single_ratio * 100.0));
                            flags.push("REPEATED_DOWNLOAD");
                        } else if *single_cnt > 200 {
                            score += 30;
                            reasons.push(format!("🟡 동일경로 반복: {}회", single_cnt));
                        }
                    }

                    // ===== 패턴 4: 멀티서버 공격 (최대 50점) =====
                    let servers: Vec<String> = ip_servers.get(ip).cloned().unwrap_or_default();
                    let server_count = servers.len();
                    if total_servers > 0 && server_count >= total_servers && gb > 5.0 {
                        score += 50;
                        reasons.push(format!("🔴 전체서버 공격: {}/{}대", server_count, total_servers));
                        flags.push("ALL_SERVERS_ATTACK");
                    } else if server_count > total_servers / 2 && gb > 3.0 {
                        score += 25;
                        reasons.push(format!("🟠 다수서버 접근: {}/{}대", server_count, total_servers));
                    }

                    // ===== 패턴 5: User-Agent 다중 사용 (봇 의심) =====
                    if unique_agents > 5 && requests > 100 {
                        score += 35;
                        reasons.push(format!("🟠 다중 UA: {}개", unique_agents));
                        flags.push("MULTI_UA");
                    } else if unique_agents > 3 {
                        score += 15;
                        reasons.push(format!("🟡 UA 변경: {}개", unique_agents));
                    }

                    // ===== 패턴 6: 요청당 바이트 (대용량 세그먼트) =====
                    let bytes_per_req = if requests > 0 { total_bytes / requests } else { 0 };
                    let mb_per_req = bytes_per_req as f64 / 1024.0 / 1024.0;
                    if mb_per_req > 10.0 {
                        score += 25;
                        reasons.push(format!("대형 세그먼트: {:.1}MB/req", mb_per_req));
                    }

                    // ===== 패턴 7: 시간당 트래픽 (최대 50점) =====
                    let activity_hours = if !first_seen.is_empty() && !last_seen.is_empty() {
                        let first_ts = format!("{}Z", first_seen.replace(" ", "T").trim_end_matches('Z'));
                        let last_ts = format!("{}Z", last_seen.replace(" ", "T").trim_end_matches('Z'));
                        if let (Ok(first), Ok(last)) = (
                            chrono::DateTime::parse_from_rfc3339(&first_ts),
                            chrono::DateTime::parse_from_rfc3339(&last_ts)
                        ) {
                            (last.signed_duration_since(first).num_seconds() as f64 / 3600.0).max(0.1)
                        } else { 1.0 }
                    } else { 1.0 };

                    let gb_per_hour = gb / activity_hours;
                    if gb_per_hour > 20.0 {
                        score += 50;
                        reasons.push(format!("🔴 극고속: {:.1}GB/h", gb_per_hour));
                        flags.push("EXTREME_SPEED");
                    } else if gb_per_hour > 10.0 {
                        score += 30;
                        reasons.push(format!("🟠 고속: {:.1}GB/h", gb_per_hour));
                    } else if gb_per_hour > 5.0 {
                        score += 15;
                        reasons.push(format!("🟡 빠른 다운: {:.1}GB/h", gb_per_hour));
                    }

                    // ===== 패턴 8: 경로 다양성 낮음 =====
                    let path_ratio = unique_paths as f64 / requests.max(1) as f64;
                    if path_ratio < 0.01 && requests > 500 {
                        score += 30;
                        reasons.push(format!("🟡 낮은 경로다양성: {:.1}%", path_ratio * 100.0));
                    }

                    // ===== 캐시 우회 공격 (확정 악성 - 300점) =====
                    // 세그먼트 파일(.gif)에 쿼리스트링 추가하여 캐시 우회 시도
                    let cache_bypass_cnt = ip_cache_bypass.get(ip).copied().unwrap_or(0);
                    if cache_bypass_cnt > 0 {
                        score = 300;
                        reasons.push(format!("🔴 캐시우회 공격: .gif? 패턴 {}회", cache_bypass_cnt));
                        flags.push("CACHE_BYPASS");
                        flags.push("CONFIRMED_ABUSER");
                    }

                    // ===== 확정 악성 유저 (300점 부여) =====
                    // 조건: 단일비디오 어뷰즈 + 전체서버 공격 + 10GB 이상
                    let is_confirmed_abuser = flags.contains(&"SINGLE_VIDEO_ABUSE")
                        && (flags.contains(&"ALL_SERVERS_ATTACK") || gb > 10.0);

                    // 또는: 극심한 버스트 + 극대용량
                    let is_confirmed_abuser2 = flags.contains(&"EXTREME_BURST")
                        && flags.contains(&"EXTREME_TRAFFIC");

                    if is_confirmed_abuser || is_confirmed_abuser2 {
                        score = 300;
                        flags.push("CONFIRMED_ABUSER");
                    }

                    // 위험도 레벨
                    let risk_level = if score >= 300 {
                        "confirmed"
                    } else if score >= 150 {
                        "critical"
                    } else if score >= 100 {
                        "high"
                    } else if score >= 50 {
                        "medium"
                    } else {
                        "low"
                    };

                    // 10점 미만은 스킵
                    if score < 10 { continue; }

                    let already_blocked = BLOCKED_SERVERS.read().contains_key(ip);
                    let req_per_sec = requests as f64 / period_seconds;

                    abusers.push(serde_json::json!({
                        "ip": ip,
                        "requests": requests,
                        "totalBytes": total_bytes,
                        "gb": format!("{:.1}", gb),
                        "gb_per_hour": format!("{:.1}", gb_per_hour),
                        "avg_req_per_sec": format!("{:.2}", req_per_sec),
                        "max_req_100s": max_req_100s,
                        "unique_paths": unique_paths,
                        "unique_agents": unique_agents,
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "score": score,
                        "risk_score": score,
                        "risk_level": risk_level,
                        "reasons": reasons,
                        "flags": flags,
                        "servers": servers,
                        "alreadyBlocked": already_blocked
                    }));
                }
            }
        }
    }

    // 점수순 정렬 후 limit 적용
    abusers.sort_by(|a, b| {
        let sa = a["score"].as_i64().unwrap_or(0);
        let sb = b["score"].as_i64().unwrap_or(0);
        sb.cmp(&sa)
    });
    abusers.truncate(limit as usize);

    // ========== 서버 정보 누락 IP 보완 ==========
    let missing_server_ips: Vec<String> = abusers.iter()
        .filter(|a| a["servers"].as_array().map(|arr| arr.is_empty()).unwrap_or(true))
        .filter_map(|a| a["ip"].as_str().map(|s| s.to_string()))
        .collect();

    if !missing_server_ips.is_empty() {
        let ips_filter = missing_server_ips.iter()
            .map(|ip| format!("'{}'", ip))
            .collect::<Vec<_>>()
            .join(",");

        let missing_query = format!(r#"
            SELECT client_ip, server_id, count() as cnt
            FROM nginx_logs
            WHERE timestamp > {} AND status = 200 AND client_ip IN ({})
            GROUP BY client_ip, server_id
        "#, time_filter, ips_filter);

        if let Ok(resp) = client.get("http://localhost:9002/exec")
            .query(&[("query", &missing_query)])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
        {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data["dataset"].as_array() {
                    let mut ip_server_map: HashMap<String, Vec<String>> = HashMap::new();
                    for row in dataset {
                        let ip = row[0].as_str().unwrap_or("").to_string();
                        let server_id = row[1].as_str().unwrap_or("").to_string();
                        if !server_id.is_empty() {
                            let server_name = server_name_map.get(&server_id)
                                .cloned()
                                .unwrap_or_else(|| server_id.chars().take(6).collect());
                            ip_server_map.entry(ip).or_default().push(server_name);
                        }
                    }

                    // abusers 업데이트
                    for abuser in &mut abusers {
                        if let Some(ip) = abuser["ip"].as_str() {
                            if let Some(servers) = ip_server_map.get(ip) {
                                abuser["servers"] = serde_json::json!(servers);
                            }
                        }
                    }
                }
            }
        }
    }

    // ========== 서버 측 자동 차단 (85점 이상) ==========
    let auto_block_threshold = 85i64;
    let mut to_block: Vec<(String, String, Vec<String>, usize)> = Vec::new();

    // 차단할 IP 수집
    for (idx, abuser) in abusers.iter().enumerate() {
        let score = abuser["score"].as_i64().unwrap_or(0);
        let already_blocked = abuser["alreadyBlocked"].as_bool().unwrap_or(false);

        if score >= auto_block_threshold && !already_blocked {
            let ip = abuser["ip"].as_str().unwrap_or("").to_string();
            let reasons = abuser["reasons"].as_array()
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str())
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default();
            let servers: Vec<String> = abuser["servers"].as_array()
                .map(|arr| arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect())
                .unwrap_or_default();

            if !ip.is_empty() {
                let reason = format!("[서버자동차단] {}점 - {}", score, reasons);
                to_block.push((ip, reason, servers, idx));
            }
        }
    }

    // 실제 차단 실행
    for (ip, reason, servers, idx) in to_block {
        let should_block = {
            let blocked = BLOCKED_SERVERS.read();
            !blocked.contains_key(&ip)
        };

        if should_block {
            {
                let mut blocked = BLOCKED_SERVERS.write();
                blocked.insert(ip.clone(), BlockCommand {
                    ip: ip.clone(),
                    reason: reason.clone(),
                    created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    cf_blocked: false,
                    servers_blocked: servers,
                });
            }
            abusers[idx]["alreadyBlocked"] = serde_json::json!(true);
            println!("[AutoBlock] {} - {}", ip, reason);

            // Cloudflare 차단 (비동기)
            let ip_clone = ip.clone();
            let reason_clone = reason.clone();
            tokio::spawn(async move {
                block_ip_cloudflare(&ip_clone, &reason_clone).await;
            });
        }
    }

    // 변경사항 저장 (차단된 것이 있으면)
    if BLOCKED_SERVERS.read().len() > 0 {
        save_blocked_list();
    }

    // ========== 결과 캐시 (30초 TTL) ==========
    let result = serde_json::json!({"abusers": abusers});
    {
        let mut cache = ABUSER_CACHE.write();
        cache.insert(cache_key, CacheEntry {
            data: result.clone(),
            expires_at: Instant::now() + Duration::from_secs(30),
        });
    }

    Json(result)
}

// ============ 로그 리스트 API ============

// IP별 로그 조회
async fn api_logs_by_ip(
    axum::extract::Path(ip): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(500i32);

    let time_filter = match period {
        "1h" => "dateadd('h', -1, now())",
        "3h" => "dateadd('h', -3, now())",
        "6h" => "dateadd('h', -6, now())",
        "12h" => "dateadd('h', -12, now())",
        "24h" => "dateadd('d', -1, now())",
        _ => "dateadd('h', -6, now())",
    };

    let escaped_ip = ip.replace("'", "''");
    let query = format!(
        "SELECT timestamp, server_id, method, path, status, bytes_sent, response_time, user_agent \
         FROM nginx_logs \
         WHERE timestamp > {} AND client_ip = '{}' \
         ORDER BY timestamp DESC \
         LIMIT {}",
        time_filter, escaped_ip, limit
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let logs: Vec<serde_json::Value> = data["dataset"].as_array()
                    .map(|arr| arr.iter().map(|row| {
                        serde_json::json!({
                            "timestamp": row[0],
                            "server_id": row[1],
                            "method": row[2],
                            "path": row[3],
                            "status": row[4],
                            "bytes_sent": row[5],
                            "response_time": row[6],
                            "user_agent": row[7]
                        })
                    }).collect())
                    .unwrap_or_default();
                Json(serde_json::json!({"logs": logs, "count": logs.len()}))
            } else {
                Json(serde_json::json!({"error": "Failed to parse response", "logs": []}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string(), "logs": []}))
    }
}

async fn api_logs_list(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(500i32);
    let server_id = params.get("server_id").map(|s| s.as_str()).unwrap_or("");
    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");

    let time_filter = match period {
        "5m" => "dateadd('m', -5, now())",
        "15m" => "dateadd('m', -15, now())",
        "1h" => "dateadd('h', -1, now())",
        "6h" => "dateadd('h', -6, now())",
        "24h" => "dateadd('d', -1, now())",
        _ => "dateadd('h', -1, now())",
    };

    let mut conditions = vec![format!("timestamp > {}", time_filter)];

    if !server_id.is_empty() {
        conditions.push(format!("server_id = '{}'", server_id.replace("'", "''")));
    }
    if !search.is_empty() {
        let escaped = search.replace("'", "''");
        conditions.push(format!("(client_ip LIKE '%{}%' OR path LIKE '%{}%')", escaped, escaped));
    }

    let query = format!(
        "SELECT timestamp, client_ip, status, bytes_sent, path, user_agent, server_id \
         FROM nginx_logs WHERE {} \
         ORDER BY timestamp DESC LIMIT {}",
        conditions.join(" AND "),
        limit
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 에이전트로부터 로그 수신 (압축 형식)
#[derive(Deserialize)]
struct CompressedLogsRequest {
    server_id: String,
    data: String, // base64 encoded gzipped JSON array
}

#[derive(Deserialize)]
struct LogEntry {
    timestamp: Option<String>,
    client_ip: String,
    method: Option<String>,
    status: i32,
    bytes_sent: i64,
    response_time: Option<f64>,
    path: String,
    referer: Option<String>,
    user_agent: Option<String>,
}

async fn api_logs_receive(
    headers: HeaderMap,
    Json(req): Json<CompressedLogsRequest>,
) -> impl IntoResponse {
    use base64::Engine;
    use flate2::read::GzDecoder;
    use std::io::Read;

    // 시크릿 검증
    let secret = headers.get("X-Agent-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_agent_secret(secret) {
        return Json(serde_json::json!({"error": "Unauthorized"}));
    }

    // base64 디코딩
    let compressed = match base64::engine::general_purpose::STANDARD.decode(&req.data) {
        Ok(data) => data,
        Err(e) => return Json(serde_json::json!({"error": format!("base64 decode error: {}", e)})),
    };

    // gzip 압축 해제
    let mut decoder = GzDecoder::new(&compressed[..]);
    let mut json_str = String::new();
    if let Err(e) = decoder.read_to_string(&mut json_str) {
        return Json(serde_json::json!({"error": format!("gzip decode error: {}", e)}));
    }

    // JSON 파싱
    let logs: Vec<LogEntry> = match serde_json::from_str(&json_str) {
        Ok(logs) => logs,
        Err(e) => return Json(serde_json::json!({"error": format!("JSON parse error: {}", e)})),
    };

    if logs.is_empty() {
        return Json(serde_json::json!({"status": "ok", "inserted": 0}));
    }

    let client = reqwest::Client::new();
    let server_id = req.server_id.replace("'", "''");

    // 배치 INSERT를 위해 모든 VALUES를 모음
    let mut values_list: Vec<String> = Vec::with_capacity(logs.len());

    for log in &logs {
        // timestamp가 숫자(나노초)인 경우 ISO8601로 변환
        let timestamp = match &log.timestamp {
            Some(ts) => {
                if let Ok(nanos) = ts.parse::<i64>() {
                    let secs = nanos / 1_000_000_000;
                    let nsecs = (nanos % 1_000_000_000) as u32;
                    chrono::DateTime::from_timestamp(secs, nsecs)
                        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
                        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string())
                } else {
                    ts.clone()
                }
            }
            None => chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
        };

        let method = log.method.clone().unwrap_or_default();
        let user_agent = log.user_agent.clone().unwrap_or_default();
        let referer = log.referer.clone().unwrap_or_default();
        let response_time = log.response_time.unwrap_or(0.0);

        // SQL escape
        let client_ip = log.client_ip.replace("'", "''");
        let path = log.path.replace("'", "''");
        let method = method.replace("'", "''");
        let user_agent = user_agent.replace("'", "''");
        let referer = referer.replace("'", "''");

        values_list.push(format!(
            "('{}', '{}', '{}', '{}', '{}', {}, {}, {}, '{}', '{}')",
            timestamp, server_id, client_ip, method, path, log.status, log.bytes_sent, response_time, referer, user_agent
        ));
    }

    // 한 번에 최대 100개씩 배치 INSERT (쿼리가 너무 길어지지 않게)
    let mut inserted = 0;
    for chunk in values_list.chunks(100) {
        let query = format!(
            "INSERT INTO nginx_logs (timestamp, server_id, client_ip, method, path, status, bytes_sent, response_time, referer, user_agent) VALUES {}",
            chunk.join(",")
        );

        let res = client.get("http://localhost:9002/exec")
            .query(&[("query", &query)])
            .send()
            .await;

        if res.is_ok() {
            inserted += chunk.len();
        }
    }

    Json(serde_json::json!({"status": "ok", "inserted": inserted}))
}

// ============ 로그 통계 API ============

// 요약 통계
async fn api_logs_stats_summary(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let server_id = params.get("server_id").map(|s| s.as_str()).unwrap_or("");

    let time_filter = match period {
        "5m" => "dateadd('m', -5, now())",
        "15m" => "dateadd('m', -15, now())",
        "1h" => "dateadd('h', -1, now())",
        "6h" => "dateadd('h', -6, now())",
        "24h" => "dateadd('d', -1, now())",
        _ => "dateadd('h', -1, now())",
    };

    let server_filter = if server_id.is_empty() {
        String::new()
    } else {
        format!(" AND server_id = '{}'", server_id.replace("'", "''"))
    };

    let query = format!(
        "SELECT count() as total, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) as s3xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as total_bytes \
         FROM nginx_logs WHERE timestamp > {}{}",
        time_filter, server_filter
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(row) = data["dataset"].as_array().and_then(|a| a.first()) {
                    return Json(serde_json::json!({
                        "total": row[0].as_i64().unwrap_or(0),
                        "s2xx": row[1].as_i64().unwrap_or(0),
                        "s3xx": row[2].as_i64().unwrap_or(0),
                        "s4xx": row[3].as_i64().unwrap_or(0),
                        "s5xx": row[4].as_i64().unwrap_or(0),
                        "total_bytes": row[5].as_i64().unwrap_or(0)
                    }));
                }
            }
            Json(serde_json::json!({"status": "error", "message": "No data"}))
        }
        Err(e) => Json(serde_json::json!({"status": "error", "message": e.to_string()}))
    }
}

// IP별 통계
async fn api_logs_stats_ips(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20);

    let time_filter = match period {
        "1h" => "dateadd('h', -1, now())",
        "6h" => "dateadd('h', -6, now())",
        "24h" => "dateadd('d', -1, now())",
        "7d" => "dateadd('d', -7, now())",
        _ => "dateadd('h', -6, now())",
    };

    let query = format!(
        "SELECT client_ip, count() as requests, sum(bytes_sent) as total_bytes \
         FROM nginx_logs WHERE timestamp > {} GROUP BY client_ip \
         ORDER BY total_bytes DESC LIMIT {}",
        time_filter, limit
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 타임라인 통계
async fn api_logs_stats_timeline(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");

    let (time_filter, sample_by) = match period {
        "1h" => ("dateadd('h', -1, now())", "1m"),
        "6h" => ("dateadd('h', -6, now())", "5m"),
        "24h" => ("dateadd('d', -1, now())", "30m"),
        "7d" => ("dateadd('d', -7, now())", "1h"),
        _ => ("dateadd('h', -6, now())", "5m"),
    };

    let query = format!(
        "SELECT timestamp, count() as requests, sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         SAMPLE BY {} ALIGN TO CALENDAR",
        time_filter, sample_by
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 일별 통계
async fn api_logs_stats_daily(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(7);

    let query = format!(
        "SELECT timestamp, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs \
         WHERE timestamp > dateadd('d', -{}, now()) \
         SAMPLE BY 1d ALIGN TO CALENDAR",
        limit
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 서버별 일별 통계
async fn api_logs_stats_daily_servers(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let days = params.get("days").and_then(|s| s.parse().ok()).unwrap_or(7);

    let query = format!(
        "SELECT timestamp, server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs \
         WHERE timestamp > dateadd('d', -{}, now()) \
         SAMPLE BY 1d ALIGN TO CALENDAR",
        days
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 시간별 통계
async fn api_logs_stats_hourly(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let date = params.get("date").map(|s| s.as_str()).unwrap_or("");

    let query = if date.is_empty() {
        "SELECT timestamp, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs \
         WHERE timestamp > dateadd('d', -1, now()) \
         SAMPLE BY 1h ALIGN TO CALENDAR".to_string()
    } else {
        format!(
            "SELECT timestamp, count() as requests, \
             sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
             sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
             sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
             sum(bytes_sent) as bytes \
             FROM nginx_logs \
             WHERE timestamp >= '{}T00:00:00Z' AND timestamp < '{}T00:00:00Z' + 86400000000L \
             SAMPLE BY 1h ALIGN TO CALENDAR",
            date, date
        )
    };

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 서버별 통계
async fn api_logs_stats_servers(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = reqwest::Client::new();
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");

    let time_filter = match period {
        "1h" => "dateadd('h', -1, now())",
        "6h" => "dateadd('h', -6, now())",
        "24h" => "dateadd('d', -1, now())",
        "7d" => "dateadd('d', -7, now())",
        _ => "dateadd('h', -6, now())",
    };

    let query = format!(
        "SELECT server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         GROUP BY server_id ORDER BY bytes DESC",
        time_filter
    );

    let res = client.get("http://localhost:9002/exec")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                Json(data)
            } else {
                Json(serde_json::json!({"error": "Failed to parse response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// ============ 이벤트 API ============

async fn api_servers_events() -> impl IntoResponse {
    let events = SERVER_EVENTS.read();
    let recent: Vec<&ServerEvent> = events.iter().rev().take(100).collect();
    Json(serde_json::json!({"events": recent}))
}

// 서버 이름 업데이트
#[derive(Deserialize)]
struct UpdateServerNameRequest {
    name: String,
}

async fn api_server_update_name(
    axum::extract::Path(server_id): axum::extract::Path<String>,
    Json(req): Json<UpdateServerNameRequest>,
) -> impl IntoResponse {
    let mut servers = EXTERNAL_SERVERS.write();
    if let Some(server) = servers.get_mut(&server_id) {
        let old_name = server.name.clone();
        server.name = req.name.clone();
        let server_clone = server.clone();
        drop(servers);
        save_server_to_db(&server_clone);
        add_server_event(&server_id, &format!("이름 변경: {} -> {}", old_name, req.name));
        Json(serde_json::json!({"success": true, "name": req.name}))
    } else {
        drop(servers);
        Json(serde_json::json!({"error": "Server not found"}))
    }
}

// ============ 서버 상태 API ============

async fn api_servers_list() -> impl IntoResponse {
    let servers = EXTERNAL_SERVERS.read();
    let cf_settings = CF_SETTINGS.read();
    let blocked_count = BLOCKED_SERVERS.read().len();
    let events = SERVER_EVENTS.read();
    let latest_version = AGENT_LATEST_VERSION.read().clone();

    let now = chrono::Utc::now();
    let server_list: Vec<serde_json::Value> = servers.values()
        .map(|s| {
            let online = s.last_seen.map(|t| t > now - chrono::Duration::minutes(2)).unwrap_or(false);
            let last_seen_ts = s.last_seen.map(|t| t.timestamp_millis()).unwrap_or(0);
            serde_json::json!({
                "id": s.id,
                "name": if s.name.is_empty() { &s.id } else { &s.name },
                "ip": s.ip,
                "url": s.url,
                "version": s.version,
                "last_seen": last_seen_ts,
                "blocked_ips": s.blocked_ips.len(),
                "online": online,
                "cpu": s.cpu,
                "memory_used": s.memory_used,
                "memory_total": s.memory_total,
                "disk_used": s.disk_used,
                "disk_total": s.disk_total,
                "rx_bytes": s.rx_bytes,
                "tx_bytes": s.tx_bytes,
                "connections": s.connections,
                "uptime": s.uptime
            })
        })
        .collect();

    let event_list: Vec<serde_json::Value> = events.iter().rev().take(50)
        .map(|e| serde_json::json!({
            "server": e.server,
            "message": e.message,
            "timestamp": e.timestamp
        }))
        .collect();

    Json(serde_json::json!({
        "servers": server_list,
        "events": event_list,
        "latest_version": latest_version,
        "totalBlocked": blocked_count,
        "cfEnabled": cf_settings.enabled
    }))
}

// 에이전트가 상태 보고 (POST)
#[derive(Deserialize)]
struct ServerStatusReport {
    #[serde(default)]
    id: String,
    #[serde(default, alias = "server_name")]
    name: String,
    #[serde(default)]
    ip: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    blocked_ips: Vec<String>,
    #[serde(default)]
    cpu: f64,
    #[serde(default)]
    memory_used: u64,
    #[serde(default)]
    memory_total: u64,
    #[serde(default)]
    disk_used: u64,
    #[serde(default)]
    disk_total: u64,
    #[serde(default)]
    rx_bytes: u64,
    #[serde(default)]
    tx_bytes: u64,
    #[serde(default)]
    connections: u64,
    #[serde(default)]
    uptime: u64,
}

async fn api_servers_status(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ServerStatusReport>,
) -> impl IntoResponse {
    // 시크릿 검증
    let secret = headers.get("X-Agent-Secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if !verify_agent_secret(secret) {
        return Json(serde_json::json!({"error": "Invalid secret"}));
    }

    // 클라이언트 IP 추출: 에이전트 데이터 > x-forwarded-for > x-real-ip > 소켓 IP
    let client_ip = if !req.ip.is_empty() {
        req.ip.clone()
    } else {
        headers.get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .or_else(|| {
                headers.get("x-real-ip")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| addr.ip().to_string())
    };

    let server_id = if !req.id.is_empty() { req.id.clone() } else { req.name.clone() };

    // 서버 상태 업데이트 또는 신규 등록
    let mut servers = EXTERNAL_SERVERS.write();

    // 기존 서버의 커스텀 이름 유지
    let existing_name = servers.get(&server_id).map(|s| s.name.clone());

    let server = servers.entry(server_id.clone()).or_insert_with(|| ExternalServer {
        id: server_id.clone(),
        name: req.name.clone(),
        ..Default::default()
    });

    server.last_seen = Some(chrono::Utc::now());
    server.online = true;
    server.ip = client_ip;
    server.version = req.version;
    server.blocked_ips = req.blocked_ips;
    server.cpu = req.cpu;
    server.memory_used = req.memory_used;
    server.memory_total = req.memory_total;
    server.disk_used = req.disk_used;
    server.disk_total = req.disk_total;
    server.rx_bytes = req.rx_bytes;
    server.tx_bytes = req.tx_bytes;
    server.connections = req.connections;
    server.uptime = req.uptime;

    // 기존 커스텀 이름이 있으면 유지, 없으면 에이전트가 보낸 이름 사용
    if let Some(existing) = existing_name {
        if !existing.is_empty() && existing != server_id {
            // 커스텀 이름이 있으면 유지
            server.name = existing;
        } else if !req.name.is_empty() {
            server.name = req.name;
        }
    } else if !req.name.is_empty() {
        server.name = req.name;
    }

    let server_clone = server.clone();
    drop(servers);

    // 서버 정보 DB에 저장
    save_server_to_db(&server_clone);

    // 대기 중인 차단 명령 반환
    let pending: Vec<serde_json::Value> = PENDING_BLOCKS.read()
        .iter()
        .map(|(ip, cmd)| serde_json::json!({"ip": ip, "reason": &cmd.reason}))
        .collect();

    Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "pending_blocks": pending
    }))
}

// ============ 블랙리스트 대기/확인 API ============

async fn api_blacklist_pending(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let pending = PENDING_BLOCKS.read();
    let blocked = BLOCKED_SERVERS.read();

    // 차단 대기 명령
    let mut commands: Vec<serde_json::Value> = pending.iter()
        .map(|(ip, cmd)| serde_json::json!({
            "ip": ip,
            "action": "block",
            "reason": cmd.reason,
            "timestamp": chrono::DateTime::parse_from_rfc3339(&cmd.created_at)
                .map(|d| d.timestamp_millis()).unwrap_or(0)
        }))
        .collect();

    // 이미 차단된 것도 포함 (에이전트가 아직 처리 안 했을 수 있음)
    for (ip, cmd) in blocked.iter() {
        // 해당 서버가 아직 처리 안 했으면 포함
        commands.push(serde_json::json!({
            "ip": ip,
            "action": "block",
            "reason": cmd.reason,
            "timestamp": chrono::DateTime::parse_from_rfc3339(&cmd.created_at)
                .map(|d| d.timestamp_millis()).unwrap_or(0)
        }));
    }

    Json(serde_json::json!({"commands": commands}))
}

#[derive(Deserialize)]
struct ConfirmBlockRequest {
    ip: String,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    server_id: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    success: Option<bool>,
}

async fn api_blacklist_confirm(Json(req): Json<ConfirmBlockRequest>) -> impl IntoResponse {
    // 서버가 차단 확인했음을 기록
    // server_id 또는 server_name 사용
    let server_name = req.server_id.or(req.server_name).unwrap_or_default();

    if server_name.is_empty() {
        return Json(serde_json::json!({"success": false, "error": "server_id or server_name required"}));
    }

    // 락을 짧게 유지하고 저장 여부 결정
    let should_save = {
        let mut pending = PENDING_BLOCKS.write();
        let mut blocked = BLOCKED_SERVERS.write();

        if let Some(mut cmd) = pending.remove(&req.ip) {
            cmd.servers_blocked.push(server_name.clone());
            blocked.insert(req.ip.clone(), cmd);
            true
        } else if let Some(cmd) = blocked.get_mut(&req.ip) {
            if !cmd.servers_blocked.contains(&server_name) {
                cmd.servers_blocked.push(server_name.clone());
                true
            } else {
                false
            }
        } else {
            return Json(serde_json::json!({"success": false, "error": "IP not found"}));
        }
    }; // 락 해제됨

    if should_save {
        save_blocked_list();
    }
    Json(serde_json::json!({"success": true}))
}

// ============ 에이전트 버전/스크립트 API ============

async fn api_agent_version() -> impl IntoResponse {
    let version = AGENT_LATEST_VERSION.read().clone();
    Json(serde_json::json!({"version": version}))
}

async fn serve_agent_script() -> impl IntoResponse {
    match std::fs::read_to_string("static/agent/server_agent.sh") {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(content))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Agent script not found"))
            .unwrap(),
    }
}

async fn serve_agent_checksum() -> impl IntoResponse {
    match std::fs::read_to_string("static/agent/server_agent.sh.sha256") {
        Ok(content) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain")
            .body(Body::from(content.trim().to_string()))
            .unwrap(),
        Err(_) => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Checksum not found"))
            .unwrap(),
    }
}
