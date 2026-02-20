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
use maxminddb::Reader as MaxmindReader;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, Semaphore};
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::{cors::CorsLayer, services::ServeDir, set_header::SetResponseHeaderLayer, compression::CompressionLayer};

const SIMPLE_WS_URL: &str = "http://127.0.0.1:8444";
const CLICKHOUSE_URL: &str = "http://127.0.0.1:8123";
const DRAGONFLY_URL: &str = "redis://127.0.0.1:6379";
const KST_OFFSET_HOURS: i64 = 9;

/// Validate and sanitize IP address patterns for SQL queries.
/// Only allows characters valid in IPv4/IPv6 addresses plus '%' for LIKE wildcards.
fn sanitize_ip_pattern(input: &str) -> String {
    input.chars().filter(|c| c.is_ascii_hexdigit() || matches!(c, '.' | ':' | '%' | '/')).collect()
}

/// Escape a string for safe use in ClickHouse SQL string literals.
/// Escapes single quotes and backslashes.
fn escape_clickhouse_sql(input: &str) -> String {
    input.replace('\\', "\\\\").replace('\'', "\\'")
}

/// Safely rename the "data" key to "dataset" in a ClickHouse JSONCompact response.
/// Uses proper JSON parsing instead of string replacement to avoid data corruption.
fn rename_data_to_dataset(body: &str) -> String {
    if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(body) {
        if let Some(obj) = val.as_object_mut() {
            if let Some(data) = obj.remove("data") {
                obj.insert("dataset".to_string(), data);
            }
        }
        serde_json::to_string(&val).unwrap_or_else(|_| body.to_string())
    } else {
        body.to_string()
    }
}

/// Generate a ClickHouse subquery that computes accurate traffic totals using
/// segmented cumulative diffs. This handles counter resets (process restarts)
/// by detecting points where http_bytes drops and computing max-min per segment.
///
/// `where_clause` - SQL WHERE condition (e.g. "ts >= toStartOfDay(now(), 'Asia/Seoul')")
/// Returns a subquery string that produces columns: http_bytes, p2p_bytes, p2p_up_bytes
fn cumulative_diff_traffic_subquery(where_clause: &str) -> String {
    format!(
        "(\
            WITH \
              numbered AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  lagInFrame(http_bytes) OVER (ORDER BY ts) as prev_http, \
                  row_number() OVER (ORDER BY ts) as rn \
                FROM p2p_stats WHERE {wc}\
              ), \
              reset_marks AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  CASE WHEN rn = 1 OR http_bytes < prev_http THEN 1 ELSE 0 END as is_reset \
                FROM numbered\
              ), \
              segments AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  sum(is_reset) OVER (ORDER BY ts) as segment_id \
                FROM reset_marks\
              ) \
            SELECT \
              sum(seg_max_http - seg_min_http) as http_bytes, \
              sum(seg_max_p2p - seg_min_p2p) as p2p_bytes, \
              sum(seg_max_p2p_up - seg_min_p2p_up) as p2p_up_bytes \
            FROM (\
              SELECT segment_id, \
                max(http_bytes) as seg_max_http, min(http_bytes) as seg_min_http, \
                max(p2p_bytes) as seg_max_p2p, min(p2p_bytes) as seg_min_p2p, \
                max(p2p_up_bytes) as seg_max_p2p_up, min(p2p_up_bytes) as seg_min_p2p_up \
              FROM segments GROUP BY segment_id\
            )\
        )",
        wc = where_clause
    )
}

/// Generate a cumulative diff query grouped by a time bucket expression.
/// Returns columns: `bucket`, http_bytes, p2p_bytes, p2p_up_bytes
///
/// `where_clause` - SQL WHERE condition
/// `bucket_expr` - ClickHouse expression for time bucketing (e.g. "toStartOfDay(ts, 'Asia/Seoul')")
/// `bucket_alias` - alias for the bucket column (e.g. "day" or "month")
fn cumulative_diff_traffic_grouped(where_clause: &str, bucket_expr: &str, bucket_alias: &str) -> String {
    format!(
        "(\
            WITH \
              numbered AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  lagInFrame(http_bytes) OVER (ORDER BY ts) as prev_http, \
                  row_number() OVER (ORDER BY ts) as rn \
                FROM p2p_stats WHERE {wc}\
              ), \
              reset_marks AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  CASE WHEN rn = 1 OR http_bytes < prev_http THEN 1 ELSE 0 END as is_reset \
                FROM numbered\
              ), \
              segments AS (\
                SELECT ts, http_bytes, p2p_bytes, p2p_up_bytes, \
                  sum(is_reset) OVER (ORDER BY ts) as segment_id \
                FROM reset_marks\
              ) \
            SELECT \
              {alias}, \
              sum(seg_max_http - seg_min_http) as http_bytes, \
              sum(seg_max_p2p - seg_min_p2p) as p2p_bytes, \
              sum(seg_max_p2p_up - seg_min_p2p_up) as p2p_up_bytes \
            FROM (\
              SELECT segment_id, {bucket} as {alias}, \
                max(http_bytes) as seg_max_http, min(http_bytes) as seg_min_http, \
                max(p2p_bytes) as seg_max_p2p, min(p2p_bytes) as seg_min_p2p, \
                max(p2p_up_bytes) as seg_max_p2p_up, min(p2p_up_bytes) as seg_min_p2p_up \
              FROM segments GROUP BY segment_id, {alias}\
            ) \
            GROUP BY {alias} ORDER BY {alias}\
        )",
        wc = where_clause,
        bucket = bucket_expr,
        alias = bucket_alias
    )
}

// 캐시 엔트리
struct CacheEntry<T> {
    data: T,
    expires_at: Instant,
}

// 봇 탐지 리포트 구조체
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct BotReportEntry {
    ip: String,
    reason: String,
    server: String,
    gif_count: i64,
    html_count: i64,
    report_count: i64,
    first_seen: String,
    last_seen: String,
    #[serde(default)]
    user_agent: String,
}

fn load_bot_reports() -> HashMap<String, BotReportEntry> {
    if let Ok(content) = std::fs::read_to_string("data/bot_reports.json") {
        if let Ok(data) = serde_json::from_str(&content) {
            return data;
        }
    }
    HashMap::new()
}

// 자동 차단 설정
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct AutoBlockSettings {
    enabled: bool,
    score: i64,
    interval_secs: u64,  // 체크 주기 (초)
}

impl Default for AutoBlockSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            score: 85,
            interval_secs: 60,  // 1분마다 체크
        }
    }
}

fn load_auto_block_settings() -> AutoBlockSettings {
    if let Ok(content) = std::fs::read_to_string("data/auto_block_settings.json") {
        if let Ok(data) = serde_json::from_str(&content) {
            return data;
        }
    }
    AutoBlockSettings::default()
}

fn save_auto_block_settings(settings: &AutoBlockSettings) {
    let _ = std::fs::create_dir_all("data");
    if let Ok(json) = serde_json::to_string_pretty(settings) {
        let _ = std::fs::write("data/auto_block_settings.json", json);
    }
}

// 전역 상태
lazy_static::lazy_static! {
    static ref ASN_READER: Option<MaxmindReader<Vec<u8>>> = {
        match MaxmindReader::open_readfile("data/GeoLite2-ASN.mmdb") {
            Ok(reader) => {
                eprintln!("[GeoIP] ASN database loaded");
                Some(reader)
            }
            Err(e) => {
                eprintln!("[GeoIP] Failed to load ASN database: {} - ISP info disabled", e);
                None
            }
        }
    };

    // 외부 서버 관리
    static ref EXTERNAL_SERVERS: Arc<RwLock<HashMap<String, ExternalServer>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref ABUSER_BG_CACHE: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
    // Summary API 캐시 (10초 TTL)
    static ref SUMMARY_CACHE: Arc<RwLock<Option<CacheEntry<serde_json::Value>>>> = Arc::new(RwLock::new(None));
    // Blacklist API 캐시 (30초 TTL)
    static ref BLACKLIST_CACHE: Arc<RwLock<Option<CacheEntry<serde_json::Value>>>> = Arc::new(RwLock::new(None));
    // 무거운 쿼리 동시 실행 제한 (최대 2개)
    static ref HEAVY_QUERY_SEMAPHORE: Arc<Semaphore> = Arc::new(Semaphore::new(2));
    // 에이전트 최신 버전
    static ref AGENT_LATEST_VERSION: Arc<RwLock<String>> = Arc::new(RwLock::new("41".to_string()));
    // 서버 이벤트 (메모리)
    static ref SERVER_EVENTS: Arc<RwLock<VecDeque<ServerEvent>>> = Arc::new(RwLock::new(VecDeque::new()));
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
    // 봇 탐지 리포트
    static ref BOT_REPORTS: Arc<RwLock<HashMap<String, BotReportEntry>>> = Arc::new(RwLock::new(load_bot_reports()));
    // 자동 차단 설정
    static ref AUTO_BLOCK_SETTINGS: Arc<RwLock<AutoBlockSettings>> = Arc::new(RwLock::new(load_auto_block_settings()));
    // 공유 HTTP 클라이언트
    static ref HTTP_CLIENT: reqwest::Client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .pool_max_idle_per_host(20)
        .build()
        .unwrap();
    // 백그라운드 프리컴퓨트 캐시 (3~10초 간격 갱신, API는 읽기만)
    static ref TRAFFIC_REALTIME_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    static ref INIT_DATA_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    static ref SUMMARY_BG_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    static ref SERVERS_REALTIME_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    static ref IP_ANALYSIS_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    static ref POPULAR_CACHE: Arc<RwLock<String>> = Arc::new(RwLock::new(String::from("{}")));
    // 로그 수신 중복 방지 캐시: SHA256(server_id + data) -> Instant
    static ref LOG_DEDUP_CACHE: Arc<RwLock<HashMap<String, Instant>>> = Arc::new(RwLock::new(HashMap::new()));
    static ref LOGS_STATS_BG_CACHE: Arc<RwLock<HashMap<String, String>>> = Arc::new(RwLock::new(HashMap::new()));
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
    let salt = std::env::var("PASSWORD_SALT")
        .unwrap_or_else(|_| "p2p-stats-default-salt".to_string());
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, password).as_bytes());
    hex::encode(hasher.finalize())
}

// DB에서 인증 확인
async fn verify_credentials(username: &str, password: &str) -> bool {
    let client = &*HTTP_CLIENT;
    let password_hash = hash_password(password);
    let query = format!(
        "SELECT password_hash FROM dashboard_users WHERE username = '{}' LIMIT 1 FORMAT JSONCompact",
        escape_clickhouse_sql(username)
    );
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(rows) = data.get("data").and_then(|d| d.as_array()) {
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
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(create_query));
    if let Err(e) = client.get(&url).send().await {
        eprintln!("[AUTH] Failed to create dashboard_users table: {}", e);
    }

    // admin 계정 확인
    let check_query = "SELECT count() FROM dashboard_users WHERE username = 'admin'";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(check_query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(count) = data.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_i64()) {
                if count == 0 {
                    let default_pw = std::env::var("ADMIN_DEFAULT_PASSWORD")
                        .unwrap_or_else(|_| "tlqkf123@".to_string());
                    let pw_hash = hash_password(&default_pw);
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
                    let insert = format!(
                        "INSERT INTO dashboard_users VALUES('admin', '{}', '{}')",
                        pw_hash, now
                    );
                    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&insert));
                    let _ = client.get(&url).send().await;
                }
                if count > 0 && std::env::var("FORCE_ADMIN_RESET").is_ok() {
                    eprintln!("[AUTH] FORCE_ADMIN_RESET set — re-creating admin with salted hash");
                    let delete_q = "ALTER TABLE dashboard_users DELETE WHERE username = 'admin'";
                    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(delete_q));
                    let _ = client.get(&url).send().await;
                    let default_pw = std::env::var("ADMIN_DEFAULT_PASSWORD")
                        .unwrap_or_else(|_| "tlqkf123@".to_string());
                    let pw_hash = hash_password(&default_pw);
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
                    let insert = format!(
                        "INSERT INTO dashboard_users VALUES('admin', '{}', '{}')",
                        pw_hash, now
                    );
                    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&insert));
                    let _ = client.get(&url).send().await;
                }
            }
        }
    }
}

// 서버 이벤트 테이블 초기화
async fn ensure_server_events_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS server_events (timestamp TIMESTAMP, server STRING, message STRING) timestamp(timestamp)";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;
}

// 에이전트 설정 테이블 초기화
async fn ensure_agent_settings_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS agent_settings (key STRING, value STRING, updated_at TIMESTAMP) timestamp(updated_at)";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(create_query));
    let _ = client.get(&url).send().await;

    // 기본 시크릿 생성
    let check_query = "SELECT count() FROM agent_settings WHERE key = 'secret'";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(check_query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(count) = data.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_i64()) {
                if count == 0 {
                    let secret = format!("{:x}", rand::random::<u128>());
                    let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ");
                    let insert = format!(
                        "INSERT INTO agent_settings VALUES('secret', '{}', '{}')",
                        secret, now
                    );
                    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&insert));
                    let _ = client.get(&url).send().await;
                }
            }
        }
    }
}

// 에이전트 시크릿 로드
async fn load_agent_secret(client: &Client) {
    let query = "SELECT value FROM agent_settings WHERE key = 'secret' LIMIT 1";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(query));

    if let Ok(res) = client.get(&url).send().await {
        if let Ok(data) = res.json::<serde_json::Value>().await {
            if let Some(secret) = data.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.get(0)).and_then(|v| v.as_str()) {
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
    let create_query = "CREATE TABLE IF NOT EXISTS dashboard_servers (\
        server_id String, name String, ip String, url String, version String, \
        updated_at DateTime64(6) DEFAULT now64()\
    ) ENGINE = ReplacingMergeTree(updated_at) ORDER BY server_id";
    let _ = client.post(CLICKHOUSE_URL).body(create_query.to_string()).send().await;
}

// 세션 테이블 초기화
async fn ensure_sessions_table(client: &Client) {
    let create_query = "CREATE TABLE IF NOT EXISTS dashboard_sessions (\
        session_id String, username String, created_at DateTime64(6) DEFAULT now64()\
    ) ENGINE = MergeTree() ORDER BY created_at";
    let _ = client.post(CLICKHOUSE_URL).body(create_query.to_string()).send().await;
}

// 세션 로드 (DB에서) - 최근 7일 세션만
async fn load_sessions_from_db(client: &Client) {
    let query = "SELECT session_id, username FROM dashboard_sessions \
        WHERE created_at > now() - INTERVAL 7 DAY FORMAT JSONCompact";

    match client.post(CLICKHOUSE_URL).body(query.to_string()).send().await {
        Ok(res) => {
            match res.json::<serde_json::Value>().await {
                Ok(data) => {
                    if let Some(rows) = data.get("data").and_then(|d| d.as_array()) {
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
                        eprintln!("No sessions in database");
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
        let client = &*HTTP_CLIENT;
        let query = format!(
            "INSERT INTO dashboard_sessions (session_id, username) VALUES ('{}', '{}')",
            session_id.replace("'", "''"),
            username.replace("'", "''")
        );
        let _ = client.post(CLICKHOUSE_URL).body(query).send().await;
    });
}

// 서버 목록 로드 (DB에서)
async fn load_servers_from_db(client: &Client) {
    let query = "SELECT server_id, name, ip, url, version FROM dashboard_servers FINAL FORMAT JSONCompact";

    match client.post(CLICKHOUSE_URL).body(query.to_string()).send().await {
        Ok(res) => {
            if let Ok(data) = res.json::<serde_json::Value>().await {
                if let Some(rows) = data.get("data").and_then(|d| d.as_array()) {
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
        Err(e) => eprintln!("Failed to load servers: {}", e),
    }
}

// 서버 정보 저장 (DB로) - 백그라운드 태스크로 실행
fn save_server_to_db(server: &ExternalServer) {
    let server_id = server.id.clone();
    let name = server.name.clone();
    let ip = server.ip.clone();
    let srv_url = server.url.clone();
    let version = server.version.clone();

    tokio::spawn(async move {
        let client = &*HTTP_CLIENT;
        let query = format!(
            "INSERT INTO dashboard_servers (server_id, name, ip, url, version) VALUES ('{}', '{}', '{}', '{}', '{}')",
            server_id.replace("'", "''"),
            name.replace("'", "''"),
            ip.replace("'", "''"),
            srv_url.replace("'", "''"),
            version.replace("'", "''")
        );
        let _ = client.post(CLICKHOUSE_URL).body(query).send().await;
    });
}

// 에이전트 시크릿 검증 (시크릿 미설정시 허용)
fn verify_agent_secret(provided: &str) -> bool {
    let secret = AGENT_SECRET.read();
    secret.is_empty() || secret.as_str() == provided
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
    events.push_back(event);
    if events.len() > 100 {
        events.pop_front();
    }

    // QuestDB에 영구 저장
    let srv = server.replace("'", "''");
    let msg = message.replace("'", "''");
    tokio::spawn(async move {
        let query = format!(
            "INSERT INTO server_events VALUES({}000, '{}', '{}')",
            timestamp, srv, msg
        );
        let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&query));
        let _ = HTTP_CLIENT.get(&url).send().await;
    });
}

// ============ 자동 차단 백그라운드 태스크 ============


fn lookup_isp(ip: &str) -> Option<String> {
    let reader = ASN_READER.as_ref()?;
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let asn: maxminddb::geoip2::Asn = reader.lookup(addr).ok()?;
    let org = asn.autonomous_system_organization?;
    // Shorten common Korean ISP names
    let short = if org.contains("SK Telecom") { "SKT" }
        else if org.contains("SK Broadband") { "SKB" }
        else if org.contains("Korea Telecom") { "KT" }
        else if org.contains("LGTELECOM") || org.contains("LG DACOM") { "LGU+" }
        else if org.contains("Samsung") { "Samsung" }
        else if org.contains("Naver") { "Naver" }
        else if org.contains("Amazon") { "AWS" }
        else if org.contains("Google") { "Google" }
        else if org.contains("Microsoft") || org.contains("Azure") { "Azure" }
        else if org.contains("Cloudflare") { "CF" }
        else {
            // Return first meaningful part (max 12 chars)
            return Some(org.split_whitespace().take(2).collect::<Vec<_>>().join(" "));
        };
    Some(short.to_string())
}

async fn run_auto_block_check(_client: &Client, threshold: i64) -> Result<(), String> {
    // ========== 프론트엔드 abuser API 점수를 그대로 사용 (단일 소스) ==========
    // 중복 스코어링 로직 제거 — API가 유일한 점수 계산 소스
    let http = &*HTTP_CLIENT;
    let resp = http.get("http://127.0.0.1:8080/api/servers/logs/abusers?period=6h&limit=500")
        .timeout(Duration::from_secs(30))
        .send().await.map_err(|e| format!("abuser API 호출 실패: {}", e))?;

    let data: serde_json::Value = resp.json().await.map_err(|e| format!("JSON 파싱 실패: {}", e))?;

    // API가 busy 상태면 다음 주기에 재시도
    if data["busy"].as_bool().unwrap_or(false) {
        eprintln!("[AutoBlock] abuser API busy, skip this cycle");
        return Ok(());
    }

    let abusers = data["abusers"].as_array().ok_or("abusers 배열 없음")?;

    let server_ids: Vec<String> = {
        let servers = EXTERNAL_SERVERS.read();
        servers.keys().cloned().collect()
    };

    let mut to_block: Vec<(String, String)> = Vec::new();

    for abuser in abusers {
        let ip = abuser["ip"].as_str().unwrap_or("");
        let score = abuser["risk_score"].as_i64()
            .or_else(|| abuser["score"].as_i64())
            .unwrap_or(0);
        let already_blocked = abuser["alreadyBlocked"].as_bool().unwrap_or(false);

        if ip.is_empty() || score < threshold || already_blocked { continue; }

        // 모바일 IP 제외 (CGNAT/공유IP — 차단 시 같은 기지국 수천 명 영향)
        let is_mobile_ip = ip.starts_with("2001:2d8:")
            || ip.starts_with("2001:4430:")
            || ip.starts_with("2001:e60:")
            || ip.starts_with("2001:0e60:")
            || ip.starts_with("2406:5900:");
        if is_mobile_ip { continue; }

        let reasons: Vec<String> = abuser["reasons"].as_array()
            .map(|arr| arr.iter().filter_map(|r| r.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let gb = abuser["gb"].as_str().unwrap_or("0");
        let gb_per_hour = abuser["gb_per_hour"].as_str().unwrap_or("0");
        let max_burst = abuser["max_req_100s"].as_i64().unwrap_or(0);
        let requests = abuser["requests"].as_i64().unwrap_or(0);

        let reason = format!("[자동차단] {}점 - {}GB, {}GB/h, {}req, burst:{}/100s | {}",
            score, gb, gb_per_hour, requests, max_burst, reasons.join(", "));
        to_block.push((ip.to_string(), reason));
    }

    eprintln!("[AutoBlock] Check complete: {} abusers from API, {} exceed threshold ({})",
             abusers.len(), to_block.len(), threshold);

    if !to_block.is_empty() {
        {
            let mut blocked = BLOCKED_SERVERS.write();
            for (ip, reason) in &to_block {
                blocked.insert(ip.clone(), BlockCommand {
                    ip: ip.clone(),
                    reason: reason.clone(),
                    created_at: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                    cf_blocked: false,
                    servers_blocked: Vec::new(),
                });
            }
        }
        save_blocked_list();

        for (ip_clone, reason_clone) in to_block.iter().cloned() {
            let server_ids_clone = server_ids.clone();
            tokio::spawn(async move {
                let cf_result = block_ip_cloudflare(&ip_clone, &reason_clone).await;
                if cf_result {
                    if let Some(mut blocked) = BLOCKED_SERVERS.try_write_for(Duration::from_secs(2)) {
                        if let Some(cmd) = blocked.get_mut(&ip_clone) {
                            cmd.cf_blocked = true;
                        }
                        drop(blocked);
                        save_blocked_list();
                    }
                }

                let servers: Vec<(String, String)> = {
                    let guard = EXTERNAL_SERVERS.read();
                    guard.iter().map(|(_, s)| (s.url.clone(), s.ip.clone())).collect()
                };
                let secret = AGENT_SECRET.read().clone();
                let http_client = &*HTTP_CLIENT;

                let mut server_blocked_count = 0;
                for (server_url, server_ip) in &servers {
                    let base_url = if !server_url.is_empty() {
                        server_url.clone()
                    } else if !server_ip.is_empty() {
                        format!("http://{}:8081", server_ip)
                    } else {
                        continue;
                    };
                    let url = format!("{}/block", base_url);
                    let res = http_client.post(&url)
                        .header("X-Agent-Secret", secret.clone())
                        .json(&serde_json::json!({"ip": ip_clone, "reason": reason_clone}))
                        .timeout(Duration::from_secs(5))
                        .send()
                        .await;
                    if res.is_ok() {
                        server_blocked_count += 1;
                    }
                }

                eprintln!("[AutoBlock] {} - CF:{} Servers:{}/{} - {}",
                         ip_clone, cf_result, server_blocked_count, server_ids_clone.len(), reason_clone);
            });
        }

        eprintln!("[AutoBlock] Blocked {} IPs (threshold: {})", to_block.len(), threshold);
    }

    Ok(())
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
        .timeout(Duration::from_secs(60))
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

    // Background task: hourly_stats 백필 (시작 시 한번, 빠진 날짜만 채움)
    let backfill_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        eprintln!("[HourlyStats] Starting backfill check...");
        let query = "SELECT toDate(date) as d FROM daily_summary FINAL ORDER BY d FORMAT JSONCompact";
        if let Ok(resp) = backfill_client.post(CLICKHOUSE_URL).body(query).send().await {
            if let Ok(text) = resp.text().await {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                    if let Some(dates) = json.get("data").and_then(|d| d.as_array()) {
                        let mut filled = 0;
                        for row in dates {
                            if let Some(date) = row.as_array().and_then(|a| a.first()).and_then(|v| v.as_str()) {
                                if !has_hourly_stats_for_date(&backfill_client, date).await {
                                    eprintln!("[HourlyStats] Backfilling {}", date);
                                    if store_hourly_stats(&backfill_client, date).await {
                                        filled += 1;
                                    }
                                    tokio::time::sleep(Duration::from_secs(2)).await;
                                }
                            }
                        }
                        eprintln!("[HourlyStats] Backfill complete: {} dates filled", filled);
                    }
                }
            }
        }
    });

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

    // Background task: /api/traffic?period=realtime 전용 pre-compute (1초마다)
    let traffic_rt_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        eprintln!("[TrafficRT] Background pre-compute started (1s interval)");
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let json = build_traffic_realtime(&traffic_rt_client).await;
            *TRAFFIC_REALTIME_CACHE.write() = json;
        }
    });

    // Background task: init-data pre-compute (1초마다 — 8개 CH 쿼리 대신 메모리)
    let init_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let json = build_init_data(&init_client).await;
            *INIT_DATA_CACHE.write() = json;
        }
    });

    // Background task: summary pre-compute (1초마다 — 4개 CH 쿼리)
    let summary_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(4)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let json = build_summary_bg(&summary_client).await;
            *SUMMARY_BG_CACHE.write() = json;
        }
    });

    // Background task: servers/realtime pre-compute (1초마다)
    let srv_rt_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let json = build_servers_realtime(&srv_rt_client).await;
            *SERVERS_REALTIME_CACHE.write() = json;
        }
    });

    // Background task: ip-analysis pre-compute (1초마다 — 50 HTTP 호출 대신 메모리)
    let ip_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            let json = build_ip_analysis(&ip_client).await;
            *IP_ANALYSIS_CACHE.write() = json;
        }
    });

    // Background task: popular pre-compute (5초마다 — uniqExact 풀스캔)
    let pop_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            let json = build_popular(&pop_client).await;
            *POPULAR_CACHE.write() = json;
        }
    });

    // Background task: abuser pre-compute (15초마다, 모든 period)
    let abuser_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(8)).await;
        eprintln!("[AbuserBG] Background pre-compute started (10s interval)");
        let periods = ["1h", "3h", "6h", "12h", "24h"];
        loop {
            let start = std::time::Instant::now();
            for period in &periods {
                let json = build_abuser_data(&abuser_client, period).await;
                let has_data = !json.contains("\"abusers\":[]");
                if has_data || !ABUSER_BG_CACHE.read().contains_key(*period) {
                    ABUSER_BG_CACHE.write().insert(period.to_string(), json);
                }
            }
            let elapsed = start.elapsed().as_secs();
            let sleep_secs = if elapsed < 10 { 10 - elapsed } else { 2 };
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }
    });

    let logs_stats_client = client.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(5)).await;
        eprintln!("[LogsStatsBG] Background pre-compute started (10s interval)");
        let periods = ["1h", "6h", "24h"];
        loop {
            let start = std::time::Instant::now();
            for period in &periods {
                build_logs_stats_data(&logs_stats_client, period).await;
            }
            let elapsed = start.elapsed().as_secs();
            let sleep_secs = if elapsed < 10 { 10 - elapsed } else { 2 };
            tokio::time::sleep(Duration::from_secs(sleep_secs)).await;
        }
    });

    // Background task: 자동 차단 스케줄러
    let autoblock_client = client.clone();
    tokio::spawn(async move {
        // 시작 시 30초 대기
        tokio::time::sleep(Duration::from_secs(30)).await;
        eprintln!("[AutoBlock] Background scheduler started");

        loop {
            let (enabled, score, interval) = {
                let settings = AUTO_BLOCK_SETTINGS.read();
                (settings.enabled, settings.score, settings.interval_secs)
            };

            if enabled {
                // 어뷰저 체크 및 자동 차단 실행
                if let Err(e) = run_auto_block_check(&autoblock_client, score).await {
                    eprintln!("[AutoBlock] Error: {}", e);
                }
            }

            tokio::time::sleep(Duration::from_secs(interval)).await;
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
                    toStartOfDay(timestamp, 'Asia/Seoul') as day,
                    client_ip,
                    count() as total_requests,
                    sum(bytes_sent) as total_bytes,
                    uniqExact(path) as unique_paths,
                    uniqExact(server_id) as server_count,
                    0 as max_burst,
                    min(timestamp) as first_seen,
                    max(timestamp) as last_seen
                FROM nginx_logs
                WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 2 DAY
                  AND timestamp < toStartOfDay(now(), 'Asia/Seoul')
                GROUP BY day, client_ip
            "#;

            if let Ok(resp) = agg_client.get("http://localhost:8123")
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
            if let Ok(resp) = agg_client.get("http://localhost:8123")
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
                                    if let Ok(_) = agg_client.get("http://localhost:8123")
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

    // Background task: daily_summary 집계 (매일 00:05 KST)
    let summary_client = client.clone();
    tokio::spawn(async move {
        loop {
            // 다음 00:05 KST까지 대기 시간 계산
            let now = chrono::Utc::now();
            let kst_now = now + chrono::Duration::hours(KST_OFFSET_HOURS);
            let tomorrow_0005 = (kst_now.date_naive() + chrono::Duration::days(1))
                .and_hms_opt(0, 5, 0).unwrap();
            let kst_tomorrow_0005 = tomorrow_0005 - chrono::Duration::hours(KST_OFFSET_HOURS);
            let wait_secs = (kst_tomorrow_0005 - now.naive_utc()).num_seconds().max(0) as u64;

            eprintln!("[DailySummary] Next aggregation in {} seconds (at 00:05 KST)", wait_secs);
            tokio::time::sleep(Duration::from_secs(wait_secs)).await;

            // 어제 날짜 계산 (KST 기준)
            let yesterday = (chrono::Utc::now() + chrono::Duration::hours(KST_OFFSET_HOURS) - chrono::Duration::days(1))
                .format("%Y-%m-%d").to_string();

            eprintln!("[DailySummary] Aggregating data for {}", yesterday);

            // daily_summary에 어제 데이터 INSERT (REPLACE 방식)
            let delete_query = format!(
                "ALTER TABLE daily_summary DELETE WHERE date = '{}'", yesterday
            );
            let _ = summary_client.get("http://localhost:8123")
                .query(&[("query", &delete_query)])
                .timeout(Duration::from_secs(30))
                .send().await;

            let traffic_sub = cumulative_diff_traffic_subquery(
                &format!("toDate(ts, 'Asia/Seoul') = '{}'", yesterday)
            );
            let insert_query = format!(r#"
                INSERT INTO daily_summary
                SELECT
                    toDate('{}') as date,
                    p.max_viewers, p.max_users,
                    traffic.http_bytes, traffic.p2p_bytes, traffic.p2p_up_bytes,
                    v.plays, v.unique_visitors,
                    v.tvmon_visitors, v.tvwiki_visitors, v.tvhot_visitors,
                    v.mobile_visitors, v.pc_visitors
                FROM (
                    SELECT
                        count() as plays,
                        uniq(ip) as unique_visitors,
                        uniqIf(ip, referrer LIKE '%tvmon%') as tvmon_visitors,
                        uniqIf(ip, referrer LIKE '%tvwiki%') as tvwiki_visitors,
                        uniqIf(ip, referrer LIKE '%tvhot%') as tvhot_visitors,
                        uniqIf(ip, device NOT LIKE '%PC%') as mobile_visitors,
                        uniqIf(ip, device LIKE '%PC%') as pc_visitors
                    FROM visitor_logs
                    WHERE toDate(timestamp, 'Asia/Seoul') = '{}'
                ) v
                CROSS JOIN (
                    SELECT http_bytes, p2p_bytes, p2p_up_bytes
                    FROM {}
                ) traffic
                CROSS JOIN (
                    SELECT max(viewers) as max_viewers, max(unique_users) as max_users
                    FROM p2p_stats
                    WHERE toDate(ts, 'Asia/Seoul') = '{}'
                ) p
            "#, yesterday, yesterday, traffic_sub, yesterday);

            if let Ok(resp) = summary_client.get("http://localhost:8123")
                .query(&[("query", &insert_query)])
                .timeout(Duration::from_secs(600))
                .send()
                .await
            {
                if resp.status().is_success() {
                    eprintln!("[DailySummary] Successfully aggregated {}", yesterday);
                    eprintln!("[HourlyStats] Aggregating hourly data for {}", yesterday);
                    if store_hourly_stats(&summary_client, &yesterday).await {
                        eprintln!("[HourlyStats] Successfully aggregated {}", yesterday);
                    } else {
                        eprintln!("[HourlyStats] Failed to aggregate {}", yesterday);
                    }
                } else {
                    eprintln!("[DailySummary] Failed to aggregate {}: {:?}", yesterday, resp.status());
                }
            }
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
        .route("/api/blacklist/bulk-unblock", post(api_blacklist_bulk_unblock))
        .route("/api/blacklist/pending", get(api_blacklist_pending))
        .route("/api/blacklist/confirm", post(api_blacklist_confirm))
        .route("/api/blacklist/times", post(api_blacklist_times))
        // 봇 탐지 리포트
        .route("/api/bot/report", post(api_bot_report))
        .route("/api/bot/reports", get(api_bot_reports_list))
        // Cloudflare 설정
        .route("/api/settings/cloudflare", get(api_cf_settings_get))
        .route("/api/settings/cloudflare", post(api_cf_settings_set))
        // 자동 차단 설정
        .route("/api/settings/autoblock", get(api_autoblock_settings_get))
        .route("/api/settings/autoblock", post(api_autoblock_settings_set))
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
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static("no-cache, no-store, must-revalidate"),
        ))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .layer(CookieManagerLayer::new())
        .layer(CorsLayer::permissive())
        .layer(CompressionLayer::new())
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

// hourly_stats 테이블 생성 (디비화) — 스키마가 맞지 않으면 재생성
async fn ensure_hourly_stats_table(client: &Client) {
    // 기존 테이블 스키마 확인 (컬럼 수)
    let check_query = "SELECT count() FROM system.columns WHERE table = 'hourly_stats' AND database = currentDatabase() FORMAT JSONCompact";
    let mut need_recreate = true;
    if let Ok(resp) = client.post(CLICKHOUSE_URL).body(check_query).send().await {
        if let Ok(text) = resp.text().await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(count) = json.get("data").and_then(|d| d.as_array())
                    .and_then(|a| a.first()).and_then(|r| r.as_array())
                    .and_then(|r| r.first()).and_then(|v| v.as_u64()) {
                    if count == 15 { need_recreate = false; }
                }
            }
        }
    }
    if need_recreate {
        eprintln!("[HourlyStats] Recreating hourly_stats table with correct schema (15 columns)");
        let _ = client.post(CLICKHOUSE_URL).body("DROP TABLE IF EXISTS hourly_stats").send().await;
        let create_query = "CREATE TABLE IF NOT EXISTS hourly_stats (\
            ts DateTime, viewers Int64, unique_users Int64, http_bytes Int64, \
            p2p_bytes Int64, p2p_up_bytes Int64, peers Int64, swarms Int64, \
            plays Int64, unique_visitors Int64, tvmon Int64, tvwiki Int64, \
            tvhot Int64, mobile Int64, pc Int64\
            ) ENGINE = ReplacingMergeTree() PARTITION BY toYYYYMM(ts) ORDER BY ts";
        let _ = client.post(CLICKHOUSE_URL).body(create_query).send().await;
    } else {
        eprintln!("[HourlyStats] hourly_stats table schema OK (15 columns)");
    }
}

async fn has_hourly_stats_for_date(client: &Client, date: &str) -> bool {
    let query = format!(
        "SELECT count() FROM hourly_stats WHERE toDate(ts) = '{}' FORMAT JSONCompact", date
    );
    if let Ok(resp) = client.post(CLICKHOUSE_URL).body(query).send().await {
        if let Ok(text) = resp.text().await {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(count) = json.get("data")
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.first())
                    .and_then(|r| r.as_array())
                    .and_then(|r| r.first())
                    .and_then(|v| v.as_u64())
                {
                    return count > 0;
                }
            }
        }
    }
    false
}

async fn store_hourly_stats(client: &Client, date: &str) -> bool {
    let delete_query = format!(
        "ALTER TABLE hourly_stats DELETE WHERE ts >= toDateTime('{} 00:00:00') AND ts <= toDateTime('{} 23:59:59')",
        date, date
    );
    let _ = client.post(CLICKHOUSE_URL).body(delete_query).send().await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    if let Some(day_data) = query_daily_stats(client, date).await {
        if let Some(dataset) = day_data.get("dataset").and_then(|d| d.as_array()) {
            let mut values: Vec<String> = Vec::new();
            for row in dataset {
                if let Some(arr) = row.as_array() {
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
                    values.push(format!(
                        "('{}',{},{},{},{},{},{},{},{},{},{},{},{},{},{})",
                        ts, viewers, unique_users, http_bytes, p2p_bytes, p2p_up_bytes,
                        peers, swarms, plays, unique_visitors, tvmon, tvwiki, tvhot, mobile, pc
                    ));
                }
            }
            if !values.is_empty() {
                let insert_query = format!("INSERT INTO hourly_stats VALUES {}", values.join(","));
                let _ = client.post(CLICKHOUSE_URL).body(insert_query).send().await;
            }
            return true;
        }
    }
    false
}

async fn query_hourly_stats_range(client: &Client, start_date: &str, end_date: &str) -> Option<serde_json::Value> {
    let query = format!(
        "SELECT ts, viewers, unique_users, http_bytes, p2p_bytes, p2p_up_bytes, \
         peers, swarms, plays, unique_visitors, tvmon, tvwiki, tvhot, mobile, pc \
         FROM hourly_stats WHERE toDate(ts) >= '{}' AND toDate(ts) <= '{}' \
         ORDER BY ts FORMAT JSONCompact",
        start_date, end_date
    );
    if let Ok(resp) = client.post(CLICKHOUSE_URL).body(query).send().await {
        if let Ok(text) = resp.text().await {
            let text = text.replace("\"data\":", "\"dataset\":");
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) {
                return Some(json);
            }
        }
    }
    None
}

// 일별 통계 조회 (하루치 데이터) - 시간별(1h) 샘플링
async fn query_daily_stats(
    client: &reqwest::Client,
    date: &str,  // "2026-01-18" 형식 (KST 기준 날짜)
) -> Option<serde_json::Value> {
    // KST 기준 날짜 필터 사용 (toDate(ts, 'Asia/Seoul'))
    let kst_date_filter = format!("toDate(ts, 'Asia/Seoul') = '{}'", date);
    let kst_visit_filter = format!("toDate(timestamp, 'Asia/Seoul') = '{}'", date);

    // r_* 필드로 델타 합산 (누적값 first/last 대신)
    let stats_query = format!(
        "SELECT toStartOfHour(ts, 'Asia/Seoul') as hour_ts, anyLast(viewers) as viewers, anyLast(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, anyLast(peers) as peers, anyLast(swarms) as swarms \
         FROM p2p_stats WHERE {} \
         GROUP BY hour_ts ORDER BY hour_ts",
        kst_date_filter
    );

    let visits_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, count() as plays, uniqExact(ip) as unique_visitors \
         FROM visitor_logs WHERE {} \
         GROUP BY ts ORDER BY ts",
        kst_visit_filter
    );

    // 고유 방문자(UV) 기준 - 5개 쿼리 병렬 실행
    let tvmon_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, uniqExact(ip) as cnt FROM visitor_logs \
         WHERE {} AND referrer LIKE '%tvmon%' GROUP BY ts ORDER BY ts", kst_visit_filter);
    let tvwiki_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, uniqExact(ip) as cnt FROM visitor_logs \
         WHERE {} AND referrer LIKE '%tvwiki%' GROUP BY ts ORDER BY ts", kst_visit_filter);
    let tvhot_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, uniqExact(ip) as cnt FROM visitor_logs \
         WHERE {} AND referrer LIKE '%tvhot%' GROUP BY ts ORDER BY ts", kst_visit_filter);
    let mobile_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, uniqExact(ip) as cnt FROM visitor_logs \
         WHERE {} AND device NOT LIKE '%PC%' GROUP BY ts ORDER BY ts", kst_visit_filter);
    let pc_query = format!(
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as ts, uniqExact(ip) as cnt FROM visitor_logs \
         WHERE {} AND device LIKE '%PC%' GROUP BY ts ORDER BY ts", kst_visit_filter);

    let (stats_result, visits_result, tvmon_result, tvwiki_result, tvhot_result, mobile_result, pc_result) = tokio::join!(
        clickhouse_query_json(client, &stats_query),
        clickhouse_query_json(client, &visits_query),
        clickhouse_query_json(client, &tvmon_query),
        clickhouse_query_json(client, &tvwiki_query),
        clickhouse_query_json(client, &tvhot_query),
        clickhouse_query_json(client, &mobile_query),
        clickhouse_query_json(client, &pc_query)
    );

    if let (Ok(mut stats_json), Ok(visits_json)) = (stats_result, visits_result) {
        let mut plays_map: HashMap<String, i64> = HashMap::new();
        let mut visitors_map: HashMap<String, i64> = HashMap::new();
        // clickhouse_query_json이 "data"를 "dataset"으로 변환함
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
                // clickhouse_query_json이 "data"를 "dataset"으로 변환함
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
    let micros = period_to_micros(period);
    let mut redis = state.redis.clone();

    let use_db_table = matches!(period, "7d" | "30d" | "365d");

    if use_db_table {
        let days: i64 = match period { "7d" => 7, "30d" => 30, "365d" => 365, _ => 7 };
        let kst_now = chrono::Utc::now() + chrono::Duration::hours(9);
        let today = kst_now.format("%Y-%m-%d").to_string();
        let start_date = (kst_now - chrono::Duration::days(days - 1)).format("%Y-%m-%d").to_string();
        let yesterday = (kst_now - chrono::Duration::days(1)).format("%Y-%m-%d").to_string();
        let mut all_data: Vec<serde_json::Value> = Vec::new();

        // 1. 과거 데이터 (어제까지): hourly_stats 테이블에서 조회
        if let Some(hist_data) = query_hourly_stats_range(&state.client, &start_date, &yesterday).await {
            if let Some(dataset) = hist_data.get("dataset").and_then(|d| d.as_array()) {
                all_data.extend(dataset.clone());
            }
        }

        if let Some(day_data) = query_daily_stats(&state.client, &today).await {
            if let Some(dataset) = day_data.get("dataset").and_then(|d| d.as_array()) {
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

    // ClickHouse: micros를 초로 변환, sample을 interval로 변환 (KST 타임존 적용)
    let secs = micros / 1_000_000;
    let interval_expr = match sample {
        "1m" => "toStartOfMinute(ts, 'Asia/Seoul')".to_string(),
        "5m" => "toStartOfFiveMinutes(ts, 'Asia/Seoul')".to_string(),
        "10m" => "toStartOfTenMinutes(ts, 'Asia/Seoul')".to_string(),
        "15m" => "toStartOfFifteenMinutes(ts, 'Asia/Seoul')".to_string(),
        "1h" => "toStartOfHour(ts, 'Asia/Seoul')".to_string(),
        "1d" => "toStartOfDay(ts, 'Asia/Seoul')".to_string(),
        _ => format!("toStartOfInterval(ts, INTERVAL 1 MINUTE, 'Asia/Seoul')")
    };

    // r_* 필드로 델타 합산
    let stats_query = format!(
        "SELECT {} as ts, anyLast(viewers) as viewers, anyLast(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, anyLast(peers) as peers, anyLast(swarms) as swarms \
         FROM p2p_stats WHERE ts > now() - INTERVAL {} SECOND GROUP BY ts ORDER BY ts",
        interval_expr, secs
    );
    let interval_ts = interval_expr.replace("ts", "timestamp");
    // plays는 시간대별 전체 카운트, unique_visitors는 당일 첫 방문 시간대만 카운트 (IP당 하루 1회)
    // 24시간 초과 기간은 단순 카운트만 (unique visitor 계산 생략 - 너무 느림)
    let visits_query = if secs > 86400 {
        // 24시간 초과: 단순 카운트 (plays만, unique_visitors는 uniqHLL로 근사)
        format!(
            "SELECT {} as ts, count() as plays, uniqHLL12(ip) as unique_visitors \
             FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND GROUP BY ts ORDER BY ts",
            interval_ts, secs
        )
    } else {
        // 24시간 이하: 정확한 고유 방문자 계산
        format!(
            "SELECT ts, sum(plays) as plays, sum(new_visitors) as unique_visitors FROM ( \
                SELECT {} as ts, count() as plays, 0 as new_visitors \
                FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND GROUP BY ts \
                UNION ALL \
                SELECT first_hour as ts, 0 as plays, count() as new_visitors FROM ( \
                    SELECT {} as first_hour FROM visitor_logs \
                    WHERE timestamp > now() - INTERVAL {} SECOND \
                    GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul') \
                ) GROUP BY first_hour \
            ) GROUP BY ts ORDER BY ts",
            interval_ts, secs, interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs
        )
    };
    // 고유 방문자(UV) 기준 - 당일 첫 방문 시간에만 카운트 (IP당 하루 1회)
    // 24시간 초과는 uniqHLL12로 근사
    let (tvmon_query, tvwiki_query, tvhot_query) = if secs > 86400 {
        (
            format!("SELECT {} as ts, uniqHLL12(ip) as cnt FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvmon%' GROUP BY ts ORDER BY ts", interval_ts, secs),
            format!("SELECT {} as ts, uniqHLL12(ip) as cnt FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvwiki%' GROUP BY ts ORDER BY ts", interval_ts, secs),
            format!("SELECT {} as ts, uniqHLL12(ip) as cnt FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvhot%' GROUP BY ts ORDER BY ts", interval_ts, secs)
        )
    } else {
        (
            format!("SELECT first_hour as ts, count() as cnt FROM (SELECT {} as first_hour FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvmon%' GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul')) GROUP BY first_hour ORDER BY ts", interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs),
            format!("SELECT first_hour as ts, count() as cnt FROM (SELECT {} as first_hour FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvwiki%' GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul')) GROUP BY first_hour ORDER BY ts", interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs),
            format!("SELECT first_hour as ts, count() as cnt FROM (SELECT {} as first_hour FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND referrer LIKE '%tvhot%' GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul')) GROUP BY first_hour ORDER BY ts", interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs)
        )
    };
    // Mobile/PC는 첫 방문 기기 기준으로 분류 (중복 없이 mobile + pc = total)
    // 24시간 초과는 uniqHLL12로 근사
    let (mobile_query, pc_query) = if secs > 86400 {
        (
            format!("SELECT {} as ts, uniqHLL12(ip) as cnt FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND device NOT LIKE '%PC%' GROUP BY ts ORDER BY ts", interval_ts, secs),
            format!("SELECT {} as ts, uniqHLL12(ip) as cnt FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND AND device LIKE '%PC%' GROUP BY ts ORDER BY ts", interval_ts, secs)
        )
    } else {
        (
            format!("SELECT first_hour as ts, count() as cnt FROM (SELECT {} as first_hour, argMin(device, timestamp) as first_device FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul') HAVING first_device NOT LIKE '%PC%') GROUP BY first_hour ORDER BY ts", interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs),
            format!("SELECT first_hour as ts, count() as cnt FROM (SELECT {} as first_hour, argMin(device, timestamp) as first_device FROM visitor_logs WHERE timestamp > now() - INTERVAL {} SECOND GROUP BY ip, toStartOfDay(timestamp, 'Asia/Seoul') HAVING first_device LIKE '%PC%') GROUP BY first_hour ORDER BY ts", interval_ts.replace("timestamp", "argMin(timestamp, timestamp)"), secs)
        )
    };

    let (stats_result, visits_result, tvmon_result, tvwiki_result, tvhot_result, mobile_result, pc_result) = tokio::join!(
        clickhouse_query_json(&state.client, &stats_query),
        clickhouse_query_json(&state.client, &visits_query),
        clickhouse_query_json(&state.client, &tvmon_query),
        clickhouse_query_json(&state.client, &tvwiki_query),
        clickhouse_query_json(&state.client, &tvhot_query),
        clickhouse_query_json(&state.client, &mobile_query),
        clickhouse_query_json(&state.client, &pc_query)
    );

    // 에러 로깅
    if stats_result.is_err() {
        eprintln!("[history_stats] stats_query failed: {:?}", stats_result.as_ref().err());
    }
    if visits_result.is_err() {
        eprintln!("[history_stats] visits_query failed: {:?}", visits_result.as_ref().err());
    }

    // stats 쿼리 성공시 visits 실패해도 진행 (방문자 데이터 0으로 채움)
    let visits_json = visits_result.unwrap_or_else(|_| serde_json::json!({"dataset": []}));

    match stats_result {
        Ok(mut stats_json) => {
            let mut plays_map: HashMap<String, i64> = HashMap::new();
            let mut visitors_map: HashMap<String, i64> = HashMap::new();
            // clickhouse_query_json이 "data"를 "dataset"으로 변환함
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
                    // clickhouse_query_json이 "data"를 "dataset"으로 변환함
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

    let secs = micros / 1_000_000;
    let query = format!(
        "SELECT swarm_id, filename, sum(viewers) as total_viewers, \
         sum(http_bytes) as http_bytes, sum(p2p_bytes) as p2p_bytes \
         FROM p2p_swarms \
         WHERE ts > now() - INTERVAL {} SECOND \
         GROUP BY swarm_id, filename \
         ORDER BY total_viewers DESC \
         LIMIT {}",
        secs, limit
    );

    clickhouse_query(&state.client, &query).await
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

    let query = format!(
        "SELECT toHour(ts) as hour, avg(viewers) as avg_viewers \
         FROM p2p_stats \
         WHERE ts > now() - INTERVAL {} DAY \
         GROUP BY toHour(ts) \
         ORDER BY hour",
        days
    );

    clickhouse_query(&state.client, &query).await
}

// 인기파일 API (고유 IP + 트래픽) - 캐싱 및 최적화
async fn api_popular(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("all");
    let limit: i64 = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20).min(100);
    let offset: i64 = params.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    if period == "all" && offset == 0 && limit == 20 {
        let cached = POPULAR_CACHE.read().clone();
        if cached.len() > 2 {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .header("x-cache", "BG")
                .body(axum::body::Body::from(cached))
                .unwrap();
        }
    }

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
        "SELECT swarm_id, anyLast(filename) as filename, uniqExact(ip) as views \
         FROM visitor_logs {} GROUP BY swarm_id ORDER BY views DESC LIMIT {}, {}",
        time_filter, offset, limit
    );

    let views_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&views_query));
    let views_data: serde_json::Value = match state.client.get(&views_url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    // swarm_id 목록 추출
    let mut swarm_ids: Vec<String> = Vec::new();
    let mut views_map: HashMap<String, (String, i64)> = HashMap::new();
    if let Some(dataset) = views_data.get("data").and_then(|d| d.as_array()) {
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
        let traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&traffic_query));
        if let Ok(resp) = state.client.get(&traffic_url).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data.get("data").and_then(|d| d.as_array()) {
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
    let cached = SUMMARY_BG_CACHE.read().clone();
    if cached.len() > 2 {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "BG")
            .body(axum::body::Body::from(cached))
            .unwrap();
    }

    // ========== 캐시 확인 (1초 TTL) ==========
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

    // p2p_stats에서 피크값, 트래픽 (r_* 델타 합산으로 당일 실제 트래픽 계산)
    let today_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, anyLast(swarms) as swarms \
        FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul')";

    let yesterday_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, anyLast(swarms) as swarms \
        FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')";

    // visitor_logs에서 오늘/어제 재생수, 순방문자 (hourly_stats 대신 직접 조회)
    let today_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul')";

    let yesterday_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND timestamp < toStartOfDay(now(), 'Asia/Seoul')";

    let (today_res, yesterday_res, today_hourly_res, yesterday_hourly_res) = tokio::join!(
        clickhouse_query_json(&state.client, today_query),
        clickhouse_query_json(&state.client, yesterday_query),
        clickhouse_query_json(&state.client, today_hourly_query),
        clickhouse_query_json(&state.client, yesterday_hourly_query)
    );

    // ClickHouse JSONCompact 응답에서 첫 번째 행 추출 헬퍼
    // clickhouse_query_json이 "data" → "dataset"으로 변환하므로 "dataset" 사용
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

    // ========== 결과 캐시 (1초 TTL) ==========
    {
        let mut cache = SUMMARY_CACHE.write();
        *cache = Some(CacheEntry {
            data: body.clone(),
            expires_at: Instant::now() + Duration::from_secs(1),
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

    // IP 필터가 있으면 조건 추가 (ClickHouse LIKE 사용)
    let ip_condition = if let Some(ip) = ip_filter {
        format!(" AND ip LIKE '%{}%'", sanitize_ip_pattern(ip))
    } else {
        String::new()
    };

    // 기간별 시간 문자열 (QuestDB dateadd 사용)
    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "1d" => "now() - INTERVAL 1 DAY",
        "7d" => "now() - INTERVAL 7 DAY",
        "30d" => "now() - INTERVAL 30 DAY",
        _ => "now() - INTERVAL 1 HOUR",
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

    clickhouse_query(&state.client, &query).await
}

async fn clickhouse_query(client: &Client, query: &str) -> Response {
    let query_with_format = if query.trim().to_uppercase().starts_with("SELECT") {
        format!("{} FORMAT JSONCompact", query)
    } else {
        query.to_string()
    };

    match client.post(CLICKHOUSE_URL).body(query_with_format).send().await {
        Ok(resp) => {
            let body = resp.text().await.unwrap_or_default();
            // ClickHouse "data" -> QuestDB 호환 "dataset" 변환
            let modified = rename_data_to_dataset(&body);
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .body(axum::body::Body::from(modified))
                .unwrap()
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            (StatusCode::BAD_GATEWAY, axum::Json(error)).into_response()
        }
    }
}

async fn clickhouse_query_json(client: &Client, query: &str) -> Result<serde_json::Value, String> {
    let query_with_format = if query.trim().to_uppercase().starts_with("SELECT") {
        format!("{} FORMAT JSONCompact", query)
    } else {
        query.to_string()
    };

    let resp = client.post(CLICKHOUSE_URL).body(query_with_format).send().await.map_err(|e| e.to_string())?;
    let body = resp.text().await.map_err(|e| e.to_string())?;
    // ClickHouse "data" -> QuestDB 호환 "dataset" 변환
    let body = rename_data_to_dataset(&body);
    serde_json::from_str(&body).map_err(|e| e.to_string())
}

// 초기 데이터 API (summary + daily + monthly)
async fn api_init_data(State(_state): State<AppState>) -> Response {
    let cached = INIT_DATA_CACHE.read().clone();
    if cached.len() > 2 {
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "BG")
            .body(axum::body::Body::from(cached))
            .unwrap();
    }
    let client = &_state.client;

    let today_traffic = cumulative_diff_traffic_subquery("ts >= toStartOfDay(now(), 'Asia/Seoul')");
    let yesterday_traffic = cumulative_diff_traffic_subquery(
        "ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')"
    );
    let today_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", today_traffic
    );
    let yesterday_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", yesterday_traffic
    );
    let today_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul')";
    let yesterday_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND timestamp < toStartOfDay(now(), 'Asia/Seoul')";
    let daily_cached_query = "SELECT toDate(date) as day, plays, unique_visitors as visitors, \
        tvmon_visitors as tvmon, tvwiki_visitors as tvwiki, tvhot_visitors as tvhot, \
        mobile_visitors as mobile, pc_visitors as pc, \
        http_bytes, p2p_bytes, p2p_up_bytes, max_viewers \
        FROM daily_summary FINAL \
        WHERE date >= toDate(now(), 'Asia/Seoul') - 30 AND date < toDate(now(), 'Asia/Seoul') \
        ORDER BY day";
    let today_daily_traffic = cumulative_diff_traffic_grouped(
        "ts >= toStartOfDay(now(), 'Asia/Seoul')",
        "toStartOfDay(ts, 'Asia/Seoul')", "day"
    );
    let today_daily_query = format!(
        "SELECT t.day, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.max_viewers \
         FROM {} t \
         LEFT JOIN (SELECT toStartOfDay(ts, 'Asia/Seoul') as day, max(viewers) as max_viewers \
                    FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') GROUP BY day) s \
         ON t.day = s.day ORDER BY t.day", today_daily_traffic
    );
    let today_visitor_query = "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as day, \
        count() as plays, uniq(ip) as visitors, \
        uniqIf(ip, referrer LIKE '%tvmon%') as tvmon, \
        uniqIf(ip, referrer LIKE '%tvwiki%') as tvwiki, \
        uniqIf(ip, referrer LIKE '%tvhot%') as tvhot, \
        uniqIf(ip, device NOT LIKE '%PC%') as mobile, \
        uniqIf(ip, device LIKE '%PC%') as pc \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') GROUP BY day ORDER BY day";
    let monthly_traffic = cumulative_diff_traffic_grouped(
        "1=1", "toStartOfMonth(ts)", "month"
    );
    let monthly_query = format!(
        "SELECT t.month, s.peak_viewers, s.peak_users, t.http_bytes as total_http, t.p2p_bytes as total_p2p \
         FROM {} t \
         LEFT JOIN (SELECT toStartOfMonth(ts) as month, max(viewers) as peak_viewers, max(unique_users) as peak_users \
                    FROM p2p_stats GROUP BY month) s \
         ON t.month = s.month ORDER BY t.month DESC LIMIT 12", monthly_traffic
    );

    let (today_res, yesterday_res, today_visitors_res, yesterday_visitors_res, daily_cached_res, today_daily_res, today_visitor_res, monthly_res) = tokio::join!(
        clickhouse_query_json(client, &today_query),
        clickhouse_query_json(client, &yesterday_query),
        clickhouse_query_json(client, today_hourly_query),
        clickhouse_query_json(client, yesterday_hourly_query),
        clickhouse_query_json(client, daily_cached_query),
        clickhouse_query_json(client, &today_daily_query),
        clickhouse_query_json(client, today_visitor_query),
        clickhouse_query_json(client, &monthly_query)
    );

    // ClickHouse 응답에서 첫 번째 행 추출 헬퍼 (dataset 키 사용)
    fn extract_row(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        json.get("dataset")?.as_array()?.first()?.as_array()
    }

    // ClickHouse는 숫자를 문자열로 반환할 수 있음
    fn parse_num(v: Option<&serde_json::Value>) -> i64 {
        v.and_then(|val| {
            val.as_i64().or_else(|| val.as_str().and_then(|s| s.parse().ok()))
        }).unwrap_or(0)
    }

    // 오늘 데이터 파싱: [max_viewers, max_users, http_bytes, p2p_bytes, swarms]
    let today_row = today_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_visitors_row = today_visitors_res.as_ref().ok().and_then(|j| extract_row(j));

    let today_data = serde_json::json!({
        "max_viewers": parse_num(today_row.and_then(|r| r.get(0))),
        "max_users": parse_num(today_row.and_then(|r| r.get(1))),
        "http_bytes": parse_num(today_row.and_then(|r| r.get(2))),
        "p2p_bytes": parse_num(today_row.and_then(|r| r.get(3))),
        "swarms": parse_num(today_row.and_then(|r| r.get(4))),
        "plays": parse_num(today_visitors_row.and_then(|r| r.get(0))),
        "unique_visitors": parse_num(today_visitors_row.and_then(|r| r.get(1)))
    });

    // 어제 데이터 파싱
    let yesterday_row = yesterday_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_visitors_row = yesterday_visitors_res.as_ref().ok().and_then(|j| extract_row(j));

    let yesterday_data = serde_json::json!({
        "max_viewers": parse_num(yesterday_row.and_then(|r| r.get(0))),
        "max_users": parse_num(yesterday_row.and_then(|r| r.get(1))),
        "http_bytes": parse_num(yesterday_row.and_then(|r| r.get(2))),
        "p2p_bytes": parse_num(yesterday_row.and_then(|r| r.get(3))),
        "swarms": parse_num(yesterday_row.and_then(|r| r.get(4))),
        "plays": parse_num(yesterday_visitors_row.and_then(|r| r.get(0))),
        "unique_visitors": parse_num(yesterday_visitors_row.and_then(|r| r.get(1)))
    });

    let summary = serde_json::json!({
        "today": today_data,
        "yesterday": yesterday_data
    });

    // 일별 데이터: 캐시된 과거 데이터 + 오늘 실시간 데이터 병합
    let mut daily_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();

    // 1. 캐시된 과거 데이터 로드 (daily_summary 테이블)
    // 컬럼순서: day, plays, visitors, tvmon, tvwiki, tvhot, mobile, pc, http_bytes, p2p_bytes, p2p_up_bytes, max_viewers
    if let Ok(ref cached_data) = daily_cached_res {
        if let Some(dataset) = cached_data.get("dataset").and_then(|d| d.as_array()) {
            for row in dataset {
                if let Some(arr) = row.as_array() {
                    let day: String = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").chars().take(10).collect();
                    daily_map.insert(day, serde_json::json!({
                        "plays": arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0),
                        "visitors": arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvmon": arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvwiki": arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvhot": arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0),
                        "mobile": arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0),
                        "pc": arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0),
                        "http_bytes": arr.get(8).and_then(|v| v.as_i64()).unwrap_or(0),
                        "p2p_bytes": arr.get(9).and_then(|v| v.as_i64()).unwrap_or(0),
                        "p2p_up_bytes": arr.get(10).and_then(|v| v.as_i64()).unwrap_or(0),
                        "max_viewers": arr.get(11).and_then(|v| v.as_i64()).unwrap_or(0)
                    }));
                }
            }
        }
    }

    // 2. 오늘 실시간 데이터 추가 (p2p_stats + visitor_logs)
    if let Ok(ref today_p2p) = today_daily_res {
        if let Some(dataset) = today_p2p.get("dataset").and_then(|d| d.as_array()) {
            for row in dataset {
                if let Some(arr) = row.as_array() {
                    let day: String = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").chars().take(10).collect();
                    let entry = daily_map.entry(day).or_insert(serde_json::json!({}));
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("http_bytes".to_string(), serde_json::json!(arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("p2p_bytes".to_string(), serde_json::json!(arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("p2p_up_bytes".to_string(), serde_json::json!(arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("max_viewers".to_string(), serde_json::json!(arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0)));
                    }
                }
            }
        }
    }
    if let Ok(ref today_visitors) = today_visitor_res {
        if let Some(dataset) = today_visitors.get("dataset").and_then(|d| d.as_array()) {
            for row in dataset {
                if let Some(arr) = row.as_array() {
                    let day: String = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").chars().take(10).collect();
                    let entry = daily_map.entry(day).or_insert(serde_json::json!({}));
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("plays".to_string(), serde_json::json!(arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("visitors".to_string(), serde_json::json!(arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvmon".to_string(), serde_json::json!(arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvwiki".to_string(), serde_json::json!(arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvhot".to_string(), serde_json::json!(arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("mobile".to_string(), serde_json::json!(arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("pc".to_string(), serde_json::json!(arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0)));
                    }
                }
            }
        }
    }

    // daily_stats 배열로 변환 (프론트엔드 형식)
    let mut daily_rows: Vec<Vec<serde_json::Value>> = daily_map.iter()
        .map(|(day, data)| vec![
            serde_json::json!(day),
            data.get("plays").cloned().unwrap_or(serde_json::json!(0)),
            data.get("visitors").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvmon").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvwiki").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvhot").cloned().unwrap_or(serde_json::json!(0)),
            data.get("mobile").cloned().unwrap_or(serde_json::json!(0)),
            data.get("pc").cloned().unwrap_or(serde_json::json!(0)),
            data.get("http_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("p2p_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("p2p_up_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("max_viewers").cloned().unwrap_or(serde_json::json!(0)),
        ])
        .collect();
    daily_rows.sort_by(|a, b| a[0].as_str().unwrap_or("").cmp(b[0].as_str().unwrap_or("")));
    let daily_stats = serde_json::json!({"dataset": daily_rows});
    let monthly_stats = monthly_res.unwrap_or(serde_json::json!({}));

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

async fn build_init_data(client: &Client) -> String {
    let today_traffic = cumulative_diff_traffic_subquery("ts >= toStartOfDay(now(), 'Asia/Seoul')");
    let yesterday_traffic = cumulative_diff_traffic_subquery(
        "ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')"
    );
    let today_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", today_traffic
    );
    let yesterday_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", yesterday_traffic
    );
    let today_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul')";
    let yesterday_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND timestamp < toStartOfDay(now(), 'Asia/Seoul')";
    let daily_cached_query = "SELECT toDate(date) as day, plays, unique_visitors as visitors, \
        tvmon_visitors as tvmon, tvwiki_visitors as tvwiki, tvhot_visitors as tvhot, \
        mobile_visitors as mobile, pc_visitors as pc, \
        http_bytes, p2p_bytes, p2p_up_bytes, max_viewers \
        FROM daily_summary FINAL \
        WHERE date >= toDate(now(), 'Asia/Seoul') - 30 AND date < toDate(now(), 'Asia/Seoul') \
        ORDER BY day";
    let today_daily_traffic = cumulative_diff_traffic_grouped(
        "ts >= toStartOfDay(now(), 'Asia/Seoul')",
        "toStartOfDay(ts, 'Asia/Seoul')", "day"
    );
    let today_daily_query = format!(
        "SELECT t.day, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.max_viewers \
         FROM {} t \
         LEFT JOIN (SELECT toStartOfDay(ts, 'Asia/Seoul') as day, max(viewers) as max_viewers \
                    FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') GROUP BY day) s \
         ON t.day = s.day ORDER BY t.day", today_daily_traffic
    );
    let today_visitor_query = "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as day, \
        count() as plays, uniq(ip) as visitors, \
        uniqIf(ip, referrer LIKE '%tvmon%') as tvmon, \
        uniqIf(ip, referrer LIKE '%tvwiki%') as tvwiki, \
        uniqIf(ip, referrer LIKE '%tvhot%') as tvhot, \
        uniqIf(ip, device NOT LIKE '%PC%') as mobile, \
        uniqIf(ip, device LIKE '%PC%') as pc \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') GROUP BY day ORDER BY day";
    let monthly_traffic = cumulative_diff_traffic_grouped(
        "1=1", "toStartOfMonth(ts)", "month"
    );
    let monthly_query = format!(
        "SELECT t.month, s.peak_viewers, s.peak_users, t.http_bytes as total_http, t.p2p_bytes as total_p2p \
         FROM {} t \
         LEFT JOIN (SELECT toStartOfMonth(ts) as month, max(viewers) as peak_viewers, max(unique_users) as peak_users \
                    FROM p2p_stats GROUP BY month) s \
         ON t.month = s.month ORDER BY t.month DESC LIMIT 12", monthly_traffic
    );

    let (today_res, yesterday_res, today_visitors_res, yesterday_visitors_res, daily_cached_res, today_daily_res, today_visitor_res, monthly_res) = tokio::join!(
        clickhouse_query_json(client, &today_query),
        clickhouse_query_json(client, &yesterday_query),
        clickhouse_query_json(client, today_hourly_query),
        clickhouse_query_json(client, yesterday_hourly_query),
        clickhouse_query_json(client, daily_cached_query),
        clickhouse_query_json(client, &today_daily_query),
        clickhouse_query_json(client, today_visitor_query),
        clickhouse_query_json(client, &monthly_query)
    );

    fn extract_row(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        json.get("dataset")?.as_array()?.first()?.as_array()
    }
    fn parse_num(v: Option<&serde_json::Value>) -> i64 {
        v.and_then(|val| val.as_i64().or_else(|| val.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0)
    }

    let today_row = today_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_visitors_row = today_visitors_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_data = serde_json::json!({
        "max_viewers": parse_num(today_row.and_then(|r| r.get(0))),
        "max_users": parse_num(today_row.and_then(|r| r.get(1))),
        "http_bytes": parse_num(today_row.and_then(|r| r.get(2))),
        "p2p_bytes": parse_num(today_row.and_then(|r| r.get(3))),
        "p2p_up_bytes": parse_num(today_row.and_then(|r| r.get(4))),
        "swarms": parse_num(today_row.and_then(|r| r.get(5))),
        "plays": parse_num(today_visitors_row.and_then(|r| r.get(0))),
        "unique_visitors": parse_num(today_visitors_row.and_then(|r| r.get(1)))
    });

    let yesterday_row = yesterday_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_visitors_row = yesterday_visitors_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_data = serde_json::json!({
        "max_viewers": parse_num(yesterday_row.and_then(|r| r.get(0))),
        "max_users": parse_num(yesterday_row.and_then(|r| r.get(1))),
        "http_bytes": parse_num(yesterday_row.and_then(|r| r.get(2))),
        "p2p_bytes": parse_num(yesterday_row.and_then(|r| r.get(3))),
        "p2p_up_bytes": parse_num(yesterday_row.and_then(|r| r.get(4))),
        "swarms": parse_num(yesterday_row.and_then(|r| r.get(5))),
        "plays": parse_num(yesterday_visitors_row.and_then(|r| r.get(0))),
        "unique_visitors": parse_num(yesterday_visitors_row.and_then(|r| r.get(1)))
    });

    let summary = serde_json::json!({ "today": today_data, "yesterday": yesterday_data });

    let daily_cached = daily_cached_res.unwrap_or(serde_json::json!({}));
    let today_daily = today_daily_res.unwrap_or(serde_json::json!({}));
    let today_visitor = today_visitor_res.unwrap_or(serde_json::json!({}));

    // HashMap으로 날짜별 중복 제거 (어제 데이터가 캐시+실시간 양쪽에 존재하는 문제 해결)
    // 날짜 키 정규화: "2026-02-18 00:00:00" 또는 "2026-02-18T00:00:00Z" → "2026-02-18"
    fn normalize_date(raw: &str) -> String {
        raw.chars().take(10).collect()
    }
    let mut daily_map: std::collections::HashMap<String, serde_json::Value> = std::collections::HashMap::new();

    // 1. 캐시된 과거 데이터 로드 (daily_summary 테이블)
    if let Some(dataset) = daily_cached.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let day = normalize_date(arr.get(0).and_then(|v| v.as_str()).unwrap_or(""));
                if day.len() == 10 {
                    daily_map.insert(day, serde_json::json!({
                        "plays": arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0),
                        "visitors": arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvmon": arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvwiki": arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0),
                        "tvhot": arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0),
                        "mobile": arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0),
                        "pc": arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0),
                        "http_bytes": arr.get(8).and_then(|v| v.as_i64()).unwrap_or(0),
                        "p2p_bytes": arr.get(9).and_then(|v| v.as_i64()).unwrap_or(0),
                        "p2p_up_bytes": arr.get(10).and_then(|v| v.as_i64()).unwrap_or(0),
                        "max_viewers": arr.get(11).and_then(|v| v.as_i64()).unwrap_or(0)
                    }));
                }
            }
        }
    }

    // 2. 실시간 트래픽 데이터 오버레이 (어제+오늘 — 캐시보다 신선한 데이터로 덮어씀)
    if let Some(dataset) = today_daily.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let day = normalize_date(arr.get(0).and_then(|v| v.as_str()).unwrap_or(""));
                if day.len() == 10 {
                    let entry = daily_map.entry(day).or_insert(serde_json::json!({}));
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("http_bytes".to_string(), serde_json::json!(arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("p2p_bytes".to_string(), serde_json::json!(arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("p2p_up_bytes".to_string(), serde_json::json!(arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("max_viewers".to_string(), serde_json::json!(arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0)));
                    }
                }
            }
        }
    }

    // 3. 실시간 방문자 데이터 오버레이
    if let Some(dataset) = today_visitor.get("dataset").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let day = normalize_date(arr.get(0).and_then(|v| v.as_str()).unwrap_or(""));
                if day.len() == 10 {
                    let entry = daily_map.entry(day).or_insert(serde_json::json!({}));
                    if let Some(obj) = entry.as_object_mut() {
                        obj.insert("plays".to_string(), serde_json::json!(arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("visitors".to_string(), serde_json::json!(arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvmon".to_string(), serde_json::json!(arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvwiki".to_string(), serde_json::json!(arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("tvhot".to_string(), serde_json::json!(arr.get(5).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("mobile".to_string(), serde_json::json!(arr.get(6).and_then(|v| v.as_i64()).unwrap_or(0)));
                        obj.insert("pc".to_string(), serde_json::json!(arr.get(7).and_then(|v| v.as_i64()).unwrap_or(0)));
                    }
                }
            }
        }
    }

    // 4. HashMap → 정렬된 Vec 변환 (프론트엔드 형식)
    let mut daily_rows: Vec<Vec<serde_json::Value>> = daily_map.iter()
        .map(|(day, data)| vec![
            serde_json::json!(day),
            data.get("plays").cloned().unwrap_or(serde_json::json!(0)),
            data.get("visitors").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvmon").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvwiki").cloned().unwrap_or(serde_json::json!(0)),
            data.get("tvhot").cloned().unwrap_or(serde_json::json!(0)),
            data.get("mobile").cloned().unwrap_or(serde_json::json!(0)),
            data.get("pc").cloned().unwrap_or(serde_json::json!(0)),
            data.get("http_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("p2p_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("p2p_up_bytes").cloned().unwrap_or(serde_json::json!(0)),
            data.get("max_viewers").cloned().unwrap_or(serde_json::json!(0)),
        ])
        .collect();
    daily_rows.sort_by(|a, b| a[0].as_str().unwrap_or("").cmp(b[0].as_str().unwrap_or("")));
    let daily_stats = serde_json::json!({"dataset": daily_rows});
    let monthly_stats = monthly_res.unwrap_or(serde_json::json!({}));

    serde_json::json!({
        "summary": summary,
        "daily_stats": daily_stats,
        "monthly_stats": monthly_stats
    }).to_string()
}

async fn build_summary_bg(client: &Client) -> String {
    let today_traffic = cumulative_diff_traffic_subquery("ts >= toStartOfDay(now(), 'Asia/Seoul')");
    let yesterday_traffic = cumulative_diff_traffic_subquery(
        "ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')"
    );
    let today_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", today_traffic
    );
    let yesterday_query = format!(
        "SELECT s.max_viewers, s.max_users, t.http_bytes, t.p2p_bytes, t.p2p_up_bytes, s.swarms \
         FROM (SELECT max(viewers) as max_viewers, max(unique_users) as max_users, anyLast(swarms) as swarms \
               FROM p2p_stats WHERE ts >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND ts < toStartOfDay(now(), 'Asia/Seoul')) s \
         CROSS JOIN {} t", yesterday_traffic
    );
    let today_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul')";
    let yesterday_hourly_query = "SELECT count() as plays, uniq(ip) as unique_visitors \
        FROM visitor_logs WHERE timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND timestamp < toStartOfDay(now(), 'Asia/Seoul')";

    let (today_res, yesterday_res, today_hourly_res, yesterday_hourly_res) = tokio::join!(
        clickhouse_query_json(client, &today_query),
        clickhouse_query_json(client, &yesterday_query),
        clickhouse_query_json(client, today_hourly_query),
        clickhouse_query_json(client, yesterday_hourly_query)
    );

    fn extract_row(json: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
        json.get("dataset")?.as_array()?.first()?.as_array()
    }

    let today_row = today_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_hourly_row = today_hourly_res.as_ref().ok().and_then(|j| extract_row(j));
    let today_data = serde_json::json!({
        "max_viewers": today_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": today_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": today_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": today_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_up_bytes": today_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": today_row.and_then(|r| r.get(5)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": today_hourly_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": today_hourly_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    let yesterday_row = yesterday_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_hourly_row = yesterday_hourly_res.as_ref().ok().and_then(|j| extract_row(j));
    let yesterday_data = serde_json::json!({
        "max_viewers": yesterday_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "max_users": yesterday_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0),
        "http_bytes": yesterday_row.and_then(|r| r.get(2)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_bytes": yesterday_row.and_then(|r| r.get(3)).and_then(|v| v.as_i64()).unwrap_or(0),
        "p2p_up_bytes": yesterday_row.and_then(|r| r.get(4)).and_then(|v| v.as_i64()).unwrap_or(0),
        "swarms": yesterday_row.and_then(|r| r.get(5)).and_then(|v| v.as_i64()).unwrap_or(0),
        "plays": yesterday_hourly_row.and_then(|r| r.get(0)).and_then(|v| v.as_i64()).unwrap_or(0),
        "unique_visitors": yesterday_hourly_row.and_then(|r| r.get(1)).and_then(|v| v.as_i64()).unwrap_or(0)
    });

    serde_json::json!({ "today": today_data, "yesterday": yesterday_data }).to_string()
}

async fn build_servers_realtime(client: &Client) -> String {
    let query = "SELECT timestamp, server, http_bytes, p2p_bytes, viewers \
         FROM p2p_servers WHERE timestamp > now() - INTERVAL 10 MINUTE AND server LIKE 'every%' ORDER BY timestamp, server LIMIT 1000 FORMAT JSONCompact";
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(query));

    let data: serde_json::Value = match client.get(&url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let mut server_timelines: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    let mut prev_values: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();

    if let Some(dataset) = data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let ts = arr.get(0).and_then(|v| v.as_str()).unwrap_or("");
                let server = arr.get(1).and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                let http = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let viewers = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);

                let (prev_http, prev_p2p) = prev_values.get(&server).copied().unwrap_or((http, p2p));
                let http_delta = (http - prev_http).max(0);
                let p2p_delta = (p2p - prev_p2p).max(0);
                prev_values.insert(server.clone(), (http, p2p));

                let timeline = server_timelines.entry(server.clone()).or_insert(Vec::new());
                timeline.push(serde_json::json!({
                    "ts": ts, "http": http_delta, "p2p": p2p_delta, "viewers": viewers
                }));
            }
        }
    }

    serde_json::json!({ "servers": server_timelines }).to_string()
}

async fn build_ip_analysis(client: &Client) -> String {
    let page_size = 200;
    let num_pages = 10;
    let semaphore = std::sync::Arc::new(Semaphore::new(5));
    let mut handles = Vec::new();

    for page in 0..num_pages {
        let url = format!("{}/api/sessions?limit={}&offset={}", SIMPLE_WS_URL, page_size, page * page_size);
        let c = client.clone();
        let sem = semaphore.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await;
            match c.get(&url).send().await {
                Ok(r) => r.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({})),
                Err(_) => serde_json::json!({}),
            }
        }));
    }

    let mut all_sessions: Vec<serde_json::Value> = Vec::new();
    let mut total_sessions: i64 = 0;
    for handle in handles {
        if let Ok(result) = handle.await {
            if let Some(total) = result.get("total").and_then(|v| v.as_i64()) {
                total_sessions = total;
            }
            if let Some(data) = result.get("data").and_then(|d| d.as_array()) {
                all_sessions.extend(data.clone());
            }
        }
    }

    let mut ip_map: std::collections::HashMap<String, (i64, i64, i64, i64, String, String)> = std::collections::HashMap::new();
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
        total_http += http; total_p2p += p2p; total_p2p_up += p2p_up;
        let entry = ip_map.entry(ip).or_insert((0, 0, 0, 0, String::new(), String::new()));
        entry.0 += 1; entry.1 += http; entry.2 += p2p; entry.3 += p2p_up;
        if !server.is_empty() { entry.4 = server; }
        if !filename.is_empty() { entry.5 = filename; }
    }

    let mut ip_list: Vec<_> = ip_map.into_iter().collect();
    ip_list.sort_by(|a, b| (b.1.1 + b.1.2).cmp(&(a.1.1 + a.1.2)));
    let unique_ips = ip_list.len() as i64;
    let ips: Vec<serde_json::Value> = ip_list.into_iter().take(100).map(|(ip, s)| {
        serde_json::json!({
            "ip": ip, "sessions": s.0, "httpBytes": s.1, "p2pBytes": s.2,
            "p2pUpBytes": s.3, "totalBytes": s.1 + s.2, "server": s.4, "filename": s.5
        })
    }).collect();

    serde_json::json!({
        "period": "realtime",
        "totals": { "totalSessions": total_sessions, "uniqueIps": unique_ips, "totalHttp": total_http, "totalP2p": total_p2p, "totalP2pUp": total_p2p_up },
        "ips": ips
    }).to_string()
}

async fn build_popular(client: &Client) -> String {
    let views_query = "SELECT swarm_id, anyLast(filename) as filename, uniq(ip) as views \
         FROM visitor_logs GROUP BY swarm_id ORDER BY views DESC LIMIT 20";
    let views_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(views_query));
    let views_data: serde_json::Value = match client.get(&views_url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let mut swarm_ids: Vec<String> = Vec::new();
    let mut views_map: HashMap<String, (String, i64)> = HashMap::new();
    if let Some(dataset) = views_data.get("data").and_then(|d| d.as_array()) {
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

    let mut traffic_map: HashMap<String, (i64, i64)> = HashMap::new();
    if !swarm_ids.is_empty() {
        let ids_str = swarm_ids.iter().map(|s| format!("'{}'", s.replace("'", "''"))).collect::<Vec<_>>().join(",");
        let traffic_query = format!(
            "SELECT swarm_id, max(http_bytes), max(p2p_bytes) FROM p2p_swarms WHERE swarm_id IN ({}) GROUP BY swarm_id", ids_str
        );
        let traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&traffic_query));
        if let Ok(resp) = client.get(&traffic_url).send().await {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data.get("data").and_then(|d| d.as_array()) {
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

    let result_dataset: Vec<serde_json::Value> = swarm_ids.iter().filter_map(|sid| {
        views_map.get(sid).map(|(filename, views)| {
            let (http, p2p) = traffic_map.get(sid).copied().unwrap_or((0, 0));
            serde_json::json!([sid, filename, views, http, p2p])
        })
    }).collect();

    serde_json::json!({
        "columns": [
            {"name": "swarm_id", "type": "STRING"}, {"name": "filename", "type": "STRING"},
            {"name": "views", "type": "LONG"}, {"name": "http_bytes", "type": "LONG"}, {"name": "p2p_bytes", "type": "LONG"}
        ],
        "dataset": result_dataset
    }).to_string()
}

async fn build_traffic_realtime(client: &Client) -> String {
    let time_filter = "ts > now() - INTERVAL 10 MINUTE";
    let interval_expr = "toStartOfInterval(ts, INTERVAL 10 SECOND)";

    let timeline_query = format!(
        "SELECT {} as ts, avg(viewers) as viewers, avg(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, avg(peers) as peers, avg(swarms) as swarms \
         FROM p2p_stats WHERE {} GROUP BY ts ORDER BY ts",
        interval_expr, time_filter
    );

    let total_query = format!(
        "SELECT max(viewers) as peak_viewers, max(unique_users) as peak_users, \
         max(peers) as peak_peers, max(swarms) as peak_swarms \
         FROM p2p_stats WHERE {}", time_filter
    );

    let traffic_query = format!(
        "SELECT sum(r_http_bytes) as total_http, sum(r_p2p_bytes) as total_p2p, \
         sum(r_p2p_up_bytes) as total_up \
         FROM p2p_stats WHERE {}", time_filter
    );

    let server_traffic_query = format!(
        "SELECT server, sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, max(viewers) as peak_viewers \
         FROM p2p_servers WHERE {} GROUP BY server ORDER BY http_bytes DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    // uniqExact → uniq (HLL 근사, realtime에서 정확성 불필요)
    let visitor_query = format!(
        "SELECT left(swarm_id, position(swarm_id, '.') - 1) as server, \
         uniq(ip) as visitors, count() as requests \
         FROM visitor_logs WHERE {} GROUP BY server ORDER BY visitors DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    let server_speed_query = "SELECT server, sum(r_http_bytes) as r_http, sum(r_p2p_bytes) as r_p2p, sum(r_p2p_up_bytes) as r_p2p_up, \
         max(viewers) as viewers, max(unique_ips) as unique_ips \
         FROM p2p_servers WHERE timestamp > now() - INTERVAL 30 SECOND GROUP BY server";

    let timeline_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&timeline_query));
    let total_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&total_query));
    let traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&traffic_query));
    let server_traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&server_traffic_query));
    let visitor_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&visitor_query));
    let server_speed_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(server_speed_query));
    let realtime_url = format!("{}/api/realtime", SIMPLE_WS_URL);

    let (timeline_res, total_res, traffic_res, server_traffic_res, visitor_res, server_speed_res, realtime_res) = tokio::join!(
        client.get(&timeline_url).send(),
        client.get(&total_url).send(),
        client.get(&traffic_url).send(),
        client.get(&server_traffic_url).send(),
        client.get(&visitor_url).send(),
        client.get(&server_speed_url).send(),
        client.get(&realtime_url).send()
    );

    let timeline_data: serde_json::Value = match timeline_res {
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
    let realtime_data: serde_json::Value = match realtime_res {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    let (total_http, total_p2p, total_p2p_up) = if let Some(dataset) = traffic_data.get("data").and_then(|d| d.as_array()) {
        if let Some(row) = dataset.first().and_then(|r| r.as_array()) {
            (
                row.get(0).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
                row.get(1).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
                row.get(2).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0),
            )
        } else { (0, 0, 0) }
    } else { (0, 0, 0) };

    let mut timeline: Vec<serde_json::Value> = Vec::new();
    if let Some(dataset) = timeline_data.get("data").and_then(|d| d.as_array()) {
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

    let empty_player = serde_json::json!({});
    let (http_gbps, p2p_gbps, p2p_up_gbps) = {
        let p1 = realtime_data.get("player1").unwrap_or(&empty_player);
        let r_http = p1.get("rHttpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p = p1.get("rP2pBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p_up = p1.get("rP2pUpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        (
            (r_http as f64) * 8.0 / 1_000_000_000.0,
            (r_p2p as f64) * 8.0 / 1_000_000_000.0,
            (r_p2p_up as f64) * 8.0 / 1_000_000_000.0,
        )
    };

    let mut totals = serde_json::json!({
        "totalHttp": total_http, "totalP2p": total_p2p, "totalP2pUp": total_p2p_up,
        "httpGbps": format!("{:.2}", http_gbps), "p2pGbps": format!("{:.2}", p2p_gbps),
        "p2pUpGbps": format!("{:.2}", p2p_up_gbps)
    });
    if let Some(dataset) = total_data.get("data").and_then(|d| d.as_array()) {
        if let Some(row) = dataset.first().and_then(|r| r.as_array()) {
            totals = serde_json::json!({
                "peakViewers": row.get(0), "peakUsers": row.get(1),
                "totalHttp": total_http, "totalP2p": total_p2p, "totalP2pUp": total_p2p_up,
                "httpGbps": format!("{:.2}", http_gbps), "p2pGbps": format!("{:.2}", p2p_gbps),
                "p2pUpGbps": format!("{:.2}", p2p_up_gbps),
                "peakPeers": row.get(2), "peakSwarms": row.get(3)
            });
        }
    }

    let mut server_traffic_map: HashMap<String, (i64, i64, i64, i64)> = HashMap::new();
    if let Some(dataset) = server_traffic_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let http_bytes = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_bytes = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_up_bytes = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let peak_viewers = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
                server_traffic_map.insert(server, (http_bytes, p2p_bytes, p2p_up_bytes, peak_viewers));
            }
        }
    }

    let mut visitor_map: HashMap<String, (i64, i64)> = HashMap::new();
    if let Some(dataset) = visitor_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let visitors = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let requests = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                visitor_map.insert(server, (visitors, requests));
            }
        }
    }

    let mut server_speed_map: HashMap<String, (f64, f64, f64, i64, i64)> = HashMap::new();
    if let Some(dataset) = server_speed_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let r_http = arr.get(1).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p = arr.get(2).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p_up = arr.get(3).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let viewers = arr.get(4).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let unique_ips = arr.get(5).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                server_speed_map.insert(server, (
                    (r_http as f64) * 8.0 / 30.0 / 1_000_000_000.0,
                    (r_p2p as f64) * 8.0 / 30.0 / 1_000_000_000.0,
                    (r_p2p_up as f64) * 8.0 / 30.0 / 1_000_000_000.0,
                    viewers,
                    unique_ips,
                ));
            }
        }
    }

    let mut all_servers: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in server_speed_map.keys() { all_servers.insert(s.clone()); }
    for s in server_traffic_map.keys() { all_servers.insert(s.clone()); }

    let mut cdn_servers: Vec<(String, i64, i64, i64, i64, i64, i64, f64, f64, f64)> = all_servers.iter()
        .filter(|s| s.starts_with("every") && *s != "every999")
        .map(|s| {
            let (http, p2p, p2p_up, peak) = server_traffic_map.get(s).copied().unwrap_or((0, 0, 0, 0));
            let (http_gbs, p2p_gbs, p2p_up_gbs, viewers, unique_ips) = server_speed_map.get(s).copied().unwrap_or((0.0, 0.0, 0.0, 0, 0));
            (s.clone(), http, p2p, p2p_up, peak, viewers, unique_ips, http_gbs, p2p_gbs, p2p_up_gbs)
        })
        .collect();
    cdn_servers.sort_by(|a, b| b.7.partial_cmp(&a.7).unwrap_or(std::cmp::Ordering::Equal));

    let mut sum_http_gbps: f64 = 0.0;
    let mut sum_p2p_gbps: f64 = 0.0;
    let mut sum_p2p_up_gbps: f64 = 0.0;
    let mut servers: Vec<serde_json::Value> = Vec::new();
    for &(ref server, http, p2p, p2p_up, _peak, viewers, unique_ips, http_gbs, p2p_gbs, p2p_up_gbs) in &cdn_servers {
        let clamped_p2p_up = p2p_up.min(p2p);
        let clamped_p2p_up_gbs = p2p_up_gbs.min(p2p_gbs);
        sum_http_gbps += http_gbs;
        sum_p2p_gbps += p2p_gbs;
        sum_p2p_up_gbps += clamped_p2p_up_gbs;
        servers.push(serde_json::json!({
            "server": server, "http": http, "p2p": p2p, "p2pUp": clamped_p2p_up,
            "httpGbps": format!("{:.2}", http_gbs),
            "p2pGbps": format!("{:.2}", p2p_gbs),
            "p2pUpGbps": format!("{:.2}", clamped_p2p_up_gbs),
            "visitors": viewers, "requests": unique_ips
        }));
    }

    totals["httpGbps"] = serde_json::json!(format!("{:.2}", sum_http_gbps));
    totals["p2pGbps"] = serde_json::json!(format!("{:.2}", sum_p2p_gbps));
    totals["p2pUpGbps"] = serde_json::json!(format!("{:.2}", sum_p2p_up_gbps));

    let result = serde_json::json!({
        "period": "realtime",
        "timeline": timeline,
        "totals": totals,
        "servers": servers
    });

    result.to_string()
}

// 트래픽 통계 API (클라우드플레어 스타일)
async fn api_traffic(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("24h");

    // Realtime: 백그라운드 3초 갱신 캐시에서 즉시 반환 (ClickHouse 쿼리 0)
    if period == "realtime" {
        let cached = TRAFFIC_REALTIME_CACHE.read().clone();
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .header("x-cache", "BG")
            .body(axum::body::Body::from(cached))
            .unwrap();
    }

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
    // ClickHouse: sample_interval을 toStartOfInterval 표현식으로 변환
    let (time_filter, interval_expr) = match period {
        "realtime" => ("ts > now() - INTERVAL 10 MINUTE", "toStartOfInterval(ts, INTERVAL 10 SECOND)"),
        "1h" => ("ts > now() - INTERVAL 1 HOUR", "toStartOfMinute(ts, 'Asia/Seoul')"),
        "6h" => ("ts > now() - INTERVAL 6 HOUR", "toStartOfFiveMinutes(ts)"),
        "24h" => ("ts > now() - INTERVAL 1 DAY", "toStartOfTenMinutes(ts)"),
        "7d" => ("ts > now() - INTERVAL 7 DAY", "toStartOfHour(ts, 'Asia/Seoul')"),
        "30d" => ("ts > now() - INTERVAL 30 DAY", "toStartOfInterval(ts, INTERVAL 6 HOUR)"),
        _ => ("ts > now() - INTERVAL 1 DAY", "toStartOfTenMinutes(ts)"),
    };

    // 1. 시계열 데이터 (트래픽 추이) - GROUP BY로 시간 간격 집계
    let timeline_query = format!(
        "SELECT {} as ts, avg(viewers) as viewers, avg(unique_users) as unique_users, \
         sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, avg(peers) as peers, avg(swarms) as swarms \
         FROM p2p_stats WHERE {} GROUP BY ts ORDER BY ts",
        interval_expr, time_filter
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
         FROM p2p_stats WHERE ts > now() - INTERVAL 30 SECOND";

    // 5. CDN 서버별 통계 (p2p_servers에서 r_* 델타 합산 + visitor_logs에서 접속자)
    let server_traffic_query = format!(
        "SELECT server, sum(r_http_bytes) as http_bytes, sum(r_p2p_bytes) as p2p_bytes, \
         sum(r_p2p_up_bytes) as p2p_up_bytes, max(viewers) as peak_viewers \
         FROM p2p_servers WHERE {} GROUP BY server ORDER BY http_bytes DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    let visitor_query = format!(
        "SELECT left(swarm_id, position(swarm_id, '.') - 1) as server, \
         uniqExact(ip) as visitors, count() as requests \
         FROM visitor_logs WHERE {} GROUP BY server ORDER BY visitors DESC",
        time_filter.replace("ts >", "timestamp >")
    );

    // 6. 서버별 실시간 속도 (최근 30초간 r_* 합산)
    let server_speed_query = "SELECT server, sum(r_http_bytes) as r_http, sum(r_p2p_bytes) as r_p2p, sum(r_p2p_up_bytes) as r_p2p_up, \
         max(viewers) as viewers, max(unique_ips) as unique_ips \
         FROM p2p_servers WHERE timestamp > now() - INTERVAL 30 SECOND GROUP BY server";

    // 7. 플레이어별 실시간 속도 (최근 30초간 r_* 합산)
    let player_speed_query = "SELECT player, sum(r_http_bytes) as r_http, sum(r_p2p_bytes) as r_p2p, sum(r_p2p_up_bytes) as r_p2p_up \
         FROM p2p_players WHERE timestamp > now() - INTERVAL 30 SECOND GROUP BY player";

    // 병렬 쿼리 실행 (ClickHouse + simple_ws) - FORMAT JSONCompact 추가
    let timeline_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&timeline_query));
    let total_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&total_query));
    let traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&traffic_query));
    let speed_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(speed_query));
    let server_traffic_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&server_traffic_query));
    let visitor_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(&visitor_query));
    let server_speed_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(server_speed_query));
    let player_speed_url = format!("{}/?query={} FORMAT JSONCompact", CLICKHOUSE_URL, urlencoding::encode(player_speed_query));
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
    let (total_http, total_p2p, total_p2p_up) = if let Some(dataset) = traffic_data.get("data").and_then(|d| d.as_array()) {
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
    if let Some(dataset) = timeline_data.get("data").and_then(|d| d.as_array()) {
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

    // 실시간 속도 계산 (Gbps) - simple_ws의 rHttpBytes 등 사용 (이미 bytes/sec)
    let empty_player = serde_json::json!({});
    let (http_gbps, p2p_gbps, p2p_up_gbps) = {
        let p1 = realtime_data.get("player1").unwrap_or(&empty_player);
        let r_http = p1.get("rHttpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p = p1.get("rP2pBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let r_p2p_up = p1.get("rP2pUpBytes").and_then(|v| v.as_i64()).unwrap_or(0);
        let http_gbs = (r_http as f64) * 8.0 / 1_000_000_000.0;
        let p2p_gbs = (r_p2p as f64) * 8.0 / 1_000_000_000.0;
        let p2p_up_gbs = (r_p2p_up as f64) * 8.0 / 1_000_000_000.0;
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
    if let Some(dataset) = total_data.get("data").and_then(|d| d.as_array()) {
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

    // CDN 서버별 트래픽 맵 구성 (p2p_servers에서 r_* 델타 합산)
    let mut server_traffic_map: std::collections::HashMap<String, (i64, i64, i64, i64)> = std::collections::HashMap::new();
    if let Some(dataset) = server_traffic_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let http_bytes = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_bytes = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                let p2p_up_bytes = arr.get(3).and_then(|v| v.as_i64()).unwrap_or(0);
                let peak_viewers = arr.get(4).and_then(|v| v.as_i64()).unwrap_or(0);
                server_traffic_map.insert(server, (http_bytes, p2p_bytes, p2p_up_bytes, peak_viewers));
            }
        }
    }

    // 3. 접속자 맵 구성
    let mut visitor_map: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();
    if let Some(dataset) = visitor_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let visitors = arr.get(1).and_then(|v| v.as_i64()).unwrap_or(0);
                let requests = arr.get(2).and_then(|v| v.as_i64()).unwrap_or(0);
                visitor_map.insert(server, (visitors, requests));
            }
        }
    }

    // 4. 서버별 속도 맵 구성 (r_* 합산 / 30 = Gbps) + viewers/unique_ips
    let mut server_speed_map: std::collections::HashMap<String, (f64, f64, f64, i64, i64)> = std::collections::HashMap::new();
    if let Some(dataset) = server_speed_data.get("data").and_then(|d| d.as_array()) {
        for row in dataset {
            if let Some(arr) = row.as_array() {
                let server = arr.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let r_http = arr.get(1).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p = arr.get(2).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let r_p2p_up = arr.get(3).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let viewers = arr.get(4).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let unique_ips = arr.get(5).and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))).unwrap_or(0);
                let http_gbs = (r_http as f64) * 8.0 / 30.0 / 1_000_000_000.0;
                let p2p_gbs = (r_p2p as f64) * 8.0 / 30.0 / 1_000_000_000.0;
                let p2p_up_gbs = (r_p2p_up as f64) * 8.0 / 30.0 / 1_000_000_000.0;
                server_speed_map.insert(server, (http_gbs, p2p_gbs, p2p_up_gbs, viewers, unique_ips));
            }
        }
    }

    // 5. 서버 병합 (속도 기준 정렬, 스케일링 없이 raw 값 표시)
    let mut all_servers: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in server_speed_map.keys() { all_servers.insert(s.clone()); }
    for s in server_traffic_map.keys() { all_servers.insert(s.clone()); }

    let mut cdn_servers: Vec<(String, i64, i64, i64, i64, i64, i64, f64, f64, f64)> = all_servers.iter()
        .filter(|s| s.starts_with("every") && *s != "every999")
        .map(|s| {
            let (http, p2p, p2p_up, peak) = server_traffic_map.get(s).copied().unwrap_or((0, 0, 0, 0));
            let (http_gbs, p2p_gbs, p2p_up_gbs, viewers, unique_ips) = server_speed_map.get(s).copied().unwrap_or((0.0, 0.0, 0.0, 0, 0));
            (s.clone(), http, p2p, p2p_up, peak, viewers, unique_ips, http_gbs, p2p_gbs, p2p_up_gbs)
        })
        .collect();
    cdn_servers.sort_by(|a, b| b.7.partial_cmp(&a.7).unwrap_or(std::cmp::Ordering::Equal));

    let mut sum_http_gbps: f64 = 0.0;
    let mut sum_p2p_gbps: f64 = 0.0;
    let mut sum_p2p_up_gbps: f64 = 0.0;
    for &(ref server, http, p2p, p2p_up, _peak, viewers, unique_ips, http_gbs, p2p_gbs, p2p_up_gbs) in &cdn_servers {
        let clamped_p2p_up = p2p_up.min(p2p);
        let clamped_p2p_up_gbs = p2p_up_gbs.min(p2p_gbs);
        sum_http_gbps += http_gbs;
        sum_p2p_gbps += p2p_gbs;
        sum_p2p_up_gbps += clamped_p2p_up_gbs;

        servers.push(serde_json::json!({
            "server": server,
            "http": http,
            "p2p": p2p,
            "p2pUp": clamped_p2p_up,
            "httpGbps": format!("{:.2}", http_gbs),
            "p2pGbps": format!("{:.2}", p2p_gbs),
            "p2pUpGbps": format!("{:.2}", clamped_p2p_up_gbs),
            "visitors": viewers,
            "requests": unique_ips
        }));
    }

    totals["httpGbps"] = serde_json::json!(format!("{:.2}", sum_http_gbps));
    totals["p2pGbps"] = serde_json::json!(format!("{:.2}", sum_p2p_gbps));
    totals["p2pUpGbps"] = serde_json::json!(format!("{:.2}", sum_p2p_up_gbps));

    let result = serde_json::json!({
        "period": period,
        "timeline": timeline,
        "totals": totals,
        "servers": servers
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

    if period == "realtime" {
        let cached = SERVERS_REALTIME_CACHE.read().clone();
        if cached.len() > 2 {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .header("x-cache", "BG")
                .body(axum::body::Body::from(cached))
                .unwrap();
        }
    }

    // 기간에 따른 시간 필터와 샘플링
    let (time_filter, sample_by) = match period {
        "1h" => ("timestamp > now() - INTERVAL 1 HOUR", "SAMPLE BY 1m"),
        "6h" => ("timestamp > now() - INTERVAL 6 HOUR", "SAMPLE BY 5m"),
        "24h" => ("timestamp > now() - INTERVAL 1 DAY", "SAMPLE BY 15m"),
        "7d" => ("timestamp > now() - INTERVAL 7 DAY", "SAMPLE BY 1h"),
        "30d" => ("timestamp > now() - INTERVAL 30 DAY", "SAMPLE BY 4h"),
        _ => ("timestamp > now() - INTERVAL 10 MINUTE", ""), // realtime: 최근 10분, 샘플링 없음
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
         FROM p2p_servers WHERE {} AND server LIKE 'every%' ORDER BY timestamp, server LIMIT {} FORMAT JSONCompact",
        time_filter, limit
    );
    let url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&query));

    let data: serde_json::Value = match state.client.get(&url).send().await {
        Ok(r) => r.json().await.unwrap_or(serde_json::json!({})),
        Err(_) => serde_json::json!({}),
    };

    // 서버별 시계열 구성 (델타 계산)
    let mut server_timelines: std::collections::HashMap<String, Vec<serde_json::Value>> = std::collections::HashMap::new();
    let mut prev_values: std::collections::HashMap<String, (i64, i64)> = std::collections::HashMap::new();

    if let Some(dataset) = data.get("data").and_then(|d| d.as_array()) {
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
    let kst = FixedOffset::east_opt(KST_OFFSET_HOURS as i32 * 3600).unwrap();
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

    if period == "realtime" {
        let cached = IP_ANALYSIS_CACHE.read().clone();
        if cached.len() > 2 {
            return Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .header("access-control-allow-origin", "*")
                .header("x-cache", "BG")
                .body(axum::body::Body::from(cached))
                .unwrap();
        }
    }

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
    // toStartOfDay(now()) = 오늘 00:00:00 UTC
    let time_filter = match period {
        "1h" => "timestamp > now() - INTERVAL 1 HOUR".to_string(),
        "6h" => "timestamp > now() - INTERVAL 6 HOUR".to_string(),
        "24h" => "timestamp > now() - INTERVAL 1 DAY".to_string(),
        "today" => "timestamp >= toStartOfDay(now(), 'Asia/Seoul')".to_string(),
        "yesterday" => "timestamp >= toStartOfDay(now(), 'Asia/Seoul') - INTERVAL 1 DAY AND timestamp < toStartOfDay(now(), 'Asia/Seoul')".to_string(),
        "7d" => "timestamp > now() - INTERVAL 7 DAY".to_string(),
        "this_week" => "timestamp >= toStartOfWeek(now(), 'Asia/Seoul')".to_string(),
        "last_week" => "timestamp >= toStartOfWeek(now(), 'Asia/Seoul') - INTERVAL 1 WEEK AND timestamp < toStartOfWeek(now(), 'Asia/Seoul')".to_string(),
        "30d" => "timestamp > now() - INTERVAL 30 DAY".to_string(),
        "this_month" => "timestamp >= toStartOfMonth(now(), 'Asia/Seoul')".to_string(),
        "last_month" => "timestamp >= toStartOfMonth(now(), 'Asia/Seoul') - INTERVAL 1 MONTH AND timestamp < toStartOfMonth(now(), 'Asia/Seoul')".to_string(),
        _ => "timestamp > now() - INTERVAL 1 DAY".to_string(),
    };

    // IP별 요청수, 트래픽, 마지막 서버
    let ip_query = format!(
        "SELECT ip, count() as sessions, sum(http_bytes) as http, sum(p2p_bytes) as p2p, sum(p2p_up_bytes) as p2p_up, anyLast(swarm_id) as last_swarm \
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
    let ip_url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&ip_query));
    let total_url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&total_query));
    let unique_url = format!("{}/?query={}", CLICKHOUSE_URL, urlencoding::encode(&unique_query));

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
            let row = data.get("data").and_then(|d| d.as_array()).and_then(|a| a.first()).and_then(|r| r.as_array());
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
            data.get("data").and_then(|d| d.as_array()).and_then(|a| a.first())
                .and_then(|r| r.as_array()).and_then(|r| r.first()).and_then(|v| v.as_i64()).unwrap_or(0)
        }
        Err(_) => 0,
    };

    let mut ips: Vec<serde_json::Value> = Vec::new();
    if let Some(dataset) = ip_data.get("data").and_then(|d| d.as_array()) {
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
        "/api/bot/",  // 봇 탐지 리포트 (서버에서 호출)
        // 읽기 전용 API
        "/api/realtime", "/api/live", "/api/sessions", "/api/ip_stats", "/api/stats",
        "/api/history/stats", "/api/history/", "/api/popular", "/api/summary", "/api/visitors", "/api/traffic",
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

    // POST 요청 허용 경로
    let public_post_paths = ["/api/blacklist/times"];
    if method == axum::http::Method::POST && public_post_paths.iter().any(|p| path == *p) {
        return next.run(request).await;
    }

    // 정적 파일
    if path.starts_with("/static/") || path == "/favicon.ico" || path == "/favicon.svg" || path == "/" || path.ends_with(".html") || path.ends_with(".js") || path.ends_with(".css") {
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
        let id_map: HashMap<String, String> = servers.iter()
            .map(|(_, s)| (s.id.clone(), s.name.clone()))
            .collect();
        (b, p, id_map)
    };

    // 서버 ID 정규화 함수
    let normalize_servers = |servers: &[String]| -> Vec<String> {
        let mut names: std::collections::HashSet<String> = std::collections::HashSet::new();
        for s in servers {
            let name = server_id_to_name.get(s).cloned().unwrap_or_else(|| s.clone());
            names.insert(name);
        }
        let mut result: Vec<String> = names.into_iter().collect();
        result.sort_by(|a, b| {
            match (a.parse::<i32>(), b.parse::<i32>()) {
                (Ok(na), Ok(nb)) => na.cmp(&nb),
                _ => a.cmp(b)
            }
        });
        result
    };

    // first_seen/last_seen 쿼리 제거 - 성능 최적화 (필요시 별도 API로 조회)
    let mut items: Vec<serde_json::Value> = Vec::new();

    for (ip, cmd) in blocked_data {
        let normalized = normalize_servers(&cmd.servers_blocked);
        items.push(serde_json::json!({
            "ip": ip,
            "reason": cmd.reason,
            "blocked_at": cmd.created_at,
            "cf_blocked": cmd.cf_blocked,
            "blocked_servers": normalized,
            "status": "blocked"
        }));
    }

    for (ip, cmd) in pending_data {
        let normalized = normalize_servers(&cmd.servers_blocked);
        items.push(serde_json::json!({
            "ip": ip,
            "reason": cmd.reason,
            "blocked_at": cmd.created_at,
            "cf_blocked": cmd.cf_blocked,
            "blocked_servers": normalized,
            "status": "pending"
        }));
    }

    // 차단시간 기준 내림차순 정렬 (최신 먼저)
    items.sort_by(|a, b| {
        let a_time = a["blocked_at"].as_str().unwrap_or("");
        let b_time = b["blocked_at"].as_str().unwrap_or("");
        b_time.cmp(a_time)
    });

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

    // 이미 차단 또는 대기 중인지 확인 + 등록 (write lock으로 원자적 처리)
    {
        let blocked = BLOCKED_SERVERS.read();
        if blocked.contains_key(&ip) {
            return Json(serde_json::json!({"success": false, "error": "IP already blocked"}));
        }
        let mut pending = PENDING_BLOCKS.write();
        if pending.contains_key(&ip) {
            return Json(serde_json::json!({"success": false, "error": "IP already pending"}));
        }
        pending.insert(ip.clone(), BlockCommand {
            ip: ip.clone(),
            reason: reason.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            cf_blocked: false,
            servers_blocked: Vec::new(),
        });
    }

    // Cloudflare 차단 시도
    let cf_result = block_ip_cloudflare(&ip, &reason).await;

    // 서버 개수 확인
    let server_count = EXTERNAL_SERVERS.read().len();

    // pending에서 blocked로 이동 (이미 다른 경로로 차단됐으면 스킵)
    let pending_cmd = PENDING_BLOCKS.write().remove(&ip);

    {
        let mut blocked = BLOCKED_SERVERS.write();
        if blocked.contains_key(&ip) {
            // 이미 다른 경로에서 차단됨 - CF 결과만 업데이트
            if cf_result {
                if let Some(cmd) = blocked.get_mut(&ip) {
                    cmd.cf_blocked = true;
                }
            }
        } else if let Some(mut cmd) = pending_cmd {
            cmd.cf_blocked = cf_result;
            blocked.insert(ip.clone(), cmd);
        } else {
            blocked.insert(ip.clone(), BlockCommand {
                ip: ip.clone(),
                reason: reason.clone(),
                created_at: chrono::Utc::now().to_rfc3339(),
                cf_blocked: cf_result,
                servers_blocked: Vec::new(),
            });
        }
    }
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

    // 락을 일관된 순서로 획득 (PENDING -> BLOCKED)
    let _ = PENDING_BLOCKS.write().remove(&ip);
    let was_blocked = BLOCKED_SERVERS.write().remove(&ip).is_some();

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
    let client = &*HTTP_CLIENT;

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

// 대량 차단 해제 API
#[derive(Deserialize)]
struct BulkUnblockRequest {
    ips: Vec<String>,
}

async fn api_blacklist_bulk_unblock(Json(req): Json<BulkUnblockRequest>) -> Json<serde_json::Value> {
    let ips: Vec<String> = req.ips.iter().map(|ip| ip.trim().to_string()).filter(|ip| !ip.is_empty()).collect();

    if ips.is_empty() {
        return Json(serde_json::json!({"success": false, "error": "No IPs provided"}));
    }

    let mut unblocked = Vec::new();
    let mut not_found = Vec::new();
    let mut cf_results: HashMap<String, bool> = HashMap::new();

    // 1. PENDING_BLOCKS + BLOCKED_SERVERS에서 제거
    {
        let mut pending = PENDING_BLOCKS.write();
        let mut blocked = BLOCKED_SERVERS.write();
        for ip in &ips {
            let _ = pending.remove(ip);
            if blocked.remove(ip).is_some() {
                unblocked.push(ip.clone());
            } else {
                not_found.push(ip.clone());
            }
        }
    }

    if unblocked.is_empty() {
        return Json(serde_json::json!({
            "success": false,
            "error": "None of the IPs were in the blacklist",
            "not_found": not_found
        }));
    }

    // 2. Cloudflare 해제 (병렬)
    let cf_futures: Vec<_> = unblocked.iter().map(|ip| {
        let ip = ip.clone();
        async move {
            let result = unblock_ip_cloudflare(&ip).await;
            (ip, result)
        }
    }).collect();
    let cf_results_vec = futures_util::future::join_all(cf_futures).await;
    for (ip, result) in cf_results_vec {
        cf_results.insert(ip, result);
    }

    // 3. 모든 스트리밍 서버에 해제 명령 (병렬)
    let servers: Vec<(String, String)> = {
        let guard = EXTERNAL_SERVERS.read();
        guard.iter().map(|(_name, s)| (s.url.clone(), s.ip.clone())).collect()
    };
    let secret = AGENT_SECRET.read().clone();
    let client = &*HTTP_CLIENT;

    let server_futures: Vec<_> = servers.iter().flat_map(|(server_url, server_ip)| {
        let base_url = if !server_url.is_empty() {
            server_url.clone()
        } else if !server_ip.is_empty() {
            format!("http://{}:8081", server_ip)
        } else {
            return Vec::new();
        };
        let secret = secret.clone();
        unblocked.iter().map(move |ip| {
            let url = format!("{}/unblock", base_url.clone());
            let secret = secret.clone();
            let ip = ip.clone();
            let client = client.clone();
            async move {
                let _ = client.post(&url)
                    .header("X-Agent-Secret", secret)
                    .json(&serde_json::json!({"ip": ip}))
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await;
            }
        }).collect::<Vec<_>>()
    }).collect();
    futures_util::future::join_all(server_futures).await;

    // 4. 파일 저장
    save_blocked_list();

    // 5. 이벤트 기록
    add_server_event("system", &format!("대량 차단 해제: {}개 IP (CF: {}개 해제)", unblocked.len(), cf_results.values().filter(|v| **v).count()));

    Json(serde_json::json!({
        "success": true,
        "unblocked": unblocked,
        "not_found": not_found,
        "total_unblocked": unblocked.len(),
        "total_not_found": not_found.len(),
        "cf_results": cf_results
    }))
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

    let client = &*HTTP_CLIENT;
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

    let client = &*HTTP_CLIENT;

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

// ============ 자동 차단 설정 API ============

async fn api_autoblock_settings_get() -> impl IntoResponse {
    let settings = AUTO_BLOCK_SETTINGS.read();
    Json(serde_json::json!({
        "enabled": settings.enabled,
        "score": settings.score,
        "interval_secs": settings.interval_secs
    }))
}

#[derive(Deserialize)]
struct AutoBlockSettingsRequest {
    enabled: Option<bool>,
    score: Option<i64>,
    interval_secs: Option<u64>,
}

async fn api_autoblock_settings_set(Json(req): Json<AutoBlockSettingsRequest>) -> impl IntoResponse {
    let mut settings = AUTO_BLOCK_SETTINGS.write();

    if let Some(enabled) = req.enabled {
        settings.enabled = enabled;
    }
    if let Some(score) = req.score {
        if score >= 50 && score <= 200 {
            settings.score = score;
        }
    }
    if let Some(interval) = req.interval_secs {
        if interval >= 30 && interval <= 600 {
            settings.interval_secs = interval;
        }
    }

    save_auto_block_settings(&settings);

    println!("[AutoBlock] 설정 변경: enabled={}, score={}, interval={}s",
             settings.enabled, settings.score, settings.interval_secs);

    Json(serde_json::json!({
        "success": true,
        "enabled": settings.enabled,
        "score": settings.score,
        "interval_secs": settings.interval_secs
    }))
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

async fn api_logs_abusers(Query(params): Query<HashMap<String, String>>) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");
    let limit: usize = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(30);

    let cached = ABUSER_BG_CACHE.read().get(period).cloned();
    if let Some(json) = cached {
        if limit < 500 && json.len() > 2 {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&json) {
                if let Some(arr) = val.get_mut("abusers").and_then(|a| a.as_array_mut()) {
                    arr.truncate(limit);
                }
                return Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/json")
                    .header("access-control-allow-origin", "*")
                    .body(axum::body::Body::from(serde_json::to_string(&val).unwrap_or_default()))
                    .unwrap();
            }
        }
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("access-control-allow-origin", "*")
            .body(axum::body::Body::from(json))
            .unwrap();
    }

    let json = build_abuser_data(&*HTTP_CLIENT, period).await;
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(json))
        .unwrap()
}

async fn build_abuser_data(client: &Client, period: &str) -> String {
    let limit = 500i32;

    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "3h" => "now() - INTERVAL 3 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "12h" => "now() - INTERVAL 12 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 6 HOUR",
    };

    let period_seconds = match period {
        "1h" => 3600.0,
        "3h" => 10800.0,
        "6h" => 21600.0,
        "12h" => 43200.0,
        "24h" => 86400.0,
        _ => 21600.0,
    };

    // 긴 기간은 쿼리 시간이 더 걸림 → 타임아웃 조정
    let query_timeout = match period {
        "1h" => std::time::Duration::from_secs(10),
        "3h" => std::time::Duration::from_secs(15),
        "6h" => std::time::Duration::from_secs(20),
        "12h" => std::time::Duration::from_secs(30),
        "24h" => std::time::Duration::from_secs(30),
        _ => std::time::Duration::from_secs(15),
    };

    let burst_time = match period {
        "12h" | "24h" => "now() - INTERVAL 3 HOUR",
        _ => time_filter,
    };

    let main_query = format!(r#"
        SELECT
            client_ip,
            count() as requests,
            sum(bytes_sent) as total_bytes,
            min(timestamp) as first_seen,
            max(timestamp) as last_seen,
            uniq(path) as unique_paths,
            countIf(path LIKE '%.gif?%') as cache_bypass_cnt,
            groupUniqArray(server_id) as servers,
            anyIf(user_agent, user_agent != '') as ua,
            uniqExact(user_agent) as unique_agents
        FROM nginx_logs
        PREWHERE timestamp > {time}
        WHERE status = 200 AND bytes_sent > 1048576
        GROUP BY client_ip
        HAVING total_bytes > 104857600
        ORDER BY total_bytes DESC
        LIMIT {lim}
        SETTINGS max_threads = 8
        FORMAT JSONCompact
    "#, time = time_filter, lim = (limit * 10).max(500));

    let burst_query = format!(r#"
        SELECT client_ip, max(cnt) as max_req
        FROM (
            SELECT client_ip, count() as cnt
            FROM nginx_logs
            PREWHERE timestamp > {time}
            WHERE status = 200 AND bytes_sent > 102400
            GROUP BY client_ip, toStartOfInterval(timestamp, INTERVAL 100 SECOND)
            HAVING cnt > 10
        )
        GROUP BY client_ip
        HAVING max_req > 10
        ORDER BY max_req DESC
        LIMIT 500
        SETTINGS max_threads = 8
        FORMAT JSONCompact
    "#, time = burst_time);

    let single_path_query = format!(r#"
        SELECT
            client_ip,
            argMax(path, cnt) as top_path,
            max(cnt) as max_cnt,
            argMax(bytes, cnt) as max_bytes
        FROM (
            SELECT client_ip, path, count() as cnt, sum(bytes_sent) as bytes
            FROM nginx_logs
            PREWHERE timestamp > now() - INTERVAL 30 MINUTE
            WHERE status = 200 AND bytes_sent > 1048576
            GROUP BY client_ip, path
            HAVING cnt > 20
        )
        GROUP BY client_ip
        ORDER BY max_cnt DESC
        LIMIT 50
        SETTINGS max_threads = 8
        FORMAT JSONCompact
    "#);

    let (main_res, burst_res, single_path_res) = tokio::join!(
        client.get("http://localhost:8123")
            .query(&[("query", &main_query)])
            .timeout(query_timeout)
            .send(),
        client.get("http://localhost:8123")
            .query(&[("query", &burst_query)])
            .timeout(query_timeout)
            .send(),
        client.get("http://localhost:8123")
            .query(&[("query", &single_path_query)])
            .timeout(std::time::Duration::from_secs(10))
            .send()
    );

    // ========== 데이터 파싱 ==========

    let mut ip_max100s: HashMap<String, i64> = HashMap::new();
    match burst_res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data["data"].as_array() {
                    for row in dataset {
                        let ip = row[0].as_str().unwrap_or("").to_string();
                        let max_req = row[1].as_i64().unwrap_or(0);
                        ip_max100s.insert(ip, max_req);
                    }
                }
            }
        }
        Err(e) => eprintln!("[AbuserBG] burst query failed ({}): {}", period, e),
    }

    let mut ip_max_single_path: HashMap<String, (i64, i64)> = HashMap::new();
    match single_path_res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(dataset) = data["data"].as_array() {
                    for row in dataset {
                        let ip = row[0].as_str().unwrap_or("").to_string();
                        let cnt = row[2].as_i64().unwrap_or(0);
                        let bytes = row[3].as_i64().unwrap_or(0);
                        ip_max_single_path.insert(ip, (cnt, bytes));
                    }
                }
            }
        }
        Err(e) => eprintln!("[AbuserBG] single_path query failed ({}): {}", period, e),
    }

    let server_name_map: HashMap<String, String> = {
        let servers = EXTERNAL_SERVERS.read();
        servers.iter().map(|(_, s)| (s.id.clone(), s.name.clone())).collect()
    };
    let total_servers = server_name_map.len();

    let mut abusers = Vec::new();

    match main_res {
        Err(e) => eprintln!("[AbuserBG] main query failed ({}): {}", period, e),
        Ok(resp) => { if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(dataset) = data["data"].as_array() {
                for row in dataset {
                    let ip = row[0].as_str().unwrap_or("");
                    let requests = row[1].as_i64().unwrap_or(0);
                    let total_bytes = row[2].as_i64().unwrap_or(0);
                    let first_seen = row[3].as_str().unwrap_or("");
                    let last_seen = row[4].as_str().unwrap_or("");
                    let unique_paths = row[5].as_i64().unwrap_or(1);
                    let cache_bypass_cnt = row[6].as_i64().unwrap_or(0);

                    let servers: Vec<String> = row[7].as_array()
                        .map(|arr| arr.iter()
                            .filter_map(|s| s.as_str())
                            .filter(|s| !s.is_empty())
                            .map(|sid| server_name_map.get(sid).cloned().unwrap_or_else(|| sid.chars().take(6).collect()))
                            .collect())
                        .unwrap_or_default();
                    let ua = row[8].as_str().unwrap_or("");
                    let unique_agents = row[9].as_i64().unwrap_or(1).max(1);

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
                    // cache_bypass_cnt는 메인 쿼리에서 이미 가져옴
                    if cache_bypass_cnt > 5 {
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

                    // 또는: 극심한 버스트 + 극고속
                    let is_confirmed_abuser3 = flags.contains(&"EXTREME_BURST")
                        && flags.contains(&"EXTREME_SPEED");

                    if is_confirmed_abuser || is_confirmed_abuser2 || is_confirmed_abuser3 {
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

                    let ua_lower = ua.to_lowercase();
                    let is_mobile = ua_lower.contains("mobile") || ua_lower.contains("android") || ua_lower.contains("iphone") || ua_lower.contains("ipad");
                    let device_name = if ua_lower.contains("iphone") { "iPhone" }
                        else if ua_lower.contains("ipad") { "iPad" }
                        else if ua_lower.contains("android") {
                            if ua_lower.contains("mobile") { "Android" } else { "Android Tablet" }
                        }
                        else if ua_lower.contains("windows") { "Windows PC" }
                        else if ua_lower.contains("macintosh") { "Mac" }
                        else if ua_lower.contains("linux") { "Linux" }
                        else { "Unknown" };
                    let isp_name = lookup_isp(ip).unwrap_or_default();

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
                        "alreadyBlocked": already_blocked,
                        "is_mobile": is_mobile,
                        "device_name": device_name,
                        "isp_name": isp_name
                    }));
                }
            }
        } }
    }

    abusers.sort_by(|a, b| {
        let sa = a["score"].as_i64().unwrap_or(0);
        let sb = b["score"].as_i64().unwrap_or(0);
        sb.cmp(&sa)
    });
    abusers.truncate(limit as usize);

    serde_json::json!({"abusers": abusers}).to_string()
}

async fn build_logs_stats_data(client: &Client, period: &str) {
    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 6 HOUR",
    };

    let time_filter_5m = match period {
        "5m" => "now() - INTERVAL 5 MINUTE",
        "15m" => "now() - INTERVAL 15 MINUTE",
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 1 HOUR",
    };

    let (interval_expr, timeline_time) = match period {
        "1h" => ("toStartOfMinute(timestamp, 'Asia/Seoul')", "now() - INTERVAL 1 HOUR"),
        "6h" => ("toStartOfFiveMinutes(timestamp, 'Asia/Seoul')", "now() - INTERVAL 6 HOUR"),
        "24h" => ("toStartOfInterval(timestamp, INTERVAL 30 MINUTE, 'Asia/Seoul')", "now() - INTERVAL 1 DAY"),
        _ => ("toStartOfFiveMinutes(timestamp, 'Asia/Seoul')", "now() - INTERVAL 6 HOUR"),
    };

    let timeout = std::time::Duration::from_secs(15);

    let summary_q = format!(
        "SELECT count() as total, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 300 AND status < 400 THEN 1 ELSE 0 END) as s3xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as total_bytes \
         FROM nginx_logs WHERE timestamp > {} FORMAT JSONCompact", time_filter_5m);

    let ips_q = format!(
        "SELECT client_ip, count() as requests, sum(bytes_sent) as total_bytes \
         FROM nginx_logs WHERE timestamp > {} GROUP BY client_ip \
         ORDER BY total_bytes DESC LIMIT 20 FORMAT JSONCompact", time_filter);

    let timeline_q = format!(
        "SELECT {} as timestamp, count() as requests, sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact",
        interval_expr, timeline_time);

    let daily_q = format!(
        "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as timestamp, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > now() - INTERVAL 7 DAY \
         GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact");

    let daily_servers_q = format!(
        "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as timestamp, server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > now() - INTERVAL 7 DAY \
         GROUP BY timestamp, server_id ORDER BY timestamp FORMAT JSONCompact");

    let servers_q = format!(
        "SELECT server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         GROUP BY server_id ORDER BY bytes DESC FORMAT JSONCompact", time_filter);

    let (r_summary, r_ips, r_timeline, r_daily, r_daily_servers, r_servers) = tokio::join!(
        client.post("http://localhost:8123").body(summary_q).timeout(timeout).send(),
        client.post("http://localhost:8123").body(ips_q).timeout(timeout).send(),
        client.post("http://localhost:8123").body(timeline_q).timeout(timeout).send(),
        client.post("http://localhost:8123").body(daily_q).timeout(timeout).send(),
        client.post("http://localhost:8123").body(daily_servers_q).timeout(timeout).send(),
        client.post("http://localhost:8123").body(servers_q).timeout(timeout).send()
    );

    let parse_summary = |resp: Result<reqwest::Response, reqwest::Error>| async move {
        if let Ok(r) = resp {
            if let Ok(body) = r.text().await {
                let body = rename_data_to_dataset(&body);
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(row) = data["dataset"].as_array().and_then(|a| a.first()) {
                        return serde_json::json!({
                            "total": row[0].as_i64().unwrap_or(0),
                            "s2xx": row[1].as_i64().unwrap_or(0),
                            "s3xx": row[2].as_i64().unwrap_or(0),
                            "s4xx": row[3].as_i64().unwrap_or(0),
                            "s5xx": row[4].as_i64().unwrap_or(0),
                            "total_bytes": row[5].as_i64().unwrap_or(0)
                        }).to_string();
                    }
                }
            }
        }
        String::new()
    };

    let parse_dataset = |resp: Result<reqwest::Response, reqwest::Error>| async move {
        if let Ok(r) = resp {
            if let Ok(body) = r.text().await {
                let body = rename_data_to_dataset(&body);
                if serde_json::from_str::<serde_json::Value>(&body).is_ok() {
                    return body;
                }
            }
        }
        String::new()
    };

    let (s_summary, s_ips, s_timeline, s_daily, s_daily_servers, s_servers) = tokio::join!(
        parse_summary(r_summary),
        parse_dataset(r_ips),
        parse_dataset(r_timeline),
        parse_dataset(r_daily),
        parse_dataset(r_daily_servers),
        parse_dataset(r_servers)
    );

    let mut cache = LOGS_STATS_BG_CACHE.write();
    let entries = [
        (format!("summary:{}", period), s_summary),
        (format!("ips:{}", period), s_ips),
        (format!("timeline:{}", period), s_timeline),
        ("daily:7".to_string(), s_daily),
        ("daily_servers:7".to_string(), s_daily_servers),
        (format!("servers:{}", period), s_servers),
    ];
    for (key, val) in entries {
        if !val.is_empty() || !cache.contains_key(&key) {
            cache.insert(key, val);
        }
    }
}

// ============ 로그 리스트 API ============

// IP별 로그 조회
async fn api_logs_by_ip(
    axum::extract::Path(ip): axum::extract::Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let client = &*HTTP_CLIENT;
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(500i32);

    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "3h" => "now() - INTERVAL 3 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "12h" => "now() - INTERVAL 12 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 6 HOUR",
    };

    let escaped_ip = sanitize_ip_pattern(&ip);
    let query = format!(
        "SELECT timestamp, server_id, method, path, status, bytes_sent, response_time, user_agent \
         FROM nginx_logs \
         WHERE timestamp > {} AND client_ip = '{}' \
         ORDER BY timestamp DESC \
         LIMIT {} FORMAT JSONCompact",
        time_filter, escaped_ip, limit
    );

    let res = client.get("http://localhost:8123")
        .query(&[("query", &query)])
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                let logs: Vec<serde_json::Value> = data["data"].as_array()
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
    let client = &*HTTP_CLIENT;
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(500i32);
    let server_id = params.get("server_id").map(|s| s.as_str()).unwrap_or("");
    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");

    let time_filter = match period {
        "5m" => "now() - INTERVAL 5 MINUTE",
        "15m" => "now() - INTERVAL 15 MINUTE",
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 1 HOUR",
    };

    let mut conditions = vec![format!("timestamp > {}", time_filter)];

    if !server_id.is_empty() {
        conditions.push(format!("server_id = '{}'", escape_clickhouse_sql(server_id)));
    }
    if !search.is_empty() {
        let escaped = escape_clickhouse_sql(search);
        conditions.push(format!("(client_ip LIKE '%{}%' OR path LIKE '%{}%')", escaped, escaped));
    }

    let query = format!(
        "SELECT timestamp, client_ip, status, bytes_sent, path, user_agent, server_id \
         FROM nginx_logs WHERE {} \
         ORDER BY timestamp DESC LIMIT {} FORMAT JSONCompact",
        conditions.join(" AND "),
        limit
    );

    let res = client.post("http://localhost:8123")
        .body(query)
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let body = rename_data_to_dataset(&body);
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    Json(data)
                } else {
                    Json(serde_json::json!({"dataset": []}))
                }
            } else {
                Json(serde_json::json!({"dataset": []}))
            }
        }
        Err(e) => Json(serde_json::json!({"dataset": [], "error": e.to_string()}))
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

    // === 중복 배치 방지 (SHA256 hash of server_id + compressed data) ===
    {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(req.server_id.as_bytes());
        hasher.update(req.data.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        let now = Instant::now();
        let mut dedup = LOG_DEDUP_CACHE.write();

        // 5분 이상 된 항목 정리 (메모리 누수 방지)
        dedup.retain(|_, t| now.duration_since(*t).as_secs() < 300);

        if let Some(prev) = dedup.get(&hash) {
            if now.duration_since(*prev).as_secs() < 120 {
                // 2분 이내 동일 배치 → 중복으로 간주, 삽입 건너뜀
                return Json(serde_json::json!({"status": "ok", "inserted": 0, "dedup": true}));
            }
        }
        dedup.insert(hash, now);
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

    let client = &*HTTP_CLIENT;
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
                        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.6f").to_string())
                        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string())
                } else {
                    ts.clone()
                }
            }
            None => chrono::Utc::now().format("%Y-%m-%d %H:%M:%S%.6f").to_string(),
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

        let res = client.post(CLICKHOUSE_URL)
            .body(query)
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
async fn api_logs_stats_summary(Query(params): Query<HashMap<String, String>>) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let server_id = params.get("server_id").map(|s| s.as_str()).unwrap_or("");

    if server_id.is_empty() {
        let cache_key = format!("summary:{}", period);
        if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
            if !cached.is_empty() {
                return Response::builder()
                    .header("content-type", "application/json")
                    .header("x-cache", "BG")
                    .body(Body::from(cached)).unwrap();
            }
        }
    }

    let client = &*HTTP_CLIENT;
    let time_filter = match period {
        "5m" => "now() - INTERVAL 5 MINUTE",
        "15m" => "now() - INTERVAL 15 MINUTE",
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        _ => "now() - INTERVAL 1 HOUR",
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
         FROM nginx_logs WHERE timestamp > {}{} FORMAT JSONCompact",
        time_filter, server_filter
    );

    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let body = rename_data_to_dataset(&body);
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(row) = data["dataset"].as_array().and_then(|a| a.first()) {
                        serde_json::json!({
                            "total": row[0].as_i64().unwrap_or(0),
                            "s2xx": row[1].as_i64().unwrap_or(0),
                            "s3xx": row[2].as_i64().unwrap_or(0),
                            "s4xx": row[3].as_i64().unwrap_or(0),
                            "s5xx": row[4].as_i64().unwrap_or(0),
                            "total_bytes": row[5].as_i64().unwrap_or(0)
                        }).to_string()
                    } else {
                        r#"{"total":0,"s2xx":0,"s3xx":0,"s4xx":0,"s5xx":0,"total_bytes":0}"#.to_string()
                    }
                } else {
                    r#"{"total":0,"s2xx":0,"s3xx":0,"s4xx":0,"s5xx":0,"total_bytes":0}"#.to_string()
                }
            } else {
                r#"{"total":0,"s2xx":0,"s3xx":0,"s4xx":0,"s5xx":0,"total_bytes":0}"#.to_string()
            }
        }
        Err(e) => serde_json::json!({"status": "error", "message": e.to_string()}).to_string(),
    };

    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
}

// IP별 통계
async fn api_logs_stats_ips(Query(params): Query<HashMap<String, String>>) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");

    let cache_key = format!("ips:{}", period);
    if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
        if !cached.is_empty() {
            return Response::builder()
                .header("content-type", "application/json")
                .header("x-cache", "BG")
                .body(Body::from(cached)).unwrap();
        }
    }

    let client = &*HTTP_CLIENT;
    let limit = params.get("limit").and_then(|s| s.parse().ok()).unwrap_or(20);
    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        "7d" => "now() - INTERVAL 7 DAY",
        _ => "now() - INTERVAL 6 HOUR",
    };
    let query = format!(
        "SELECT client_ip, count() as requests, sum(bytes_sent) as total_bytes \
         FROM nginx_logs WHERE timestamp > {} GROUP BY client_ip \
         ORDER BY total_bytes DESC LIMIT {} FORMAT JSONCompact",
        time_filter, limit);
    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => resp.text().await.map(|b| rename_data_to_dataset(&b)).unwrap_or_else(|_| r#"{"dataset":[]}"#.to_string()),
        Err(_) => r#"{"dataset":[]}"#.to_string(),
    };
    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
}

// 타임라인 통계
async fn api_logs_stats_timeline(Query(params): Query<HashMap<String, String>>) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");

    let cache_key = format!("timeline:{}", period);
    if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
        if !cached.is_empty() {
            return Response::builder()
                .header("content-type", "application/json")
                .header("x-cache", "BG")
                .body(Body::from(cached)).unwrap();
        }
    }

    let client = &*HTTP_CLIENT;
    let (time_filter, interval_expr) = match period {
        "1h" => ("now() - INTERVAL 1 HOUR", "toStartOfMinute(timestamp, 'Asia/Seoul')"),
        "6h" => ("now() - INTERVAL 6 HOUR", "toStartOfFiveMinutes(timestamp, 'Asia/Seoul')"),
        "24h" => ("now() - INTERVAL 1 DAY", "toStartOfInterval(timestamp, INTERVAL 30 MINUTE, 'Asia/Seoul')"),
        "7d" => ("now() - INTERVAL 7 DAY", "toStartOfHour(timestamp, 'Asia/Seoul')"),
        _ => ("now() - INTERVAL 6 HOUR", "toStartOfFiveMinutes(timestamp, 'Asia/Seoul')"),
    };
    let query = format!(
        "SELECT {} as timestamp, count() as requests, sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact",
        interval_expr, time_filter);
    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => resp.text().await.map(|b| rename_data_to_dataset(&b)).unwrap_or_else(|_| r#"{"dataset":[]}"#.to_string()),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    };
    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
}

// 일별 통계
async fn api_logs_stats_daily(Query(params): Query<HashMap<String, String>>) -> Response {
    let limit = params.get("limit").and_then(|s| s.parse::<i32>().ok()).unwrap_or(7);

    let cache_key = format!("daily:{}", limit);
    if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
        if !cached.is_empty() {
            return Response::builder()
                .header("content-type", "application/json")
                .header("x-cache", "BG")
                .body(Body::from(cached)).unwrap();
        }
    }

    let client = &*HTTP_CLIENT;
    let query = format!(
        "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as timestamp, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > now() - INTERVAL {} DAY \
         GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact", limit);
    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => resp.text().await.map(|b| rename_data_to_dataset(&b)).unwrap_or_else(|_| r#"{"dataset":[]}"#.to_string()),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    };
    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
}

// 서버별 일별 통계
async fn api_logs_stats_daily_servers(Query(params): Query<HashMap<String, String>>) -> Response {
    let days = params.get("days").and_then(|s| s.parse::<i32>().ok()).unwrap_or(7);

    let cache_key = format!("daily_servers:{}", days);
    if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
        if !cached.is_empty() {
            return Response::builder()
                .header("content-type", "application/json")
                .header("x-cache", "BG")
                .body(Body::from(cached)).unwrap();
        }
    }

    let client = &*HTTP_CLIENT;
    let query = format!(
        "SELECT toStartOfDay(timestamp, 'Asia/Seoul') as timestamp, server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > now() - INTERVAL {} DAY \
         GROUP BY timestamp, server_id ORDER BY timestamp FORMAT JSONCompact", days);
    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => resp.text().await.map(|b| rename_data_to_dataset(&b)).unwrap_or_else(|_| r#"{"dataset":[]}"#.to_string()),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    };
    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
}

// 시간별 통계
async fn api_logs_stats_hourly(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let client = &*HTTP_CLIENT;
    let date = params.get("date").map(|s| s.as_str()).unwrap_or("");

    let query = if date.is_empty() {
        "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as timestamp, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs \
         WHERE timestamp > now() - INTERVAL 1 DAY \
         GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact".to_string()
    } else {
        format!(
            "SELECT toStartOfHour(timestamp, 'Asia/Seoul') as timestamp, count() as requests, \
             sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
             sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
             sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
             sum(bytes_sent) as bytes \
             FROM nginx_logs \
             WHERE timestamp >= toDate('{}') AND timestamp < toDate('{}') + INTERVAL 1 DAY \
             GROUP BY timestamp ORDER BY timestamp FORMAT JSONCompact",
            date, date
        )
    };

    let res = client.post(CLICKHOUSE_URL)
        .body(query)
        .send()
        .await;

    match res {
        Ok(resp) => {
            if let Ok(body) = resp.text().await {
                let body = rename_data_to_dataset(&body);
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&body) {
                    Json(data)
                } else {
                    Json(serde_json::json!({"error": "Failed to parse response"}))
                }
            } else {
                Json(serde_json::json!({"error": "Failed to read response"}))
            }
        }
        Err(e) => Json(serde_json::json!({"error": e.to_string()}))
    }
}

// 서버별 통계
async fn api_logs_stats_servers(Query(params): Query<HashMap<String, String>>) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("6h");

    let cache_key = format!("servers:{}", period);
    if let Some(cached) = LOGS_STATS_BG_CACHE.read().get(&cache_key).cloned() {
        if !cached.is_empty() {
            return Response::builder()
                .header("content-type", "application/json")
                .header("x-cache", "BG")
                .body(Body::from(cached)).unwrap();
        }
    }

    let client = &*HTTP_CLIENT;
    let time_filter = match period {
        "1h" => "now() - INTERVAL 1 HOUR",
        "6h" => "now() - INTERVAL 6 HOUR",
        "24h" => "now() - INTERVAL 1 DAY",
        "7d" => "now() - INTERVAL 7 DAY",
        _ => "now() - INTERVAL 6 HOUR",
    };
    let query = format!(
        "SELECT server_id, count() as requests, \
         sum(CASE WHEN status >= 200 AND status < 300 THEN 1 ELSE 0 END) as s2xx, \
         sum(CASE WHEN status >= 400 AND status < 500 THEN 1 ELSE 0 END) as s4xx, \
         sum(CASE WHEN status >= 500 THEN 1 ELSE 0 END) as s5xx, \
         sum(bytes_sent) as bytes \
         FROM nginx_logs WHERE timestamp > {} \
         GROUP BY server_id ORDER BY bytes DESC FORMAT JSONCompact", time_filter);
    let res = client.post(CLICKHOUSE_URL).body(query).send().await;
    let json_str = match res {
        Ok(resp) => resp.text().await.map(|b| rename_data_to_dataset(&b)).unwrap_or_else(|_| r#"{"dataset":[]}"#.to_string()),
        Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
    };
    Response::builder()
        .header("content-type", "application/json")
        .header("x-cache", "MISS")
        .body(Body::from(json_str)).unwrap()
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
    let blocked = BLOCKED_SERVERS.read();
    let blocked_count = blocked.len();

    // 서버별 차단 IP 수 미리 계산
    let mut per_server_blocked: HashMap<String, usize> = HashMap::new();
    for cmd in blocked.values() {
        for sid in &cmd.servers_blocked {
            *per_server_blocked.entry(sid.clone()).or_insert(0) += 1;
        }
    }
    drop(blocked);

    let events = SERVER_EVENTS.read();
    let latest_version = AGENT_LATEST_VERSION.read().clone();

    let now = chrono::Utc::now();
    let server_list: Vec<serde_json::Value> = servers.values()
        .map(|s| {
            let online = s.last_seen.map(|t| t > now - chrono::Duration::minutes(2)).unwrap_or(false);
            let last_seen_ts = s.last_seen.map(|t| t.timestamp_millis()).unwrap_or(0);
            let srv_blocked = per_server_blocked.get(&s.id).copied().unwrap_or(0);
            serde_json::json!({
                "id": s.id,
                "name": if s.name.is_empty() { &s.id } else { &s.name },
                "ip": s.ip,
                "url": s.url,
                "version": s.version,
                "last_seen": last_seen_ts,
                "blocked_ips": srv_blocked,
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

    // 버전 체크 - 최신 버전이 아니면 update:true 반환
    let latest = AGENT_LATEST_VERSION.read().clone();
    let needs_update = server_clone.version != latest;

    Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "pending_blocks": pending,
        "update": needs_update
    }))
}

// ============ 블랙리스트 대기/확인 API ============

async fn api_blacklist_pending(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let pending = PENDING_BLOCKS.read();
    let blocked = BLOCKED_SERVERS.read();
    let server_id = params.get("server_id").cloned().unwrap_or_default();

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

    // 이미 차단된 것 중 이 서버가 아직 confirm 안 한 것만 포함
    for (ip, cmd) in blocked.iter() {
        if !server_id.is_empty() && cmd.servers_blocked.contains(&server_id) {
            continue; // 이 서버는 이미 처리함 → 스킵
        }
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

    // 락을 분리해서 데드락 방지
    let pending_cmd = PENDING_BLOCKS.write().remove(&req.ip);

    let should_save = if let Some(mut cmd) = pending_cmd {
        cmd.servers_blocked.push(server_name.clone());
        // 이미 BLOCKED에 있으면 servers_blocked만 병합, 없으면 insert
        let mut blocked = BLOCKED_SERVERS.write();
        if let Some(existing) = blocked.get_mut(&req.ip) {
            if !existing.servers_blocked.contains(&server_name) {
                existing.servers_blocked.push(server_name.clone());
            }
        } else {
            blocked.insert(req.ip.clone(), cmd);
        }
        true
    } else {
        let mut blocked = BLOCKED_SERVERS.write();
        if let Some(cmd) = blocked.get_mut(&req.ip) {
            if !cmd.servers_blocked.contains(&server_name) {
                cmd.servers_blocked.push(server_name.clone());
                true
            } else {
                false
            }
        } else {
            return Json(serde_json::json!({"success": false, "error": "IP not found"}));
        }
    };

    if should_save {
        save_blocked_list();
    }
    Json(serde_json::json!({"success": true}))
}

// IP 시간 정보 배치 조회 API (first_seen, last_seen)
async fn api_blacklist_times(Json(ips): Json<Vec<String>>) -> impl IntoResponse {
    if ips.is_empty() {
        return Json(serde_json::json!({}));
    }

    let ips_filter = ips.iter()
        .take(100) // 최대 100개
        .map(|ip| format!("'{}'", ip.replace('\'', "")))
        .collect::<Vec<_>>()
        .join(",");

    let query = format!(r#"
        SELECT client_ip,
               formatDateTime(min(timestamp), '%Y-%m-%d %H:%i:%S', 'Asia/Seoul') as first_seen,
               formatDateTime(max(timestamp), '%Y-%m-%d %H:%i:%S', 'Asia/Seoul') as last_seen
        FROM nginx_logs
        PREWHERE timestamp > now() - INTERVAL 3 DAY AND client_ip IN ({ips})
        GROUP BY client_ip
        SETTINGS max_threads = 8
        FORMAT JSON
    "#, ips = ips_filter);

    let client = &*HTTP_CLIENT;
    let mut result: HashMap<String, serde_json::Value> = HashMap::new();

    if let Ok(resp) = client.get("http://localhost:8123")
        .query(&[("query", &query)])
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        if let Ok(data) = resp.json::<serde_json::Value>().await {
            if let Some(rows) = data["data"].as_array() {
                for row in rows {
                    let ip = row["client_ip"].as_str().unwrap_or("").to_string();
                    let first = row["first_seen"].as_str().unwrap_or("").to_string();
                    let last = row["last_seen"].as_str().unwrap_or("").to_string();
                    result.insert(ip, serde_json::json!({"first_seen": first, "last_seen": last}));
                }
            }
        }
    }

    Json(serde_json::json!(result))
}

// ============ 봇 탐지 리포트 API ============

#[derive(Deserialize)]
struct BotReportRequest {
    ip: String,
    reason: String,
    server: Option<String>,
    gif_count: Option<i64>,
    html_count: Option<i64>,
    user_agent: Option<String>,
}

fn save_bot_reports() {
    let reports = BOT_REPORTS.read();
    if let Ok(json) = serde_json::to_string_pretty(&*reports) {
        let _ = std::fs::write("data/bot_reports.json", json);
    }
}

async fn api_bot_report(Json(req): Json<BotReportRequest>) -> Json<serde_json::Value> {
    let ip = req.ip.trim().to_string();

    // IP 형식 검증
    if ip.parse::<std::net::IpAddr>().is_err() {
        return Json(serde_json::json!({"success": false, "error": "Invalid IP format"}));
    }

    let now = chrono::Utc::now().to_rfc3339();
    let server = req.server.unwrap_or_else(|| "unknown".to_string());
    let gif_count = req.gif_count.unwrap_or(0);
    let html_count = req.html_count.unwrap_or(0);
    let user_agent = req.user_agent.unwrap_or_default();

    let mut reports = BOT_REPORTS.write();

    if let Some(entry) = reports.get_mut(&ip) {
        entry.report_count += 1;
        entry.last_seen = now.clone();
        entry.gif_count = gif_count;
        if !user_agent.is_empty() {
            entry.user_agent = user_agent.clone();
        }
    } else {
        reports.insert(ip.clone(), BotReportEntry {
            ip: ip.clone(),
            reason: req.reason.clone(),
            server: server.clone(),
            gif_count,
            html_count,
            report_count: 1,
            first_seen: now.clone(),
            last_seen: now.clone(),
            user_agent,
        });
    }

    drop(reports);
    save_bot_reports();

    Json(serde_json::json!({
        "success": true,
        "ip": ip,
        "message": "Bot reported"
    }))
}

async fn api_bot_reports_list() -> Json<serde_json::Value> {
    let reports = BOT_REPORTS.read();
    let mut list: Vec<&BotReportEntry> = reports.values().collect();
    list.sort_by(|a, b| b.report_count.cmp(&a.report_count));

    Json(serde_json::json!({
        "success": true,
        "count": list.len(),
        "reports": list
    }))
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
