use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{Datelike, FixedOffset, Timelike, Utc};
use futures_util::{SinkExt, StreamExt};
use redis::AsyncCommands;
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::{cors::CorsLayer, services::ServeDir};

const SIMPLE_WS_URL: &str = "https://127.0.0.1:8443";
const QUESTDB_URL: &str = "http://127.0.0.1:9002";
const DRAGONFLY_URL: &str = "redis://127.0.0.1:6379";

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

    // hourly_stats 테이블 생성 (디비화)
    ensure_hourly_stats_table(&client).await;
    eprintln!("hourly_stats table ensured");

    // Background task: 과거 데이터 디비화 (최초 실행 시 과거 365일 데이터 저장)
    let init_client = client.clone();
    tokio::spawn(async move {
        eprintln!("Starting historical data aggregation...");
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        // 과거 365일까지 데이터가 없는 날만 저장
        for i in 1..=365i64 {
            let date = (chrono::Utc::now() - chrono::Duration::days(i)).format("%Y-%m-%d").to_string();
            if !has_hourly_stats_for_date(&init_client, &date).await {
                eprintln!("Aggregating data for {}...", date);
                if store_hourly_stats(&init_client, &date).await {
                    eprintln!("  -> {} stored successfully", date);
                } else {
                    eprintln!("  -> {} no data or failed", date);
                }
                // 부하 방지를 위해 짧은 딜레이
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        eprintln!("Historical data aggregation complete");
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

    let app = Router::new()
        .route("/ws", get(ws_handler))
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
        .route("/api/visitors", get(api_visitors))
        .route("/api/traffic", get(api_traffic))
        .route("/api/servers/realtime", get(api_servers_realtime))
        .route("/api/server-time", get(api_server_time))
        .route("/api/ip-analysis", get(api_ip_analysis))
        .nest_service("/", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    eprintln!("P2P Stats Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
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

// 종합통계 (오늘/어제 비교)
async fn api_summary(State(state): State<AppState>) -> Response {
    // timestamp_floor('d', now()) = 오늘 자정 UTC
    let today_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= timestamp_floor('d', now())";

    let yesterday_query = "SELECT max(viewers) as max_viewers, max(unique_users) as max_users, \
        last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, last(swarms) as swarms \
        FROM p2p_stats WHERE ts >= dateadd('d', -1, timestamp_floor('d', now())) AND ts < timestamp_floor('d', now())";

    let today_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(today_query));
    let yesterday_url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(yesterday_query));

    let (today_res, yesterday_res) = tokio::join!(
        state.client.get(&today_url).send(),
        state.client.get(&yesterday_url).send()
    );

    let today_data = match today_res {
        Ok(r) => r.text().await.unwrap_or_else(|_| "{}".to_string()),
        Err(_) => "{}".to_string(),
    };
    let yesterday_data = match yesterday_res {
        Ok(r) => r.text().await.unwrap_or_else(|_| "{}".to_string()),
        Err(_) => "{}".to_string(),
    };

    let body = format!(r#"{{"today":{},"yesterday":{}}}"#, today_data, yesterday_data);

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(axum::body::Body::from(body))
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
