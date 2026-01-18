use axum::{
    extract::{Query, Request},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use reqwest::Client;
use std::collections::HashMap;
use std::time::Duration;
use tower_http::{cors::CorsLayer, services::ServeDir};

const SIMPLE_WS_URL: &str = "https://127.0.0.1:8443";
const QUESTDB_URL: &str = "http://127.0.0.1:9002";

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let app = Router::new()
        .route("/api/realtime", get(proxy_realtime))
        .route("/api/live", get(proxy_live))
        .route("/api/stats", get(proxy_stats))
        .route("/api/history/stats", get(history_stats))
        .route("/api/history/swarms", get(history_swarms))
        .nest_service("/", ServeDir::new("static"))
        .layer(CorsLayer::permissive())
        .with_state(client);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    eprintln!("P2P Stats Dashboard listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn proxy_realtime(
    axum::extract::State(client): axum::extract::State<Client>,
) -> Response {
    proxy_get(&client, "/api/realtime", "").await
}

async fn proxy_live(
    axum::extract::State(client): axum::extract::State<Client>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let query = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&"))
    };
    proxy_get(&client, "/api/live", &query).await
}

async fn proxy_stats(
    axum::extract::State(client): axum::extract::State<Client>,
) -> Response {
    proxy_get(&client, "/stats", "").await
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

// QuestDB history endpoints
// period in microseconds: 1h=3600000000, 1d=86400000000, 7d=604800000000
fn period_to_micros(period: &str) -> i64 {
    match period {
        "1h" => 3_600_000_000,
        "6h" => 21_600_000_000,
        "1d" | "24h" => 86_400_000_000,
        "7d" => 604_800_000_000,
        "30d" => 2_592_000_000_000,
        _ => 3_600_000_000,
    }
}

async fn history_stats(
    axum::extract::State(client): axum::extract::State<Client>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let period = params.get("period").map(|s| s.as_str()).unwrap_or("1h");
    let sample = params.get("sample").map(|s| s.as_str()).unwrap_or("1m");
    let micros = period_to_micros(period);

    let query = format!(
        "SELECT ts, last(viewers) as viewers, last(unique_users) as unique_users, \
         last(http_bytes) as http_bytes, last(p2p_bytes) as p2p_bytes, \
         last(p2p_up_bytes) as p2p_up_bytes, last(peers) as peers, last(swarms) as swarms \
         FROM p2p_stats \
         WHERE ts > systimestamp() - {}L \
         SAMPLE BY {}",
        micros, sample
    );

    questdb_query(&client, &query).await
}

async fn history_swarms(
    axum::extract::State(client): axum::extract::State<Client>,
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

    questdb_query(&client, &query).await
}

async fn questdb_query(client: &Client, query: &str) -> Response {
    let url = format!("{}/exec?query={}", QUESTDB_URL, urlencoding::encode(query));

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
