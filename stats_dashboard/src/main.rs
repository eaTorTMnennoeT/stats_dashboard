use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Query, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use futures_util::{SinkExt, StreamExt};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tower_http::{cors::CorsLayer, services::ServeDir};

const SIMPLE_WS_URL: &str = "https://127.0.0.1:8443";
const QUESTDB_URL: &str = "http://127.0.0.1:9002";

#[derive(Clone)]
struct AppState {
    client: Client,
    tx: broadcast::Sender<String>,
}

#[tokio::main]
async fn main() {
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let (tx, _) = broadcast::channel::<String>(100);
    let state = AppState {
        client: client.clone(),
        tx: tx.clone(),
    };

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
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/api/realtime", get(proxy_realtime))
        .route("/api/live", get(proxy_live))
        .route("/api/stats", get(proxy_stats))
        .route("/api/history/stats", get(history_stats))
        .route("/api/history/swarms", get(history_swarms))
        .route("/api/history/hourly", get(history_hourly))
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

async fn proxy_realtime(State(state): State<AppState>) -> Response {
    proxy_get(&state.client, "/api/realtime", "").await
}

async fn proxy_live(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let query = if params.is_empty() {
        String::new()
    } else {
        format!(
            "?{}",
            params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&")
        )
    };
    proxy_get(&state.client, "/api/live", &query).await
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
    State(state): State<AppState>,
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

    questdb_query(&state.client, &query).await
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
