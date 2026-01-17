mod admin;
mod api;
mod db;
mod stats;
mod ws;

use actix_cors::Cors;
use actix_files::Files;
use actix_web::{web, App, HttpServer};
use rustls::pki_types::CertificateDer;
use rustls::ServerConfig;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::db::{ClickHouseClient, DragonflyClient};
use crate::stats::RealtimeStats;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 로깅 초기화 (warn 이상만)
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::warn!("🚀 P2P Stats Server (Rust + Actix) 시작...");

    // TLS 설정
    let tls_config = load_tls_config();

    // 공유 상태
    let stats = Arc::new(RealtimeStats::new());
    let stats_data = web::Data::from(stats.clone());

    let clickhouse = web::Data::new(ClickHouseClient::new().await);
    let dragonfly = web::Data::new(DragonflyClient::new().await);

    if dragonfly.is_connected() {
        tracing::warn!("🔗 Dragonfly (Redis) 연결됨");
    } else {
        tracing::warn!("⚠️ Dragonfly 연결 실패 - 캐싱 비활성화");
    }

    // 워커 수 계산 (CPU 수의 절반, 최소 4, 최대 32)
    let workers = (num_cpus::get() / 2).clamp(4, 32);
    tracing::warn!("🔧 워커 수: {}", workers);
    tracing::warn!("🌐 HTTPS 서버: https://0.0.0.0:8443");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(86400); // CORS preflight 캐시 24시간

        App::new()
            .wrap(cors)
            .app_data(stats_data.clone())
            .app_data(clickhouse.clone())
            .app_data(dragonfly.clone())
            // JSON 페이로드 제한
            .app_data(web::JsonConfig::default().limit(4096))
            .app_data(web::PayloadConfig::default().limit(4096))
            // WebSocket 연결 (활성화!)
            .route("/ws", web::get().to(ws::ws_handler))
            // API
            .service(
                web::scope("/api")
                    .route("/realtime", web::get().to(api::realtime))
                    .route("/live", web::get().to(api::live))
                    .route("/top", web::get().to(api::top))
                    .route("/hourly", web::get().to(api::hourly))
                    .route("/traffic/daily", web::get().to(api::daily))
                    .route("/traffic/monthly", web::get().to(api::monthly)),
            )
            // Admin API
            .service(
                web::scope("/admin")
                    .route("/status", web::get().to(admin::status))
                    .route("/sessions", web::get().to(admin::sessions))
                    .route("/sessions/{id}", web::get().to(admin::session_detail))
                    .route("/sessions/{id}/kick", web::post().to(admin::kick_session))
                    .route("/swarms", web::get().to(admin::swarms))
                    .route("/referrers", web::get().to(admin::referrers))
                    .route("/servers", web::get().to(admin::servers)),
            )
            // 정적 파일
            .service(Files::new("/static", "/opt/stats-server/public"))
            // index.html fallback
            .route("/", web::get().to(|| async {
                actix_web::HttpResponse::Ok()
                    .content_type("text/html")
                    .body(std::fs::read_to_string("/opt/stats-server/public/index.html").unwrap_or_default())
            }))
    })
    .bind_rustls_0_23("0.0.0.0:8443", tls_config)?
    .workers(workers)
    .backlog(8192)                    // 연결 대기열 증가
    .max_connections(100_000)         // 최대 동시 연결
    .max_connection_rate(50_000)      // 초당 새 연결 제한
    .keep_alive(std::time::Duration::from_secs(75)) // Keep-alive
    .client_request_timeout(std::time::Duration::from_secs(10))
    .client_disconnect_timeout(std::time::Duration::from_secs(5))
    .run()
    .await
}

fn load_tls_config() -> ServerConfig {
    let cert_path = "/opt/aquatic/cert/2.pem";
    let key_path = "/opt/aquatic/cert/1.pem";

    let cert_file = &mut BufReader::new(File::open(cert_path).expect("cert 파일 없음"));
    let key_file = &mut BufReader::new(File::open(key_path).expect("key 파일 없음"));

    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(cert_file)
        .filter_map(|r| r.ok())
        .collect();

    let key = rustls_pemfile::private_key(key_file)
        .expect("키 파일 읽기 실패")
        .expect("키를 찾을 수 없음");

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("TLS 설정 실패")
}
