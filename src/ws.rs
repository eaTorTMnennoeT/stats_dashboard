use actix::{Actor, ActorContext, AsyncContext, StreamHandler};
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::db::{ClickHouseClient, EventRow};
use crate::stats::{RealtimeStats, WsMessage};

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(45);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(90);

/// WebSocket 핸들러
pub async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    stats: web::Data<RealtimeStats>,
    clickhouse: web::Data<ClickHouseClient>,
) -> Result<HttpResponse, Error> {
    let session_id = Uuid::new_v4().to_string();
    let ip = req
        .headers()
        .get("x-real-ip")
        .or_else(|| req.headers().get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown")
        .to_string();

    let ws_session = WsSession {
        session_id,
        ip,
        stats: stats.into_inner(),
        clickhouse: clickhouse.into_inner(),
        last_heartbeat: Instant::now(),
    };

    ws::start(ws_session, &req, stream)
}

pub struct WsSession {
    session_id: String,
    ip: String,
    stats: Arc<RealtimeStats>,
    clickhouse: Arc<ClickHouseClient>,
    last_heartbeat: Instant,
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.heartbeat(ctx);
        tracing::debug!("WS 연결: {}", self.session_id);
    }

    fn stopped(&mut self, _ctx: &mut Self::Context) {
        // 세션 정보를 먼저 가져온 후 종료
        if let Some(session) = self.stats.sessions.get(&self.session_id) {
            if session.initialized {
                let event = EventRow {
                    session_id: self.session_id.clone(),
                    swarm_id: session.swarm_id.clone(),
                    player_id: session.player_id,
                    filename: session.filename.clone(),
                    server: session.server.clone(),
                    referrer: session.referrer.clone(),
                    device: session.device.clone(),
                    device_name: session.device_name.clone(),
                    net_type: session.net_type.clone(),
                    browser: session.browser.clone(),
                    ip: session.ip.clone(),
                    http_bytes: session.http_bytes,
                    p2p_bytes: session.p2p_bytes,
                    p2p_up_bytes: session.p2p_up_bytes,
                    peers: session.peers,
                    timestamp: chrono::Utc::now().timestamp(),
                };

                // 비동기 이벤트 저장 (백그라운드)
                let ch = self.clickhouse.clone();
                actix::spawn(async move {
                    if let Err(e) = ch.insert_event(event).await {
                        tracing::warn!("ClickHouse 이벤트 저장 실패: {}", e);
                    }
                });
            }
        }

        self.stats.close_session(&self.session_id);
        tracing::debug!("WS 종료: {}", self.session_id);
    }
}

impl WsSession {
    fn heartbeat(&self, ctx: &mut ws::WebsocketContext<Self>) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.last_heartbeat) > CLIENT_TIMEOUT {
                tracing::debug!("WS 타임아웃: {}", act.session_id);
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }

    fn handle_message(&mut self, text: &str) {
        match serde_json::from_str::<WsMessage>(text) {
            Ok(WsMessage::Init(mut msg)) => {
                msg.ip = self.ip.clone();
                self.stats.init_session(&self.session_id, &msg);
            }
            Ok(WsMessage::Stats(msg)) => {
                self.stats.update_stats(&self.session_id, &msg);
            }
            Err(e) => {
                tracing::warn!("WS 메시지 파싱 실패: {}", e);
            }
        }
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.last_heartbeat = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.last_heartbeat = Instant::now();
            }
            Ok(ws::Message::Text(text)) => {
                self.last_heartbeat = Instant::now();
                self.handle_message(&text);
            }
            Ok(ws::Message::Binary(bin)) => {
                if let Ok(text) = String::from_utf8(bin.to_vec()) {
                    self.handle_message(&text);
                }
            }
            Ok(ws::Message::Close(reason)) => {
                tracing::debug!("WS 클라이언트 종료: {:?}", reason);
                ctx.stop();
            }
            _ => {}
        }
    }
}
