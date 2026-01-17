use actix_web::{web, HttpRequest, HttpResponse};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;

use crate::stats::RealtimeStats;

/// 어드민 API 키 (환경변수로 설정)
fn get_admin_key() -> String {
    std::env::var("ADMIN_KEY").unwrap_or_else(|_| "changeme".to_string())
}

/// 인증 확인
fn check_auth(req: &HttpRequest) -> bool {
    let admin_key = get_admin_key();

    // Authorization: Bearer <key> 또는 X-Admin-Key: <key>
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                return &auth_str[7..] == admin_key;
            }
        }
    }

    if let Some(key) = req.headers().get("X-Admin-Key") {
        if let Ok(key_str) = key.to_str() {
            return key_str == admin_key;
        }
    }

    false
}

/// 인증 실패 응답
fn unauthorized() -> HttpResponse {
    HttpResponse::Unauthorized().json(serde_json::json!({
        "error": "Unauthorized",
        "message": "Invalid or missing admin key"
    }))
}

/// /admin/status - 서버 상태
pub async fn status(req: HttpRequest, stats: web::Data<RealtimeStats>) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let total_viewers = stats.total_viewers.load(Ordering::Relaxed);
    let total_sessions = stats.sessions.len();
    let total_swarms = stats.swarms.len();
    let total_http = stats.total_http_bytes.load(Ordering::Relaxed);
    let total_p2p = stats.total_p2p_bytes.load(Ordering::Relaxed);

    HttpResponse::Ok().json(serde_json::json!({
        "status": "running",
        "viewers": total_viewers,
        "sessions": total_sessions,
        "swarms": total_swarms,
        "traffic": {
            "http_bytes": total_http,
            "p2p_bytes": total_p2p,
            "total_bytes": total_http + total_p2p
        },
        "memory": get_memory_usage(),
        "uptime": get_uptime()
    }))
}

/// /admin/sessions - 세션 목록
pub async fn sessions(
    req: HttpRequest,
    stats: web::Data<RealtimeStats>,
    query: web::Query<SessionsQuery>,
) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let limit = query.limit.unwrap_or(50).min(500) as usize;
    let offset = query.offset.unwrap_or(0) as usize;
    let search = query.search.as_deref();

    let mut sessions: Vec<SessionInfo> = stats.sessions.iter()
        .filter(|s| {
            if let Some(search) = search {
                s.key().contains(search)
                    || s.swarm_id.contains(search)
                    || s.filename.contains(search)
                    || s.ip.contains(search)
                    || s.referrer.contains(search)
            } else {
                true
            }
        })
        .map(|s| SessionInfo {
            session_id: s.key().clone(),
            swarm_id: s.swarm_id.clone(),
            player_id: s.player_id,
            filename: s.filename.clone(),
            server: s.server.clone(),
            referrer: s.referrer.clone(),
            device: s.device.clone(),
            browser: s.browser.clone(),
            ip: s.ip.clone(),
            http_bytes: s.http_bytes,
            p2p_bytes: s.p2p_bytes,
            p2p_up_bytes: s.p2p_up_bytes,
            peers: s.peers,
        })
        .collect();

    // http_bytes + p2p_bytes 내림차순 정렬
    sessions.sort_by(|a, b| {
        (b.http_bytes + b.p2p_bytes).cmp(&(a.http_bytes + a.p2p_bytes))
    });

    let total = sessions.len();
    let data: Vec<_> = sessions.into_iter().skip(offset).take(limit).collect();

    HttpResponse::Ok().json(serde_json::json!({
        "data": data,
        "total": total,
        "limit": limit,
        "offset": offset
    }))
}

/// /admin/sessions/{id} - 세션 상세
pub async fn session_detail(
    req: HttpRequest,
    stats: web::Data<RealtimeStats>,
    path: web::Path<String>,
) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let session_id = path.into_inner();

    if let Some(s) = stats.sessions.get(&session_id) {
        HttpResponse::Ok().json(SessionInfo {
            session_id: s.key().clone(),
            swarm_id: s.swarm_id.clone(),
            player_id: s.player_id,
            filename: s.filename.clone(),
            server: s.server.clone(),
            referrer: s.referrer.clone(),
            device: s.device.clone(),
            browser: s.browser.clone(),
            ip: s.ip.clone(),
            http_bytes: s.http_bytes,
            p2p_bytes: s.p2p_bytes,
            p2p_up_bytes: s.p2p_up_bytes,
            peers: s.peers,
        })
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        }))
    }
}

/// /admin/sessions/{id}/kick - 세션 강제 종료
pub async fn kick_session(
    req: HttpRequest,
    stats: web::Data<RealtimeStats>,
    path: web::Path<String>,
) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let session_id = path.into_inner();

    if stats.sessions.contains_key(&session_id) {
        stats.close_session(&session_id);
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Session {} kicked", session_id)
        }))
    } else {
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "Session not found"
        }))
    }
}

/// /admin/swarms - Swarm 목록
pub async fn swarms(
    req: HttpRequest,
    stats: web::Data<RealtimeStats>,
    query: web::Query<SessionsQuery>,
) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let limit = query.limit.unwrap_or(50).min(500) as usize;
    let offset = query.offset.unwrap_or(0) as usize;

    let mut swarms: Vec<_> = stats.swarms.iter()
        .map(|s| {
            let http = s.http_bytes.load(Ordering::Relaxed);
            let p2p = s.p2p_bytes.load(Ordering::Relaxed);
            serde_json::json!({
                "swarm_id": s.key().clone(),
                "filename": s.filename.read().clone(),
                "viewers": s.viewers.load(Ordering::Relaxed),
                "http_bytes": http,
                "p2p_bytes": p2p,
                "total_bytes": http + p2p
            })
        })
        .collect();

    swarms.sort_by(|a, b| {
        b["viewers"].as_i64().cmp(&a["viewers"].as_i64())
    });

    let total = swarms.len();
    let data: Vec<_> = swarms.into_iter().skip(offset).take(limit).collect();

    HttpResponse::Ok().json(serde_json::json!({
        "data": data,
        "total": total
    }))
}

/// /admin/referrers - 리퍼러 통계
pub async fn referrers(req: HttpRequest, stats: web::Data<RealtimeStats>) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let mut referrers: Vec<_> = stats.referrers.iter()
        .map(|r| serde_json::json!({
            "referrer": r.key().clone(),
            "count": r.value().load(Ordering::Relaxed)
        }))
        .collect();

    referrers.sort_by(|a, b| {
        b["count"].as_i64().cmp(&a["count"].as_i64())
    });

    HttpResponse::Ok().json(serde_json::json!({
        "data": referrers,
        "total": referrers.len()
    }))
}

/// /admin/servers - 서버별 통계
pub async fn servers(req: HttpRequest, stats: web::Data<RealtimeStats>) -> HttpResponse {
    if !check_auth(&req) {
        return unauthorized();
    }

    let mut servers: Vec<_> = stats.server_traffic.iter()
        .map(|s| {
            let http = s.http_bytes.load(Ordering::Relaxed);
            let p2p = s.p2p_bytes.load(Ordering::Relaxed);
            let total = http + p2p;
            let ratio = if total > 0 {
                (p2p as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            serde_json::json!({
                "server": s.key().clone(),
                "viewers": s.viewers.load(Ordering::Relaxed),
                "http_bytes": http,
                "p2p_bytes": p2p,
                "total_bytes": total,
                "p2p_ratio": format!("{:.1}", ratio)
            })
        })
        .collect();

    servers.sort_by(|a, b| {
        b["viewers"].as_i64().cmp(&a["viewers"].as_i64())
    });

    HttpResponse::Ok().json(serde_json::json!({
        "data": servers,
        "total": servers.len()
    }))
}

#[derive(Deserialize)]
pub struct SessionsQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub search: Option<String>,
}

#[derive(Serialize)]
struct SessionInfo {
    session_id: String,
    swarm_id: String,
    player_id: u8,
    filename: String,
    server: String,
    referrer: String,
    device: String,
    browser: String,
    ip: String,
    http_bytes: u64,
    p2p_bytes: u64,
    p2p_up_bytes: u64,
    peers: u32,
}

fn get_memory_usage() -> serde_json::Value {
    // /proc/self/status에서 메모리 정보 읽기
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let mut vm_rss = 0u64;
        let mut vm_size = 0u64;

        for line in status.lines() {
            if line.starts_with("VmRSS:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    vm_rss = val.parse().unwrap_or(0);
                }
            } else if line.starts_with("VmSize:") {
                if let Some(val) = line.split_whitespace().nth(1) {
                    vm_size = val.parse().unwrap_or(0);
                }
            }
        }

        return serde_json::json!({
            "rss_kb": vm_rss,
            "rss_mb": vm_rss / 1024,
            "virtual_kb": vm_size,
            "virtual_mb": vm_size / 1024
        });
    }

    serde_json::json!({})
}

fn get_uptime() -> serde_json::Value {
    // /proc/self/stat에서 시작 시간 읽기
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        if let Some(secs) = uptime.split_whitespace().next() {
            if let Ok(uptime_secs) = secs.parse::<f64>() {
                let hours = (uptime_secs / 3600.0) as u64;
                let mins = ((uptime_secs % 3600.0) / 60.0) as u64;
                return serde_json::json!({
                    "seconds": uptime_secs as u64,
                    "formatted": format!("{}h {}m", hours, mins)
                });
            }
        }
    }

    serde_json::json!({})
}
