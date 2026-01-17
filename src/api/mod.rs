use actix_web::{web, HttpResponse};
use serde::Deserialize;

use crate::db::{ClickHouseClient, DragonflyClient};
use crate::stats::RealtimeStats;

/// /api/realtime - 실시간 통계 (캐싱 안 함 - 실시간 데이터)
pub async fn realtime(stats: web::Data<RealtimeStats>) -> HttpResponse {
    HttpResponse::Ok().json(stats.to_json())
}

/// /api/live - 실시간 시청 목록 (캐싱 안 함 - 실시간 데이터)
pub async fn live(
    stats: web::Data<RealtimeStats>,
    query: web::Query<PaginationQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(20).min(100) as usize;
    let offset = query.offset.unwrap_or(0) as usize;

    let mut swarms: Vec<_> = stats.swarms.iter()
        .map(|s| {
            let http = s.http_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let p2p = s.p2p_bytes.load(std::sync::atomic::Ordering::Relaxed);
            let total = http + p2p;
            let ratio = if total > 0 {
                format!("{:.1}", (p2p as f64 / total as f64) * 100.0)
            } else {
                "0.0".to_string()
            };

            serde_json::json!({
                "swarm_id": s.key().clone(),
                "filename": s.filename.read().clone(),
                "viewers": s.viewers.load(std::sync::atomic::Ordering::Relaxed),
                "http_bytes": http,
                "p2p_bytes": p2p,
                "p2pRatio": ratio
            })
        })
        .collect();

    // 시청자 수로 정렬
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

/// /api/top - 인기 콘텐츠 (30초 캐시)
pub async fn top(
    ch: web::Data<ClickHouseClient>,
    cache: web::Data<DragonflyClient>,
    query: web::Query<TopQuery>,
) -> HttpResponse {
    let limit = query.limit.unwrap_or(20).min(100);
    let offset = query.offset.unwrap_or(0);
    let period = query.period.as_deref().unwrap_or("all");

    let cache_key = format!("api:top:{}:{}:{}", period, limit, offset);

    // 캐시 확인
    if let Some(cached) = cache.get_cache(&cache_key).await {
        return HttpResponse::Ok()
            .content_type("application/json")
            .body(cached);
    }

    // DB 조회
    match ch.get_top(limit, offset, period).await {
        Ok((data, total)) => {
            let response = serde_json::json!({
                "data": data,
                "total": total
            });
            let json_str = response.to_string();

            // 캐시 저장 (30초)
            cache.set_cache(&cache_key, &json_str, 30).await;

            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({
                "error": e.to_string()
            }))
        }
    }
}

/// /api/hourly - 시간별 통계 (60초 캐시)
pub async fn hourly(
    ch: web::Data<ClickHouseClient>,
    cache: web::Data<DragonflyClient>,
) -> HttpResponse {
    let cache_key = "api:hourly";

    // 캐시 확인
    if let Some(cached) = cache.get_cache(cache_key).await {
        return HttpResponse::Ok()
            .content_type("application/json")
            .body(cached);
    }

    match ch.get_hourly().await {
        Ok(data) => {
            let json_str = serde_json::to_string(&data).unwrap_or_default();

            // 캐시 저장 (60초)
            cache.set_cache(cache_key, &json_str, 60).await;

            HttpResponse::Ok().json(data)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))
    }
}

/// /api/traffic/daily - 일별 통계 (5분 캐시)
pub async fn daily(
    ch: web::Data<ClickHouseClient>,
    cache: web::Data<DragonflyClient>,
) -> HttpResponse {
    let cache_key = "api:daily";

    // 캐시 확인
    if let Some(cached) = cache.get_cache(cache_key).await {
        return HttpResponse::Ok()
            .content_type("application/json")
            .body(cached);
    }

    match ch.get_daily().await {
        Ok(data) => {
            let json_str = serde_json::to_string(&data).unwrap_or_default();

            // 캐시 저장 (5분)
            cache.set_cache(cache_key, &json_str, 300).await;

            HttpResponse::Ok().json(data)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))
    }
}

/// /api/traffic/monthly - 월별 통계 (10분 캐시)
pub async fn monthly(
    ch: web::Data<ClickHouseClient>,
    cache: web::Data<DragonflyClient>,
) -> HttpResponse {
    let cache_key = "api:monthly";

    // 캐시 확인
    if let Some(cached) = cache.get_cache(cache_key).await {
        return HttpResponse::Ok()
            .content_type("application/json")
            .body(cached);
    }

    match ch.get_monthly().await {
        Ok(data) => {
            let json_str = serde_json::to_string(&data).unwrap_or_default();

            // 캐시 저장 (10분)
            cache.set_cache(cache_key, &json_str, 600).await;

            HttpResponse::Ok().json(data)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": e.to_string()
        }))
    }
}

#[derive(Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Deserialize)]
pub struct TopQuery {
    pub limit: Option<u32>,
    pub offset: Option<u32>,
    pub period: Option<String>,
}
