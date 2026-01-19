use actix_web::{web, App, HttpServer, HttpRequest, HttpResponse, middleware};
use actix_ws::Message;
use futures_util::StreamExt;
use indexmap::IndexMap;
use maxminddb::{geoip2, Reader};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

// ============================================================
// GeoIP Reader (전역)
// ============================================================
static GEOIP_ASN_READER: Lazy<Option<Reader<Vec<u8>>>> = Lazy::new(|| {
    let path = "data/GeoLite2-ASN.mmdb";
    match Reader::open_readfile(path) {
        Ok(reader) => {
            log::info!("GeoIP ASN database loaded: {}", path);
            Some(reader)
        }
        Err(e) => {
            log::warn!("Failed to load GeoIP ASN database: {} - ISP matching disabled", e);
            None
        }
    }
});

static GEOIP_COUNTRY_READER: Lazy<Option<Reader<Vec<u8>>>> = Lazy::new(|| {
    let path = "data/GeoLite2-Country.mmdb";
    match Reader::open_readfile(path) {
        Ok(reader) => {
            log::info!("GeoIP Country database loaded: {}", path);
            Some(reader)
        }
        Err(e) => {
            log::warn!("Failed to load GeoIP Country database: {}", e);
            None
        }
    }
});

static GEOIP_CITY_READER: Lazy<Option<Reader<Vec<u8>>>> = Lazy::new(|| {
    let path = "data/GeoLite2-City.mmdb";
    match Reader::open_readfile(path) {
        Ok(reader) => {
            log::info!("GeoIP City database loaded: {}", path);
            Some(reader)
        }
        Err(e) => {
            log::warn!("Failed to load GeoIP City database: {}", e);
            None
        }
    }
});

// ============================================================
// 설정 상수 (Aquatic 기반)
// ============================================================
const MAX_PEER_AGE_MS: u64 = 180_000;       // 피어 타임아웃 180초
const MAX_OFFER_AGE_MS: u64 = 120_000;      // Offer 만료 120초
const MAX_OFFERS_PER_ANNOUNCE: usize = 10;   // 최대 offer 수
const CLEANUP_INTERVAL_SECS: u64 = 30;       // 정리 주기
const PEER_ANNOUNCE_INTERVAL: usize = 120;   // 재announce 주기

// ============================================================
// GeoIP 데이터 (ISP 기반 매칭용)
// ============================================================
#[derive(Clone, Debug, Default)]
struct GeoData {
    country: String,      // 국가 코드 (예: "KR")
    city: String,         // 도시 이름 (예: "Seoul")
    asn: u32,             // ISP 식별자 (예: 4766 = SK Telecom)
    as_org: String,       // ISP 이름
}

// ============================================================
// 데이터 구조체 (Aquatic 기반 개선)
// ============================================================

/// Offer에 대한 Answer 기대 추적 (Aquatic 방식)
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExpectingAnswer {
    from_peer_id: String,
    offer_id: String,
}

#[derive(Clone, Debug)]
struct Peer {
    peer_id: String,
    socket_id: u64,
    ip: String,
    geo: GeoData,
    valid_until: u64,           // 만료 시간 (ms)
    is_seeder: bool,
    offers_sent: u64,
    offers_received: u64,
    answers_sent: u64,
    // Offer에 대한 Answer 기대 목록 (offer_id -> 만료시간)
    expecting_answers: IndexMap<ExpectingAnswer, u64>,
}

#[derive(Clone, Debug, Default)]
struct Swarm {
    info_hash: String,
    // IndexMap 사용: 삽입 순서 유지 → 피어 선택 다양성 확보
    peers: IndexMap<String, Peer>,
    num_seeders: usize,
    created_at: u64,
    total_announces: u64,
}

// 메시지 로그 (최근 N개)
#[derive(Clone, Debug, Serialize)]
struct MessageLog {
    timestamp: u64,
    #[serde(rename = "type")]
    msg_type: String,  // "offer" or "answer"
    from_peer: String,
    to_peer: String,
    info_hash: String,
    from_isp: String,
    to_isp: String,
    #[serde(rename = "fromCountry")]
    from_country: String,
    #[serde(rename = "toCountry")]
    to_country: String,
    #[serde(rename = "fromCity")]
    from_city: String,
    #[serde(rename = "toCity")]
    to_city: String,
    #[serde(rename = "matchTier")]
    match_tier: String,  // "isp_city", "isp", "city", "country", "random"
}

// 피어 연결 관계
#[derive(Clone, Debug, Default, Serialize)]
struct PeerConnection {
    peer_id: String,
    connected_peers: Vec<String>,  // 연결된 피어 목록
    offers_sent_to: HashMap<String, u64>,  // 피어별 offer 전송 횟수
    answers_received_from: HashMap<String, u64>,  // 피어별 answer 수신 횟수
}

const MAX_MESSAGE_LOGS: usize = 200;

#[derive(Default)]
struct TrackerState {
    // 스웜 관리: info_hash -> Swarm (IndexMap으로 순서 유지)
    swarms: IndexMap<String, Swarm>,

    // 소켓 -> (info_hash, peer_id) 매핑 (연결 해제 시 정리용)
    socket_to_peer: HashMap<u64, Vec<(String, String)>>,

    // 소켓 -> sender (메시지 전송용)
    sockets: HashMap<u64, mpsc::UnboundedSender<String>>,

    // 통계
    total_connections: u64,
    total_announces: u64,
    total_offers_relayed: u64,
    total_answers_relayed: u64,
    total_answers_expired: u64,
    start_time: u64,

    // ISP별 통계
    isp_stats: HashMap<u32, IspStats>,

    // 국가별 통계
    country_stats: HashMap<String, CountryStats>,

    // 도시별 통계
    city_stats: HashMap<String, CityStats>,

    // 매칭 통계 (계층적 지역 매칭)
    matches_same_isp_city: u64,  // 같은 ISP + 같은 도시 (최고)
    matches_same_isp: u64,       // 같은 ISP (다른 도시)
    matches_same_city: u64,      // 같은 도시 (다른 ISP)
    matches_same_country: u64,   // 같은 국가 (다른 도시)
    matches_random: u64,         // 해외 매칭

    // 메시지 로그 (최근 200개)
    message_logs: Vec<MessageLog>,

    // 피어별 연결 관계
    peer_connections: HashMap<String, PeerConnection>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct IspStats {
    asn: u32,
    name: String,
    peer_count: u64,
    offers_internal: u64,   // 같은 ISP 내 offer
    offers_external: u64,   // 다른 ISP로 offer
}

#[derive(Clone, Debug, Default, Serialize)]
struct CountryStats {
    code: String,
    peer_count: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct CityStats {
    name: String,
    country: String,
    peer_count: u64,
}

type SharedState = Arc<RwLock<TrackerState>>;

// ============================================================
// 프로토콜 메시지 (WebTorrent 호환)
// ============================================================

#[derive(Deserialize, Debug)]
struct TrackerMessage {
    action: Option<String>,
    info_hash: Option<String>,
    peer_id: Option<String>,
    offers: Option<Vec<Offer>>,
    numwant: Option<u32>,
    answer: Option<serde_json::Value>,
    offer_id: Option<String>,
    to_peer_id: Option<String>,
    // 추가 필드
    left: Option<u64>,       // 남은 바이트 (0이면 seeder)
    event: Option<String>,   // started, stopped, completed
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Offer {
    offer_id: String,
    offer: serde_json::Value,
}

#[derive(Serialize)]
struct AnnounceResponse {
    action: String,
    info_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    complete: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    incomplete: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offer: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    offer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    interval: Option<usize>,
}

#[derive(Serialize)]
struct ScrapeResponse {
    action: String,
    files: HashMap<String, ScrapeFile>,
}

#[derive(Serialize)]
struct ScrapeFile {
    complete: u32,
    incomplete: u32,
}

// ============================================================
// API 응답 구조체
// ============================================================

#[derive(Serialize)]
struct StatsResponse {
    uptime: u64,
    #[serde(rename = "totalConnections")]
    total_connections: u64,
    #[serde(rename = "activeConnections")]
    active_connections: u64,
    #[serde(rename = "totalSwarms")]
    total_swarms: u64,
    #[serde(rename = "activeSwarms")]
    active_swarms: u64,
    #[serde(rename = "totalPeers")]
    total_peers: u64,
    #[serde(rename = "totalSeeders")]
    total_seeders: u64,
    #[serde(rename = "totalLeechers")]
    total_leechers: u64,
    #[serde(rename = "totalAnnounces")]
    total_announces: u64,
    #[serde(rename = "offersRelayed")]
    offers_relayed: u64,
    #[serde(rename = "answersRelayed")]
    answers_relayed: u64,
    #[serde(rename = "answersExpired")]
    answers_expired: u64,
    // 계층적 매칭 통계
    #[serde(rename = "matchesSameIspCity")]
    matches_same_isp_city: u64,
    #[serde(rename = "matchesSameIsp")]
    matches_same_isp: u64,
    #[serde(rename = "matchesSameCity")]
    matches_same_city: u64,
    #[serde(rename = "matchesSameCountry")]
    matches_same_country: u64,
    #[serde(rename = "matchesRandom")]
    matches_random: u64,
}

#[derive(Serialize)]
struct SwarmInfo {
    #[serde(rename = "infoHash")]
    info_hash: String,
    #[serde(rename = "peerCount")]
    peer_count: u64,
    seeders: usize,
    leechers: usize,
    #[serde(rename = "createdAt")]
    created_at: u64,
    announces: u64,
}

#[derive(Serialize)]
struct SwarmsResponse {
    swarms: Vec<SwarmInfo>,
    total: u64,
}

#[derive(Serialize)]
struct IspStatsResponse {
    isps: Vec<IspStats>,
}

#[derive(Serialize)]
struct MessageLogsResponse {
    logs: Vec<MessageLog>,
    total: usize,
}

#[derive(Serialize)]
struct PeerDetailResponse {
    peer_id: String,
    ip: String,
    isp: String,
    country: String,
    swarms: Vec<String>,
    offers_sent: u64,
    answers_sent: u64,
    connected_peers: Vec<String>,
    offers_sent_to: HashMap<String, u64>,
    answers_received_from: HashMap<String, u64>,
}

#[derive(Serialize)]
struct ConnectionsResponse {
    connections: Vec<ConnectionInfo>,
    total: usize,
}

#[derive(Serialize)]
struct ConnectionInfo {
    from_peer: String,
    to_peer: String,
    from_isp: String,
    to_isp: String,
    offer_count: u64,
    answer_count: u64,
}

// ============================================================
// 유틸리티 함수
// ============================================================

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// GeoIP 조회 (MaxMind ASN + Country + City DB)
fn lookup_geo(ip: &str) -> GeoData {
    // IP 주소에서 포트 제거 (예: "1.2.3.4:12345" -> "1.2.3.4")
    let ip_str = ip.split(':').next().unwrap_or(ip);

    // IPv6 대괄호 제거 (예: "[::1]" -> "::1")
    let ip_clean = ip_str.trim_start_matches('[').trim_end_matches(']');

    let mut result = GeoData::default();

    if let Ok(ip_addr) = ip_clean.parse::<IpAddr>() {
        // ASN 조회
        if let Some(reader) = GEOIP_ASN_READER.as_ref() {
            if let Ok(asn) = reader.lookup::<geoip2::Asn>(ip_addr) {
                result.asn = asn.autonomous_system_number.unwrap_or(0);
                result.as_org = asn.autonomous_system_organization.unwrap_or("Unknown").to_string();
            }
        }

        // City DB에서 국가 + 도시 조회 (Country DB 대체)
        if let Some(reader) = GEOIP_CITY_READER.as_ref() {
            if let Ok(city) = reader.lookup::<geoip2::City>(ip_addr) {
                // 국가
                if let Some(c) = city.country {
                    result.country = c.iso_code.unwrap_or("").to_string();
                }
                // 도시
                if let Some(c) = city.city {
                    if let Some(names) = c.names {
                        // 영어 이름 우선, 없으면 첫 번째 이름
                        result.city = names.get("en")
                            .or_else(|| names.values().next())
                            .map(|s| s.to_string())
                            .unwrap_or_default();
                    }
                }
            }
        } else if let Some(reader) = GEOIP_COUNTRY_READER.as_ref() {
            // City DB가 없으면 Country DB 사용
            if let Ok(country) = reader.lookup::<geoip2::Country>(ip_addr) {
                if let Some(c) = country.country {
                    result.country = c.iso_code.unwrap_or("").to_string();
                }
            }
        }
    }

    result
}

// ============================================================
// 피어 선택 알고리즘 (계층적 지역 기반 매칭)
// ============================================================

/// 피어 선택: 계층적 우선순위 매칭
/// 1순위: 같은 ISP (ASN) - 망 내부 트래픽
/// 2순위: 같은 도시 - 낮은 지연시간
/// 3순위: 같은 국가 - 국제 트래픽 회피
/// 4순위: 랜덤 선택
fn extract_response_peers<'a>(
    peer_map: &'a IndexMap<String, Peer>,
    max_num_peers: usize,
    sender_peer_id: &str,
    sender_geo: &GeoData,  // 요청자의 지역 정보
) -> Vec<&'a Peer> {
    // 자신 제외한 피어 수
    let available = peer_map.len().saturating_sub(1);

    if available == 0 {
        return Vec::new();
    }

    // 피어 수가 적으면 전체 반환
    if available <= max_num_peers {
        return peer_map.values()
            .filter(|p| p.peer_id != sender_peer_id)
            .collect();
    }

    let mut result: Vec<&Peer> = Vec::with_capacity(max_num_peers);
    let mut selected_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut rng = rand::thread_rng();

    // 1순위: 같은 ISP + 같은 도시 (최고 품질)
    if sender_geo.asn > 0 && !sender_geo.city.is_empty() {
        let mut same_isp_city: Vec<&Peer> = peer_map.values()
            .filter(|p| {
                p.peer_id != sender_peer_id
                    && p.geo.asn == sender_geo.asn
                    && !p.geo.city.is_empty()
                    && p.geo.city == sender_geo.city
            })
            .collect();
        same_isp_city.shuffle(&mut rng);  // 랜덤 셔플

        for peer in same_isp_city.iter().take(max_num_peers) {
            result.push(*peer);
            selected_ids.insert(peer.peer_id.as_str());
        }
    }

    // 2순위: 같은 ISP (다른 도시)
    if sender_geo.asn > 0 && result.len() < max_num_peers {
        let mut same_isp: Vec<&Peer> = peer_map.values()
            .filter(|p| {
                p.peer_id != sender_peer_id
                    && !selected_ids.contains(p.peer_id.as_str())
                    && p.geo.asn == sender_geo.asn
            })
            .collect();
        same_isp.shuffle(&mut rng);  // 랜덤 셔플

        let remaining = max_num_peers - result.len();
        for peer in same_isp.iter().take(remaining) {
            result.push(*peer);
            selected_ids.insert(peer.peer_id.as_str());
        }
    }

    // 3순위: 같은 도시 (다른 ISP)
    if !sender_geo.city.is_empty() && result.len() < max_num_peers {
        let mut same_city: Vec<&Peer> = peer_map.values()
            .filter(|p| {
                p.peer_id != sender_peer_id
                    && !selected_ids.contains(p.peer_id.as_str())
                    && !p.geo.city.is_empty()
                    && p.geo.city == sender_geo.city
            })
            .collect();
        same_city.shuffle(&mut rng);  // 랜덤 셔플

        let remaining = max_num_peers - result.len();
        for peer in same_city.iter().take(remaining) {
            result.push(*peer);
            selected_ids.insert(peer.peer_id.as_str());
        }
    }

    // 4순위: 같은 국가 (다른 도시)
    if !sender_geo.country.is_empty() && result.len() < max_num_peers {
        let mut same_country: Vec<&Peer> = peer_map.values()
            .filter(|p| {
                p.peer_id != sender_peer_id
                    && !selected_ids.contains(p.peer_id.as_str())
                    && !p.geo.country.is_empty()
                    && p.geo.country == sender_geo.country
            })
            .collect();
        same_country.shuffle(&mut rng);  // 랜덤 셔플

        let remaining = max_num_peers - result.len();
        for peer in same_country.iter().take(remaining) {
            result.push(*peer);
            selected_ids.insert(peer.peer_id.as_str());
        }
    }

    // 5순위: 나머지 (해외 포함)
    if result.len() < max_num_peers {
        let mut others: Vec<&Peer> = peer_map.values()
            .filter(|p| p.peer_id != sender_peer_id && !selected_ids.contains(p.peer_id.as_str()))
            .collect();
        others.shuffle(&mut rng);  // 랜덤 셔플

        let remaining = max_num_peers - result.len();
        result.extend(others.iter().take(remaining).copied());
    }

    result
}

// ============================================================
// 트래커 로직
// ============================================================

fn handle_announce(
    state: &mut TrackerState,
    socket_id: u64,
    ip: &str,
    msg: &TrackerMessage,
) -> Vec<(u64, String)> {
    let mut responses: Vec<(u64, String)> = Vec::new();

    let info_hash = match &msg.info_hash {
        Some(h) => h.clone(),
        None => return responses,
    };

    let peer_id = match &msg.peer_id {
        Some(p) => p.clone(),
        None => return responses,
    };

    let now = now_ms();
    state.total_announces += 1;

    // 이벤트 처리 (stopped면 피어 제거)
    if let Some(event) = &msg.event {
        if event == "stopped" {
            if let Some(swarm) = state.swarms.get_mut(&info_hash) {
                if let Some(peer) = swarm.peers.swap_remove(&peer_id) {
                    if peer.is_seeder {
                        swarm.num_seeders = swarm.num_seeders.saturating_sub(1);
                    }
                }
            }
            return responses;
        }
    }

    // 스웜 생성 또는 가져오기
    let swarm = state.swarms.entry(info_hash.clone()).or_insert_with(|| {
        Swarm {
            info_hash: info_hash.clone(),
            peers: IndexMap::new(),
            num_seeders: 0,
            created_at: now,
            total_announces: 0,
        }
    });

    swarm.total_announces += 1;

    // Answer 처리 (다른 피어에게 전달)
    if let Some(answer) = &msg.answer {
        if let Some(to_peer_id) = &msg.to_peer_id {
            // sender(peer_id)의 geo 정보 가져오기
            let sender_geo = swarm.peers.get(&peer_id).map(|p| p.geo.clone()).unwrap_or_default();

            if let Some(target_peer) = swarm.peers.get_mut(to_peer_id) {
                // expecting_answers 확인 (Aquatic 방식)
                let expecting = ExpectingAnswer {
                    from_peer_id: peer_id.clone(),
                    offer_id: msg.offer_id.clone().unwrap_or_default(),
                };

                if target_peer.expecting_answers.swap_remove(&expecting).is_some() {
                    let target_geo = target_peer.geo.clone();

                    let response = AnnounceResponse {
                        action: "announce".to_string(),
                        info_hash: info_hash.clone(),
                        complete: None,
                        incomplete: None,
                        offer: None,
                        offer_id: msg.offer_id.clone(),
                        peer_id: Some(peer_id.clone()),
                        answer: Some(answer.clone()),
                        interval: None,
                    };

                    if let Ok(json) = serde_json::to_string(&response) {
                        responses.push((target_peer.socket_id, json));
                        state.total_answers_relayed += 1;

                        // 매칭 티어 계산
                        let same_country = match (!sender_geo.country.is_empty(), !target_geo.country.is_empty()) {
                            (true, true) => sender_geo.country == target_geo.country,
                            _ => true,
                        };
                        let same_city = !sender_geo.city.is_empty() && !target_geo.city.is_empty() && sender_geo.city == target_geo.city;
                        let same_isp = sender_geo.asn > 0 && target_geo.asn > 0 && sender_geo.asn == target_geo.asn;
                        let match_tier = if same_isp && same_city { "isp_city" }
                            else if same_isp { "isp" }
                            else if same_city { "city" }
                            else if same_country { "country" }
                            else { "random" };

                        // 메시지 로그 기록
                        let log_entry = MessageLog {
                            timestamp: now,
                            msg_type: "answer".to_string(),
                            from_peer: peer_id.clone(),
                            to_peer: to_peer_id.clone(),
                            info_hash: info_hash.clone(),
                            from_isp: sender_geo.as_org.clone(),
                            to_isp: target_geo.as_org.clone(),
                            from_country: sender_geo.country.clone(),
                            to_country: target_geo.country.clone(),
                            from_city: sender_geo.city.clone(),
                            to_city: target_geo.city.clone(),
                            match_tier: match_tier.to_string(),
                        };
                        state.message_logs.push(log_entry);
                        if state.message_logs.len() > MAX_MESSAGE_LOGS {
                            state.message_logs.remove(0);
                        }

                        // 연결 관계 기록
                        let conn = state.peer_connections.entry(peer_id.clone()).or_insert_with(|| PeerConnection {
                            peer_id: peer_id.clone(),
                            ..Default::default()
                        });
                        *conn.answers_received_from.entry(to_peer_id.clone()).or_insert(0) += 1;
                        if !conn.connected_peers.contains(to_peer_id) {
                            conn.connected_peers.push(to_peer_id.clone());
                        }

                        // 통계 업데이트
                        if let Some(sender_peer) = swarm.peers.get_mut(&peer_id) {
                            sender_peer.answers_sent += 1;
                        }
                    }
                } else {
                    log::debug!("Answer for unknown offer_id: {:?}", msg.offer_id);
                }
            }
        }
        return responses;
    }

    // seeder 여부 확인 (WebTorrent 클라이언트는 left 필드를 안 보내서 대부분 리처로 처리됨)
    let is_seeder = msg.left.map(|l| l == 0).unwrap_or(false)
        || msg.event.as_deref() == Some("completed");

    // 피어 ID 검증: 같은 peer_id로 다른 socket에서 요청 시 거부 (스푸핑 방지)
    if let Some(existing_peer) = swarm.peers.get(&peer_id) {
        if existing_peer.socket_id != socket_id {
            log::warn!("Peer ID spoofing attempt: {} from socket {}", peer_id, socket_id);
            return responses;
        }
    }

    // GeoIP 조회
    let geo = lookup_geo(ip);

    // 피어 등록/업데이트
    let is_new_peer = !swarm.peers.contains_key(&peer_id);
    let peer = swarm.peers.entry(peer_id.clone()).or_insert_with(|| {
        Peer {
            peer_id: peer_id.clone(),
            socket_id,
            ip: ip.to_string(),
            geo: geo.clone(),
            valid_until: now + MAX_PEER_AGE_MS,
            is_seeder: false,
            offers_sent: 0,
            offers_received: 0,
            answers_sent: 0,
            expecting_answers: IndexMap::new(),
        }
    });

    // 새 피어면 ISP peer_count 증가
    if is_new_peer && geo.asn > 0 {
        let isp_stat = state.isp_stats.entry(geo.asn).or_insert_with(|| IspStats {
            asn: geo.asn,
            name: geo.as_org.clone(),
            peer_count: 0,
            offers_internal: 0,
            offers_external: 0,
        });
        isp_stat.peer_count += 1;
    }

    // 새 피어면 국가별 통계 증가
    if is_new_peer && !geo.country.is_empty() {
        let country_stat = state.country_stats.entry(geo.country.clone()).or_insert_with(|| CountryStats {
            code: geo.country.clone(),
            peer_count: 0,
        });
        country_stat.peer_count += 1;
    }

    // 새 피어면 도시별 통계 증가
    if is_new_peer && !geo.city.is_empty() {
        let city_key = format!("{}_{}", geo.country, geo.city);
        let city_stat = state.city_stats.entry(city_key).or_insert_with(|| CityStats {
            name: geo.city.clone(),
            country: geo.country.clone(),
            peer_count: 0,
        });
        city_stat.peer_count += 1;
    }

    // 피어 정보 업데이트
    peer.valid_until = now + MAX_PEER_AGE_MS;
    peer.socket_id = socket_id;

    // seeder 상태 변경 추적
    if peer.is_seeder != is_seeder {
        if is_seeder {
            swarm.num_seeders += 1;
        } else {
            swarm.num_seeders = swarm.num_seeders.saturating_sub(1);
        }
        peer.is_seeder = is_seeder;
    }

    // 소켓 -> 피어 매핑 등록
    state.socket_to_peer
        .entry(socket_id)
        .or_insert_with(Vec::new)
        .push((info_hash.clone(), peer_id.clone()));

    // Offer 처리 (다른 피어들에게 전달)
    if let Some(offers) = &msg.offers {
        let numwant = msg.numwant.unwrap_or(10) as usize;
        let max_offers = offers.len().min(MAX_OFFERS_PER_ANNOUNCE);

        // 피어 선택 (계층적 지역 매칭)
        let target_peers = extract_response_peers(
            &swarm.peers,
            numwant.min(max_offers),
            &peer_id,
            &geo,
        );

        // 1단계: 메시지 생성 및 expecting_answers 데이터 수집
        let mut expecting_entries: Vec<(ExpectingAnswer, u64)> = Vec::new();
        let mut offers_count = 0u64;
        let mut offers_internal = 0u64;
        let mut offers_external = 0u64;

        for (i, target_peer) in target_peers.iter().enumerate() {
            if i >= offers.len() {
                break;
            }

            let offer = &offers[i];

            // 계층적 매칭 통계 기록
            let t_geo = &target_peer.geo;

            // 국가 비교 (한쪽이라도 있으면 사용, 둘 다 있으면 비교)
            let same_country = match (!geo.country.is_empty(), !t_geo.country.is_empty()) {
                (true, true) => geo.country == t_geo.country,
                (true, false) | (false, true) => true,  // 한쪽만 있으면 같은 국가로 간주
                (false, false) => true,  // 둘 다 없으면 같은 국가로 간주 (국내 트래픽 가정)
            };

            // 도시 비교
            let same_city = !geo.city.is_empty() && !t_geo.city.is_empty() && geo.city == t_geo.city;

            let same_isp = geo.asn > 0 && t_geo.asn > 0 && t_geo.asn == geo.asn;

            let match_tier = if same_isp && same_city {
                // 같은 ISP + 같은 도시 (최고)
                state.matches_same_isp_city += 1;
                offers_internal += 1;
                "isp_city"
            } else if same_isp {
                // 같은 ISP (다른 도시)
                state.matches_same_isp += 1;
                offers_internal += 1;
                "isp"
            } else if same_city {
                // 같은 도시 (다른 ISP)
                state.matches_same_city += 1;
                offers_external += 1;
                "city"
            } else if same_country {
                // 같은 국가 (다른 도시)
                state.matches_same_country += 1;
                offers_external += 1;
                "country"
            } else {
                // 해외 매칭
                state.matches_random += 1;
                offers_external += 1;
                "random"
            };

            // expecting_answers 데이터 수집
            expecting_entries.push((
                ExpectingAnswer {
                    from_peer_id: target_peer.peer_id.clone(),
                    offer_id: offer.offer_id.clone(),
                },
                now + MAX_OFFER_AGE_MS,
            ));
            offers_count += 1;

            let response = AnnounceResponse {
                action: "announce".to_string(),
                info_hash: info_hash.clone(),
                complete: None,
                incomplete: None,
                offer: Some(offer.offer.clone()),
                offer_id: Some(offer.offer_id.clone()),
                peer_id: Some(peer_id.clone()),
                answer: None,
                interval: None,
            };

            if let Ok(json) = serde_json::to_string(&response) {
                responses.push((target_peer.socket_id, json));
                state.total_offers_relayed += 1;

                // 메시지 로그 기록
                let log_entry = MessageLog {
                    timestamp: now,
                    msg_type: "offer".to_string(),
                    from_peer: peer_id.clone(),
                    to_peer: target_peer.peer_id.clone(),
                    info_hash: info_hash.clone(),
                    from_isp: geo.as_org.clone(),
                    to_isp: target_peer.geo.as_org.clone(),
                    from_country: geo.country.clone(),
                    to_country: target_peer.geo.country.clone(),
                    from_city: geo.city.clone(),
                    to_city: target_peer.geo.city.clone(),
                    match_tier: match_tier.to_string(),
                };
                state.message_logs.push(log_entry);
                if state.message_logs.len() > MAX_MESSAGE_LOGS {
                    state.message_logs.remove(0);
                }

                // 연결 관계 기록
                let conn = state.peer_connections.entry(peer_id.clone()).or_insert_with(|| PeerConnection {
                    peer_id: peer_id.clone(),
                    ..Default::default()
                });
                *conn.offers_sent_to.entry(target_peer.peer_id.clone()).or_insert(0) += 1;
            }
        }

        // ISP 통계 업데이트
        if geo.asn > 0 {
            let isp_stat = state.isp_stats.entry(geo.asn).or_insert_with(|| IspStats {
                asn: geo.asn,
                name: geo.as_org.clone(),
                peer_count: 0,
                offers_internal: 0,
                offers_external: 0,
            });
            isp_stat.offers_internal += offers_internal;
            isp_stat.offers_external += offers_external;
        }

        // 2단계: expecting_answers 등록 (별도 mutable borrow)
        if let Some(sender_peer) = swarm.peers.get_mut(&peer_id) {
            for (expecting, valid_until) in expecting_entries {
                sender_peer.expecting_answers.insert(expecting, valid_until);
            }
            sender_peer.offers_sent += offers_count;
        }
    }

    // AnnounceResponse (complete/incomplete 포함) - 요청자에게 전송
    let announce_response = AnnounceResponse {
        action: "announce".to_string(),
        info_hash: info_hash.clone(),
        complete: Some(swarm.num_seeders),
        incomplete: Some(swarm.peers.len() - swarm.num_seeders),
        offer: None,
        offer_id: None,
        peer_id: None,
        answer: None,
        interval: Some(PEER_ANNOUNCE_INTERVAL),
    };

    if let Ok(json) = serde_json::to_string(&announce_response) {
        responses.push((socket_id, json));
    }

    responses
}

fn handle_scrape(state: &TrackerState, msg: &TrackerMessage) -> Option<String> {
    let info_hash = msg.info_hash.as_ref()?;

    let mut files = HashMap::new();

    if let Some(swarm) = state.swarms.get(info_hash) {
        files.insert(info_hash.clone(), ScrapeFile {
            complete: swarm.num_seeders as u32,
            incomplete: (swarm.peers.len() - swarm.num_seeders) as u32,
        });
    } else {
        files.insert(info_hash.clone(), ScrapeFile {
            complete: 0,
            incomplete: 0,
        });
    }

    let response = ScrapeResponse {
        action: "scrape".to_string(),
        files,
    };

    serde_json::to_string(&response).ok()
}

fn cleanup_peer(state: &mut TrackerState, socket_id: u64) {
    // 소켓에 연결된 모든 피어 제거
    if let Some(peer_infos) = state.socket_to_peer.remove(&socket_id) {
        for (info_hash, peer_id) in peer_infos {
            if let Some(swarm) = state.swarms.get_mut(&info_hash) {
                if let Some(peer) = swarm.peers.swap_remove(&peer_id) {
                    if peer.is_seeder {
                        swarm.num_seeders = swarm.num_seeders.saturating_sub(1);
                    }
                }

                // 빈 스웜 제거
                if swarm.peers.is_empty() {
                    state.swarms.swap_remove(&info_hash);
                }
            }
        }
    }

    // 소켓 sender 제거
    state.sockets.remove(&socket_id);
}

// ============================================================
// WebSocket 핸들러
// ============================================================

async fn ws_handler(
    req: HttpRequest,
    stream: web::Payload,
    state: web::Data<SharedState>,
) -> Result<HttpResponse, actix_web::Error> {
    let (res, mut session, mut msg_stream) = actix_ws::handle(&req, stream)?;

    // 소켓 ID 생성
    let socket_id: u64 = rand::random();

    // 클라이언트 IP 추출
    let ip = req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string();

    // 메시지 전송용 채널
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // 소켓 등록
    {
        let mut s = state.write();
        s.sockets.insert(socket_id, tx);
        s.total_connections += 1;
    }

    log::info!("New connection: socket_id={}, ip={}", socket_id, ip);

    let state_clone = state.clone();
    let ip_clone = ip.clone();

    // 메시지 처리 태스크
    actix_rt::spawn(async move {
        loop {
            tokio::select! {
                // 클라이언트로부터 메시지 수신
                Some(msg) = msg_stream.next() => {
                    match msg {
                        Ok(Message::Text(text)) => {
                            if let Ok(tracker_msg) = serde_json::from_str::<TrackerMessage>(&text) {
                                let action = tracker_msg.action.as_deref().unwrap_or("");

                                match action {
                                    "announce" => {
                                        let responses = {
                                            let mut s = state_clone.write();
                                            handle_announce(&mut s, socket_id, &ip_clone, &tracker_msg)
                                        };

                                        // 응답 전송
                                        let s = state_clone.read();
                                        for (target_socket_id, json) in responses {
                                            if let Some(sender) = s.sockets.get(&target_socket_id) {
                                                let _ = sender.send(json);
                                            }
                                        }
                                    }
                                    "scrape" => {
                                        let s = state_clone.read();
                                        if let Some(response) = handle_scrape(&s, &tracker_msg) {
                                            drop(s);
                                            let _ = session.text(response).await;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Ok(Message::Ping(data)) => {
                            let _ = session.pong(&data).await;
                        }
                        Ok(Message::Close(_)) => {
                            break;
                        }
                        Err(_) => {
                            break;
                        }
                        _ => {}
                    }
                }

                // 다른 피어에게 보낼 메시지
                Some(msg) = rx.recv() => {
                    if session.text(msg).await.is_err() {
                        break;
                    }
                }

                else => break,
            }
        }

        // 연결 종료 시 정리
        log::info!("Connection closed: socket_id={}", socket_id);
        let mut s = state_clone.write();
        cleanup_peer(&mut s, socket_id);
    });

    Ok(res)
}

// ============================================================
// HTTP API 핸들러
// ============================================================

async fn api_stats(state: web::Data<SharedState>) -> HttpResponse {
    let s = state.read();
    let now = now_secs();

    let mut total_peers: u64 = 0;
    let mut total_seeders: u64 = 0;

    for swarm in s.swarms.values() {
        total_peers += swarm.peers.len() as u64;
        total_seeders += swarm.num_seeders as u64;
    }

    let response = StatsResponse {
        uptime: now.saturating_sub(s.start_time),
        total_connections: s.total_connections,
        active_connections: s.sockets.len() as u64,
        total_swarms: s.swarms.len() as u64,
        active_swarms: s.swarms.values().filter(|sw| !sw.peers.is_empty()).count() as u64,
        total_peers,
        total_seeders,
        total_leechers: total_peers - total_seeders,
        total_announces: s.total_announces,
        offers_relayed: s.total_offers_relayed,
        answers_relayed: s.total_answers_relayed,
        answers_expired: s.total_answers_expired,
        matches_same_isp_city: s.matches_same_isp_city,
        matches_same_isp: s.matches_same_isp,
        matches_same_city: s.matches_same_city,
        matches_same_country: s.matches_same_country,
        matches_random: s.matches_random,
    };

    HttpResponse::Ok().json(response)
}

async fn api_swarms(state: web::Data<SharedState>, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let s = state.read();

    let limit: usize = query.get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);

    let offset: usize = query.get("offset")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let mut swarms: Vec<SwarmInfo> = s.swarms.values()
        .map(|swarm| SwarmInfo {
            info_hash: swarm.info_hash.clone(),
            peer_count: swarm.peers.len() as u64,
            seeders: swarm.num_seeders,
            leechers: swarm.peers.len() - swarm.num_seeders,
            created_at: swarm.created_at,
            announces: swarm.total_announces,
        })
        .collect();

    // 피어 수 기준 정렬
    swarms.sort_by(|a, b| b.peer_count.cmp(&a.peer_count));

    let total = swarms.len() as u64;
    let swarms: Vec<_> = swarms.into_iter().skip(offset).take(limit).collect();

    HttpResponse::Ok().json(SwarmsResponse { swarms, total })
}

async fn api_swarm_detail(state: web::Data<SharedState>, path: web::Path<String>) -> HttpResponse {
    let info_hash = path.into_inner();
    let s = state.read();

    if let Some(swarm) = s.swarms.get(&info_hash) {
        let response = SwarmInfo {
            info_hash: swarm.info_hash.clone(),
            peer_count: swarm.peers.len() as u64,
            seeders: swarm.num_seeders,
            leechers: swarm.peers.len() - swarm.num_seeders,
            created_at: swarm.created_at,
            announces: swarm.total_announces,
        };
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "Swarm not found"}))
    }
}

async fn api_isps(state: web::Data<SharedState>) -> HttpResponse {
    let s = state.read();

    let isps: Vec<IspStats> = s.isp_stats.values().cloned().collect();

    HttpResponse::Ok().json(IspStatsResponse { isps })
}

#[derive(Serialize)]
struct CountryStatsResponse {
    countries: Vec<CountryStats>,
}

async fn api_countries(state: web::Data<SharedState>) -> HttpResponse {
    let s = state.read();

    let mut countries: Vec<CountryStats> = s.country_stats.values().cloned().collect();
    countries.sort_by(|a, b| b.peer_count.cmp(&a.peer_count));

    HttpResponse::Ok().json(CountryStatsResponse { countries })
}

#[derive(Serialize)]
struct CityStatsResponse {
    cities: Vec<CityStats>,
}

async fn api_cities(state: web::Data<SharedState>, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let s = state.read();

    let limit: usize = query.get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    let mut cities: Vec<CityStats> = s.city_stats.values().cloned().collect();
    cities.sort_by(|a, b| b.peer_count.cmp(&a.peer_count));
    cities.truncate(limit);

    HttpResponse::Ok().json(CityStatsResponse { cities })
}

// 메시지 로그 API
async fn api_logs(state: web::Data<SharedState>, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let s = state.read();

    let limit = query.get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(50)
        .min(200);

    let logs: Vec<MessageLog> = s.message_logs.iter().rev().take(limit).cloned().collect();
    let total = s.message_logs.len();

    HttpResponse::Ok().json(MessageLogsResponse { logs, total })
}

// 피어 상세 API
async fn api_peer_detail(state: web::Data<SharedState>, path: web::Path<String>) -> HttpResponse {
    let peer_id = path.into_inner();
    let s = state.read();

    // 피어가 속한 스웜 찾기
    let mut swarms_list = Vec::new();
    let mut peer_info: Option<&Peer> = None;

    for (info_hash, swarm) in s.swarms.iter() {
        if let Some(peer) = swarm.peers.get(&peer_id) {
            swarms_list.push(info_hash.clone());
            if peer_info.is_none() {
                peer_info = Some(peer);
            }
        }
    }

    if let Some(peer) = peer_info {
        let conn = s.peer_connections.get(&peer_id);

        let response = PeerDetailResponse {
            peer_id: peer.peer_id.clone(),
            ip: peer.ip.clone(),
            isp: peer.geo.as_org.clone(),
            country: peer.geo.country.clone(),
            swarms: swarms_list,
            offers_sent: peer.offers_sent,
            answers_sent: peer.answers_sent,
            connected_peers: conn.map(|c| c.connected_peers.clone()).unwrap_or_default(),
            offers_sent_to: conn.map(|c| c.offers_sent_to.clone()).unwrap_or_default(),
            answers_received_from: conn.map(|c| c.answers_received_from.clone()).unwrap_or_default(),
        };

        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::NotFound().json(serde_json::json!({"error": "Peer not found"}))
    }
}

// 연결 관계 API
async fn api_connections(state: web::Data<SharedState>, query: web::Query<HashMap<String, String>>) -> HttpResponse {
    let s = state.read();

    let limit = query.get("limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .min(500);

    // peer_connections에서 연결 정보 추출
    let mut connections: Vec<ConnectionInfo> = Vec::new();

    for (peer_id, conn) in s.peer_connections.iter() {
        // peer의 ISP 정보 찾기
        let from_isp = s.swarms.values()
            .find_map(|swarm| swarm.peers.get(peer_id))
            .map(|p| p.geo.as_org.clone())
            .unwrap_or_default();

        for (to_peer, offer_count) in &conn.offers_sent_to {
            let to_isp = s.swarms.values()
                .find_map(|swarm| swarm.peers.get(to_peer))
                .map(|p| p.geo.as_org.clone())
                .unwrap_or_default();

            let answer_count = conn.answers_received_from.get(to_peer).copied().unwrap_or(0);

            connections.push(ConnectionInfo {
                from_peer: peer_id.clone(),
                to_peer: to_peer.clone(),
                from_isp: from_isp.clone(),
                to_isp,
                offer_count: *offer_count,
                answer_count,
            });

            if connections.len() >= limit {
                break;
            }
        }

        if connections.len() >= limit {
            break;
        }
    }

    // offer_count 기준 정렬 (많이 연결된 순)
    connections.sort_by(|a, b| b.offer_count.cmp(&a.offer_count));

    let total = connections.len();
    HttpResponse::Ok().json(ConnectionsResponse { connections, total })
}

async fn api_health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// ============================================================
// 백그라운드 태스크: 타임아웃 피어/Offer 정리
// ============================================================

async fn cleanup_task(state: SharedState) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(CLEANUP_INTERVAL_SECS));

    loop {
        interval.tick().await;

        let now = now_ms();

        let mut s = state.write();

        // 타임아웃된 피어 및 만료된 offer 정리
        let mut peers_removed = 0u64;
        let mut offers_expired = 0u64;

        for swarm in s.swarms.values_mut() {
            // 만료된 expecting_answers 정리
            for peer in swarm.peers.values_mut() {
                let before = peer.expecting_answers.len();
                peer.expecting_answers.retain(|_, valid_until| *valid_until > now);
                offers_expired += (before - peer.expecting_answers.len()) as u64;
            }

            // 타임아웃된 피어 제거
            let before = swarm.peers.len();
            swarm.peers.retain(|_, peer| {
                let keep = peer.valid_until > now;
                if !keep && peer.is_seeder {
                    swarm.num_seeders = swarm.num_seeders.saturating_sub(1);
                }
                keep
            });
            peers_removed += (before - swarm.peers.len()) as u64;
        }

        // 빈 스웜 제거
        s.swarms.retain(|_, swarm| !swarm.peers.is_empty());

        s.total_answers_expired += offers_expired;

        log::debug!(
            "Cleanup: {} peers removed, {} offers expired, {} swarms, {} sockets",
            peers_removed,
            offers_expired,
            s.swarms.len(),
            s.sockets.len()
        );
    }
}

// ============================================================
// 메인
// ============================================================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let state = Arc::new(RwLock::new(TrackerState {
        start_time: now_secs(),
        ..Default::default()
    }));

    // 백그라운드 정리 태스크 시작
    let cleanup_state = state.clone();
    tokio::spawn(async move {
        cleanup_task(cleanup_state).await;
    });

    // SSL 설정 (Cloudflare Origin Certificate)
    let cert_path = "certs/cert.pem";
    let key_path = "certs/key.pem";

    let tls_config = if std::path::Path::new(cert_path).exists() {
        let cert_file = std::fs::File::open(cert_path)?;
        let key_file = std::fs::File::open(key_path)?;

        let cert_chain: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
            .filter_map(|r| r.ok())
            .collect();

        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
            .expect("No private key found");

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("Failed to build TLS config");

        Some(config)
    } else {
        log::warn!("SSL certificates not found, running without TLS");
        None
    };

    let bind_addr = "0.0.0.0:2053";
    log::info!("Starting tracker on {} (Aquatic-enhanced)", bind_addr);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .wrap(middleware::Logger::default())
            .wrap(
                middleware::DefaultHeaders::new()
                    .add(("Access-Control-Allow-Origin", "*"))
                    .add(("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
                    .add(("Access-Control-Allow-Headers", "Content-Type"))
            )
            // WebSocket (트래커)
            .route("/", web::get().to(ws_handler))
            .route("/announce", web::get().to(ws_handler))
            // HTTP API (모니터링)
            .route("/api/stats", web::get().to(api_stats))
            .route("/api/swarms", web::get().to(api_swarms))
            .route("/api/swarm/{info_hash}", web::get().to(api_swarm_detail))
            .route("/api/isps", web::get().to(api_isps))
            .route("/api/countries", web::get().to(api_countries))
            .route("/api/cities", web::get().to(api_cities))
            .route("/api/logs", web::get().to(api_logs))
            .route("/api/peer/{peer_id}", web::get().to(api_peer_detail))
            .route("/api/connections", web::get().to(api_connections))
            .route("/api/health", web::get().to(api_health))
    })
    .workers(num_cpus::get());

    if let Some(tls) = tls_config {
        server.bind_rustls_0_23(bind_addr, tls)?.run().await
    } else {
        server.bind(bind_addr)?.run().await
    }
}

// ============================================================
// 테스트
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn make_peer(id: &str, asn: u32, city: &str, country: &str) -> Peer {
        Peer {
            peer_id: id.to_string(),
            socket_id: 0,
            ip: "127.0.0.1".to_string(),
            geo: GeoData {
                country: country.to_string(),
                city: city.to_string(),
                asn,
                as_org: format!("ASN{}", asn),
            },
            valid_until: 9999999999999,
            is_seeder: false,
            offers_sent: 0,
            offers_received: 0,
            answers_sent: 0,
            expecting_answers: IndexMap::new(),
        }
    }

    #[test]
    fn test_peer_selection_priority() {
        // 테스트 피어 생성
        let mut peers: IndexMap<String, Peer> = IndexMap::new();

        // 1. 같은 ISP + 같은 도시 (SKT, Seoul)
        peers.insert("peer_isp_city_1".into(), make_peer("peer_isp_city_1", 4766, "Seoul", "KR"));
        peers.insert("peer_isp_city_2".into(), make_peer("peer_isp_city_2", 4766, "Seoul", "KR"));

        // 2. 같은 ISP, 다른 도시 (SKT, Busan)
        peers.insert("peer_isp_1".into(), make_peer("peer_isp_1", 4766, "Busan", "KR"));
        peers.insert("peer_isp_2".into(), make_peer("peer_isp_2", 4766, "Incheon", "KR"));

        // 3. 다른 ISP, 같은 도시 (KT, Seoul)
        peers.insert("peer_city_1".into(), make_peer("peer_city_1", 4670, "Seoul", "KR"));
        peers.insert("peer_city_2".into(), make_peer("peer_city_2", 9318, "Seoul", "KR"));

        // 4. 같은 국가, 다른 도시 (LGU+, Daegu)
        peers.insert("peer_country_1".into(), make_peer("peer_country_1", 3786, "Daegu", "KR"));
        peers.insert("peer_country_2".into(), make_peer("peer_country_2", 3786, "Gwangju", "KR"));

        // 5. 해외 (US)
        peers.insert("peer_foreign_1".into(), make_peer("peer_foreign_1", 7922, "New York", "US"));
        peers.insert("peer_foreign_2".into(), make_peer("peer_foreign_2", 16509, "Seattle", "US"));

        // 발신자: SKT, Seoul
        let sender_geo = GeoData {
            country: "KR".to_string(),
            city: "Seoul".to_string(),
            asn: 4766,
            as_org: "SK Telecom".to_string(),
        };

        // 5개만 요청
        let result = extract_response_peers(&peers, 5, "sender", &sender_geo);

        println!("\n=== 피어 선택 결과 (5개 요청) ===");
        for (i, peer) in result.iter().enumerate() {
            println!("{}. {} - ASN:{}, City:{}, Country:{}",
                i + 1, peer.peer_id, peer.geo.asn, peer.geo.city, peer.geo.country);
        }

        // 검증: 처음 2개는 ISP+City, 다음 2개는 같은 ISP
        assert_eq!(result.len(), 5);

        // 1-2번: 같은 ISP + 같은 도시
        let first_two: Vec<&str> = result[0..2].iter().map(|p| p.peer_id.as_str()).collect();
        assert!(first_two.iter().all(|id| id.starts_with("peer_isp_city")),
            "처음 2개는 ISP+City여야 함: {:?}", first_two);

        // 3-4번: 같은 ISP (다른 도시)
        let next_two: Vec<&str> = result[2..4].iter().map(|p| p.peer_id.as_str()).collect();
        assert!(next_two.iter().all(|id| id.starts_with("peer_isp_")),
            "3-4번은 같은 ISP여야 함: {:?}", next_two);

        // 5번: 같은 도시 (다른 ISP)
        assert!(result[4].peer_id.starts_with("peer_city"),
            "5번은 같은 도시여야 함: {}", result[4].peer_id);

        println!("\n✅ 우선순위 테스트 통과!");
    }

    #[test]
    fn test_peer_selection_all_tiers() {
        let mut peers: IndexMap<String, Peer> = IndexMap::new();

        // 각 티어별 1개씩만
        peers.insert("peer_isp_city".into(), make_peer("peer_isp_city", 4766, "Seoul", "KR"));
        peers.insert("peer_isp".into(), make_peer("peer_isp", 4766, "Busan", "KR"));
        peers.insert("peer_city".into(), make_peer("peer_city", 4670, "Seoul", "KR"));
        peers.insert("peer_country".into(), make_peer("peer_country", 3786, "Daegu", "KR"));
        peers.insert("peer_foreign".into(), make_peer("peer_foreign", 7922, "NYC", "US"));

        let sender_geo = GeoData {
            country: "KR".to_string(),
            city: "Seoul".to_string(),
            asn: 4766,
            as_org: "SK Telecom".to_string(),
        };

        // 10개 요청 (5개만 있음)
        let result = extract_response_peers(&peers, 10, "sender", &sender_geo);

        println!("\n=== 전체 티어 테스트 ===");
        for (i, peer) in result.iter().enumerate() {
            println!("{}. {} - ASN:{}, City:{}, Country:{}",
                i + 1, peer.peer_id, peer.geo.asn, peer.geo.city, peer.geo.country);
        }

        assert_eq!(result.len(), 5);

        // 순서 검증 (셔플이 있어서 같은 티어 내 순서는 랜덤)
        let ids: Vec<&str> = result.iter().map(|p| p.peer_id.as_str()).collect();

        // ISP+City가 첫 번째
        assert_eq!(ids[0], "peer_isp_city", "1번은 ISP+City");
        // 같은 ISP가 두 번째
        assert_eq!(ids[1], "peer_isp", "2번은 같은 ISP");
        // 같은 도시가 세 번째
        assert_eq!(ids[2], "peer_city", "3번은 같은 도시");
        // 같은 국가가 네 번째
        assert_eq!(ids[3], "peer_country", "4번은 같은 국가");
        // 해외가 마지막
        assert_eq!(ids[4], "peer_foreign", "5번은 해외");

        println!("\n✅ 전체 티어 테스트 통과!");
    }

    #[test]
    fn test_shuffle_distribution() {
        let mut peers: IndexMap<String, Peer> = IndexMap::new();

        // 같은 ISP 피어 10개
        for i in 0..10 {
            let id = format!("peer_{}", i);
            peers.insert(id.clone(), make_peer(&id, 4766, "Seoul", "KR"));
        }

        let sender_geo = GeoData {
            country: "KR".to_string(),
            city: "Seoul".to_string(),
            asn: 4766,
            as_org: "SK Telecom".to_string(),
        };

        // 여러 번 실행해서 셔플 확인
        let mut first_selections: std::collections::HashMap<String, u32> = std::collections::HashMap::new();

        for _ in 0..100 {
            let result = extract_response_peers(&peers, 3, "sender", &sender_geo);
            if let Some(first) = result.first() {
                *first_selections.entry(first.peer_id.clone()).or_insert(0) += 1;
            }
        }

        println!("\n=== 셔플 분포 테스트 (100회) ===");
        for (id, count) in &first_selections {
            println!("{}: {}회 ({}%)", id, count, count);
        }

        // 최소 3개 이상의 다른 피어가 첫 번째로 선택되어야 함 (셔플 작동 확인)
        assert!(first_selections.len() >= 3,
            "셔플이 작동하면 여러 피어가 선택되어야 함. 현재: {}개", first_selections.len());

        println!("\n✅ 셔플 분포 테스트 통과!");
    }
}
