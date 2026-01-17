use dashmap::DashMap;
use parking_lot::RwLock;
use serde::Deserialize;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};

// 고성능을 위한 샤드 수 (CPU 코어 * 4)
const SHARD_COUNT: usize = 128;

/// 세션 정보 (메모리 최적화)
#[derive(Debug, Clone, Default)]
pub struct Session {
    pub swarm_id: String,
    pub player_id: u8,
    pub filename: String,
    pub server: String,
    pub referrer: String,
    pub device: String,
    pub device_name: String,
    pub net_type: String,
    pub browser: String,
    pub ip: String,
    pub http_bytes: u64,
    pub p2p_bytes: u64,
    pub p2p_up_bytes: u64,
    pub peers: u32,
    pub initialized: bool,
}

/// Swarm 통계
#[derive(Debug, Default)]
pub struct SwarmStats {
    pub viewers: AtomicI64,
    pub http_bytes: AtomicU64,
    pub p2p_bytes: AtomicU64,
    pub filename: RwLock<String>,
}

/// 플레이어 통계
#[derive(Debug, Default)]
pub struct PlayerStats {
    pub viewers: AtomicI64,
    pub http_bytes: AtomicU64,
    pub p2p_bytes: AtomicU64,
    pub p2p_up_bytes: AtomicU64,
}

/// 전체 실시간 통계
pub struct RealtimeStats {
    // 세션 관리
    pub sessions: DashMap<String, Session>,

    // 전체 통계
    pub total_viewers: AtomicI64,
    pub total_http_bytes: AtomicU64,
    pub total_p2p_bytes: AtomicU64,
    pub total_p2p_up_bytes: AtomicU64,
    pub total_peers: AtomicI64,

    // Swarm별 통계
    pub swarms: DashMap<String, SwarmStats>,

    // 플레이어별 통계
    pub player1: PlayerStats,
    pub player2: PlayerStats,

    // 디바이스 통계
    pub devices: DashMap<String, AtomicI64>,

    // 네트워크 통계
    pub networks: DashMap<String, AtomicI64>,

    // 브라우저 통계
    pub browsers: DashMap<String, AtomicI64>,

    // 리퍼러 통계
    pub referrers: DashMap<String, AtomicI64>,

    // 서버별 통계
    pub servers: DashMap<String, AtomicI64>,
    pub server_traffic: DashMap<String, ServerTraffic>,
}

#[derive(Debug, Default)]
pub struct ServerTraffic {
    pub viewers: AtomicI64,
    pub http_bytes: AtomicU64,
    pub p2p_bytes: AtomicU64,
}

impl RealtimeStats {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::with_shard_amount(SHARD_COUNT),
            total_viewers: AtomicI64::new(0),
            total_http_bytes: AtomicU64::new(0),
            total_p2p_bytes: AtomicU64::new(0),
            total_p2p_up_bytes: AtomicU64::new(0),
            total_peers: AtomicI64::new(0),
            swarms: DashMap::with_shard_amount(64),
            player1: PlayerStats::default(),
            player2: PlayerStats::default(),
            devices: DashMap::with_shard_amount(4),
            networks: DashMap::with_shard_amount(4),
            browsers: DashMap::with_shard_amount(16),
            referrers: DashMap::with_shard_amount(32),
            servers: DashMap::with_shard_amount(16),
            server_traffic: DashMap::with_shard_amount(16),
        }
    }

    /// 세션 초기화 (init 메시지)
    pub fn init_session(&self, session_id: &str, msg: &InitMessage) {
        // 이미 초기화된 세션이면 무시
        if let Some(session) = self.sessions.get(session_id) {
            if session.initialized {
                return;
            }
        }

        let session = Session {
            swarm_id: msg.swarm_id.clone(),
            player_id: msg.player_id,
            filename: msg.filename.clone(),
            server: msg.server.clone(),
            referrer: msg.referrer.clone(),
            device: msg.device.clone(),
            device_name: msg.device_name.clone(),
            net_type: msg.net_type.clone(),
            browser: msg.browser.clone(),
            ip: msg.ip.clone(),
            initialized: true,
            ..Default::default()
        };

        self.sessions.insert(session_id.to_string(), session.clone());

        // 전체 통계 증가
        self.total_viewers.fetch_add(1, Ordering::Relaxed);

        // Swarm 통계
        self.swarms
            .entry(msg.swarm_id.clone())
            .or_insert_with(|| {
                let s = SwarmStats::default();
                *s.filename.write() = msg.filename.clone();
                s
            })
            .viewers
            .fetch_add(1, Ordering::Relaxed);

        // 플레이어 통계
        match msg.player_id {
            1 => self.player1.viewers.fetch_add(1, Ordering::Relaxed),
            2 => self.player2.viewers.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };

        // 디바이스 통계
        let device_type = Self::classify_device(&msg.device);
        self.devices
            .entry(device_type)
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // 네트워크 통계
        self.networks
            .entry(msg.net_type.to_lowercase())
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // 브라우저 통계
        self.browsers
            .entry(msg.browser.clone())
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // 리퍼러 통계
        let referrer_host = Self::extract_host(&msg.referrer);
        self.referrers
            .entry(referrer_host)
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        // 서버 통계
        let server_key = if msg.server.is_empty() { "unknown".to_string() } else { msg.server.clone() };
        self.servers
            .entry(server_key.clone())
            .or_insert_with(|| AtomicI64::new(0))
            .fetch_add(1, Ordering::Relaxed);

        self.server_traffic
            .entry(server_key)
            .or_insert_with(ServerTraffic::default)
            .viewers
            .fetch_add(1, Ordering::Relaxed);
    }

    /// 통계 업데이트 (stats 메시지)
    pub fn update_stats(&self, session_id: &str, msg: &StatsMessage) {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            let h_delta = msg.http_bytes.saturating_sub(session.http_bytes);
            let p_delta = msg.p2p_bytes.saturating_sub(session.p2p_bytes);
            let u_delta = msg.p2p_up_bytes.saturating_sub(session.p2p_up_bytes);
            let peer_delta = msg.peers as i64 - session.peers as i64;

            // 세션 업데이트
            session.http_bytes = msg.http_bytes;
            session.p2p_bytes = msg.p2p_bytes;
            session.p2p_up_bytes = msg.p2p_up_bytes;
            session.peers = msg.peers;

            // 전체 통계
            if h_delta > 0 {
                self.total_http_bytes.fetch_add(h_delta, Ordering::Relaxed);
            }
            if p_delta > 0 {
                self.total_p2p_bytes.fetch_add(p_delta, Ordering::Relaxed);
            }
            if u_delta > 0 {
                self.total_p2p_up_bytes.fetch_add(u_delta, Ordering::Relaxed);
            }
            self.total_peers.fetch_add(peer_delta, Ordering::Relaxed);

            // Swarm 통계
            if let Some(swarm) = self.swarms.get(&session.swarm_id) {
                if h_delta > 0 {
                    swarm.http_bytes.fetch_add(h_delta, Ordering::Relaxed);
                }
                if p_delta > 0 {
                    swarm.p2p_bytes.fetch_add(p_delta, Ordering::Relaxed);
                }
            }

            // 플레이어 통계
            let player = match session.player_id {
                1 => Some(&self.player1),
                2 => Some(&self.player2),
                _ => None,
            };
            if let Some(p) = player {
                if h_delta > 0 {
                    p.http_bytes.fetch_add(h_delta, Ordering::Relaxed);
                }
                if p_delta > 0 {
                    p.p2p_bytes.fetch_add(p_delta, Ordering::Relaxed);
                }
            }

            // 서버 트래픽
            let server_key = if session.server.is_empty() { "unknown" } else { &session.server };
            if let Some(st) = self.server_traffic.get(server_key) {
                if h_delta > 0 {
                    st.http_bytes.fetch_add(h_delta, Ordering::Relaxed);
                }
                if p_delta > 0 {
                    st.p2p_bytes.fetch_add(p_delta, Ordering::Relaxed);
                }
            }
        }
    }

    /// 세션 종료
    pub fn close_session(&self, session_id: &str) {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            if !session.initialized {
                return;
            }

            // 전체 통계 감소
            self.total_viewers.fetch_sub(1, Ordering::Relaxed);
            self.total_peers.fetch_sub(session.peers as i64, Ordering::Relaxed);

            // Swarm 통계
            if let Some(swarm) = self.swarms.get(&session.swarm_id) {
                let viewers = swarm.viewers.fetch_sub(1, Ordering::Relaxed);
                if viewers <= 1 {
                    self.swarms.remove(&session.swarm_id);
                }
            }

            // 플레이어 통계
            match session.player_id {
                1 => self.player1.viewers.fetch_sub(1, Ordering::Relaxed),
                2 => self.player2.viewers.fetch_sub(1, Ordering::Relaxed),
                _ => 0,
            };

            // 디바이스 통계
            let device_type = Self::classify_device(&session.device);
            if let Some(d) = self.devices.get(&device_type) {
                d.fetch_sub(1, Ordering::Relaxed);
            }

            // 네트워크 통계
            if let Some(n) = self.networks.get(&session.net_type.to_lowercase()) {
                n.fetch_sub(1, Ordering::Relaxed);
            }

            // 브라우저 통계
            if let Some(b) = self.browsers.get(&session.browser) {
                let count = b.fetch_sub(1, Ordering::Relaxed);
                if count <= 1 {
                    self.browsers.remove(&session.browser);
                }
            }

            // 리퍼러 통계
            let referrer_host = Self::extract_host(&session.referrer);
            if let Some(r) = self.referrers.get(&referrer_host) {
                let count = r.fetch_sub(1, Ordering::Relaxed);
                if count <= 1 {
                    self.referrers.remove(&referrer_host);
                }
            }

            // 서버 통계
            let server_key = if session.server.is_empty() { "unknown".to_string() } else { session.server.clone() };
            if let Some(s) = self.servers.get(&server_key) {
                let count = s.fetch_sub(1, Ordering::Relaxed);
                if count <= 1 {
                    self.servers.remove(&server_key);
                }
            }
            if let Some(st) = self.server_traffic.get(&server_key) {
                st.viewers.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }

    fn classify_device(device: &str) -> String {
        let d = device.to_lowercase();
        if d.contains("mobile") || d.contains("phone") {
            "mobile".to_string()
        } else if d.contains("tablet") || d.contains("ipad") {
            "tablet".to_string()
        } else if d.contains("pc") || d.contains("desktop") || d.contains("web") {
            "desktop".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn extract_host(referrer: &str) -> String {
        url::Url::parse(referrer)
            .map(|u| u.host_str().unwrap_or("direct").to_string())
            .unwrap_or_else(|_| "direct".to_string())
    }

    /// API 응답용 JSON
    pub fn to_json(&self) -> serde_json::Value {
        let total_http = self.total_http_bytes.load(Ordering::Relaxed);
        let total_p2p = self.total_p2p_bytes.load(Ordering::Relaxed);
        let total = total_http + total_p2p;
        let p2p_ratio = if total > 0 {
            format!("{:.1}", (total_p2p as f64 / total as f64) * 100.0)
        } else {
            "0.0".to_string()
        };

        let p1_http = self.player1.http_bytes.load(Ordering::Relaxed);
        let p1_p2p = self.player1.p2p_bytes.load(Ordering::Relaxed);
        let p1_total = p1_http + p1_p2p;
        let p1_ratio = if p1_total > 0 {
            format!("{:.1}", (p1_p2p as f64 / p1_total as f64) * 100.0)
        } else {
            "0.0".to_string()
        };

        let p2_http = self.player2.http_bytes.load(Ordering::Relaxed);
        let p2_p2p = self.player2.p2p_bytes.load(Ordering::Relaxed);
        let p2_total = p2_http + p2_p2p;
        let p2_ratio = if p2_total > 0 {
            format!("{:.1}", (p2_p2p as f64 / p2_total as f64) * 100.0)
        } else {
            "0.0".to_string()
        };

        // Top referrers
        let mut referrers: Vec<_> = self.referrers.iter()
            .map(|r| (r.key().clone(), r.value().load(Ordering::Relaxed)))
            .collect();
        referrers.sort_by(|a, b| b.1.cmp(&a.1));
        referrers.truncate(10);

        // Top browsers
        let mut browsers: Vec<_> = self.browsers.iter()
            .map(|b| (b.key().clone(), b.value().load(Ordering::Relaxed)))
            .collect();
        browsers.sort_by(|a, b| b.1.cmp(&a.1));
        browsers.truncate(10);

        // Server traffic
        let mut server_traffic: Vec<_> = self.server_traffic.iter()
            .map(|s| {
                let http = s.http_bytes.load(Ordering::Relaxed);
                let p2p = s.p2p_bytes.load(Ordering::Relaxed);
                let total = http + p2p;
                let ratio = if total > 0 {
                    format!("{:.1}", (p2p as f64 / total as f64) * 100.0)
                } else {
                    "0.0".to_string()
                };
                serde_json::json!({
                    "name": s.key().clone(),
                    "viewers": s.viewers.load(Ordering::Relaxed),
                    "httpBytes": http,
                    "p2pBytes": p2p,
                    "totalBytes": total,
                    "p2pRatio": ratio
                })
            })
            .collect();
        server_traffic.sort_by(|a, b| {
            b["totalBytes"].as_u64().cmp(&a["totalBytes"].as_u64())
        });

        serde_json::json!({
            "total": {
                "viewers": self.total_viewers.load(Ordering::Relaxed),
                "httpBytes": total_http,
                "p2pBytes": total_p2p,
                "p2pUpBytes": self.total_p2p_up_bytes.load(Ordering::Relaxed),
                "peers": self.total_peers.load(Ordering::Relaxed),
                "p2pRatio": p2p_ratio
            },
            "player1": {
                "viewers": self.player1.viewers.load(Ordering::Relaxed),
                "httpBytes": p1_http,
                "p2pBytes": p1_p2p,
                "p2pUpBytes": self.player1.p2p_up_bytes.load(Ordering::Relaxed),
                "p2pRatio": p1_ratio
            },
            "player2": {
                "viewers": self.player2.viewers.load(Ordering::Relaxed),
                "httpBytes": p2_http,
                "p2pBytes": p2_p2p,
                "p2pUpBytes": self.player2.p2p_up_bytes.load(Ordering::Relaxed),
                "p2pRatio": p2_ratio
            },
            "activeSwarms": self.swarms.len(),
            "devices": {
                "mobile": self.devices.get("mobile").map(|d| d.load(Ordering::Relaxed)).unwrap_or(0),
                "desktop": self.devices.get("desktop").map(|d| d.load(Ordering::Relaxed)).unwrap_or(0),
                "tablet": self.devices.get("tablet").map(|d| d.load(Ordering::Relaxed)).unwrap_or(0),
                "unknown": self.devices.get("unknown").map(|d| d.load(Ordering::Relaxed)).unwrap_or(0)
            },
            "browsers": browsers.iter().map(|(k, v)| serde_json::json!({"name": k, "count": v})).collect::<Vec<_>>(),
            "referrers": referrers.iter().map(|(k, v)| serde_json::json!({"name": k, "count": v})).collect::<Vec<_>>(),
            "serverTraffic": server_traffic
        })
    }
}

// 메시지 타입 (클라이언트는 camelCase 사용)
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitMessage {
    pub swarm_id: String,
    #[serde(default)]
    pub player_id: u8,
    #[serde(default)]
    pub filename: String,
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub referrer: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub device_name: String,
    #[serde(default)]
    pub net_type: String,
    #[serde(default)]
    pub browser: String,
    #[serde(default)]
    pub ip: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatsMessage {
    #[serde(default)]
    pub http_bytes: u64,
    #[serde(default)]
    pub p2p_bytes: u64,
    #[serde(default)]
    pub p2p_up_bytes: u64,
    #[serde(default)]
    pub peers: u32,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum WsMessage {
    #[serde(rename = "init")]
    Init(InitMessage),
    #[serde(rename = "stats")]
    Stats(StatsMessage),
}
