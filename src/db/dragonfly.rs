use redis::{AsyncCommands, aio::ConnectionManager, Client};

pub struct DragonflyClient {
    conn_manager: Option<ConnectionManager>,
}

impl DragonflyClient {
    pub async fn new() -> Self {
        let conn_manager = match Client::open("redis://127.0.0.1:6379") {
            Ok(client) => {
                match ConnectionManager::new(client).await {
                    Ok(cm) => Some(cm),
                    Err(e) => {
                        tracing::warn!("Dragonfly 연결 실패: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Dragonfly 클라이언트 생성 실패: {}", e);
                None
            }
        };

        Self { conn_manager }
    }

    /// 캐시 가져오기
    pub async fn get_cache(&self, key: &str) -> Option<String> {
        if let Some(ref cm) = self.conn_manager {
            let mut conn = cm.clone();
            match conn.get::<_, Option<String>>(key).await {
                Ok(value) => return value,
                Err(e) => {
                    tracing::debug!("캐시 조회 실패: {}", e);
                }
            }
        }
        None
    }

    /// 캐시 저장
    pub async fn set_cache(&self, key: &str, value: &str, ttl_secs: u64) {
        if let Some(ref cm) = self.conn_manager {
            let mut conn = cm.clone();
            if let Err(e) = conn.set_ex::<_, _, ()>(key, value, ttl_secs).await {
                tracing::debug!("캐시 저장 실패: {}", e);
            }
        }
    }

    /// 연결 상태 확인
    pub fn is_connected(&self) -> bool {
        self.conn_manager.is_some()
    }
}
