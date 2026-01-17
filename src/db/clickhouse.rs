use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

pub struct ClickHouseClient {
    client: Client,
    tx: mpsc::UnboundedSender<EventRow>,
}

impl ClickHouseClient {
    pub async fn new() -> Self {
        let client = Client::default()
            .with_url("http://127.0.0.1:8123")
            .with_database("p2p_stats")
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "0");

        let client_clone = client.clone();
        let (tx, mut rx) = mpsc::unbounded_channel::<EventRow>();

        // 백그라운드 배치 삽입 태스크
        tokio::spawn(async move {
            let mut buffer: Vec<EventRow> = Vec::with_capacity(1000);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    // 이벤트 수신
                    Some(event) = rx.recv() => {
                        buffer.push(event);
                        // 버퍼가 가득 차면 즉시 플러시
                        if buffer.len() >= 500 {
                            if let Err(e) = flush_buffer(&client_clone, &mut buffer).await {
                                tracing::warn!("ClickHouse 배치 삽입 실패: {}", e);
                            }
                        }
                    }
                    // 주기적 플러시 (5초)
                    _ = interval.tick() => {
                        if !buffer.is_empty() {
                            if let Err(e) = flush_buffer(&client_clone, &mut buffer).await {
                                tracing::warn!("ClickHouse 주기적 삽입 실패: {}", e);
                            }
                        }
                    }
                }
            }
        });

        Self { client, tx }
    }

    /// 이벤트 삽입 (비동기 - 즉시 반환)
    pub async fn insert_event(&self, event: EventRow) -> Result<(), clickhouse::error::Error> {
        let _ = self.tx.send(event);
        Ok(())
    }

    /// 인기 콘텐츠 조회
    pub async fn get_top(
        &self,
        limit: u32,
        offset: u32,
        period: &str,
    ) -> Result<(Vec<TopItem>, u64), clickhouse::error::Error> {
        let time_filter = match period {
            "daily" => "AND timestamp > now() - INTERVAL 1 DAY",
            "weekly" => "AND timestamp > now() - INTERVAL 7 DAY",
            "monthly" => "AND timestamp > now() - INTERVAL 30 DAY",
            _ => "",
        };

        // 총 개수
        let count_query = format!(
            "SELECT count(DISTINCT swarm_id) as total FROM events WHERE length(filename) > 0 {}",
            time_filter
        );
        let total: u64 = self.client
            .query(&count_query)
            .fetch_one::<CountRow>()
            .await
            .map(|r| r.total)
            .unwrap_or(0);

        // 데이터
        let query = format!(
            r#"
            SELECT
                swarm_id,
                anyLast(filename) as filename,
                count(DISTINCT session_id) as views,
                sum(http_bytes) as http_bytes,
                sum(p2p_bytes) as p2p_bytes
            FROM events
            WHERE length(filename) > 0 {}
            GROUP BY swarm_id
            ORDER BY views DESC
            LIMIT {} OFFSET {}
            "#,
            time_filter, limit, offset
        );

        let data = self.client
            .query(&query)
            .fetch_all::<TopItem>()
            .await
            .unwrap_or_default();

        Ok((data, total))
    }

    /// 시간별 통계
    pub async fn get_hourly(&self) -> Result<Vec<HourlyStats>, clickhouse::error::Error> {
        let query = r#"
            SELECT
                toStartOfHour(timestamp, 'Asia/Seoul') as hour,
                count() as sessions,
                sum(http_bytes) as http_bytes,
                sum(p2p_bytes) as p2p_bytes
            FROM events
            WHERE timestamp > now() - INTERVAL 24 HOUR
            GROUP BY hour
            ORDER BY hour
        "#;

        self.client.query(query).fetch_all().await
    }

    /// 일별 통계
    pub async fn get_daily(&self) -> Result<Vec<DailyStats>, clickhouse::error::Error> {
        let query = r#"
            SELECT
                toDate(timestamp, 'Asia/Seoul') as date,
                count() as sessions,
                sum(http_bytes) as http_bytes,
                sum(p2p_bytes) as p2p_bytes
            FROM events
            WHERE timestamp > now() - INTERVAL 30 DAY
            GROUP BY date
            ORDER BY date
        "#;

        self.client.query(query).fetch_all().await
    }

    /// 월별 통계
    pub async fn get_monthly(&self) -> Result<Vec<MonthlyStats>, clickhouse::error::Error> {
        let query = r#"
            SELECT
                toStartOfMonth(timestamp, 'Asia/Seoul') as month,
                count() as sessions,
                sum(http_bytes) as http_bytes,
                sum(p2p_bytes) as p2p_bytes
            FROM events
            WHERE timestamp > now() - INTERVAL 12 MONTH
            GROUP BY month
            ORDER BY month
        "#;

        self.client.query(query).fetch_all().await
    }
}

async fn flush_buffer(client: &Client, buffer: &mut Vec<EventRow>) -> Result<(), clickhouse::error::Error> {
    if buffer.is_empty() {
        return Ok(());
    }

    let mut insert = client.insert("events")?;
    for event in buffer.drain(..) {
        insert.write(&event).await?;
    }
    insert.end().await?;
    Ok(())
}

#[derive(Row, Deserialize)]
struct CountRow {
    total: u64,
}

#[derive(Row, Serialize, Deserialize)]
pub struct TopItem {
    pub swarm_id: String,
    pub filename: String,
    pub views: u64,
    pub http_bytes: u64,
    pub p2p_bytes: u64,
}

#[derive(Row, Serialize, Deserialize)]
pub struct HourlyStats {
    pub hour: String,
    pub sessions: u64,
    pub http_bytes: u64,
    pub p2p_bytes: u64,
}

#[derive(Row, Serialize, Deserialize)]
pub struct DailyStats {
    pub date: String,
    pub sessions: u64,
    pub http_bytes: u64,
    pub p2p_bytes: u64,
}

#[derive(Row, Serialize, Deserialize)]
pub struct MonthlyStats {
    pub month: String,
    pub sessions: u64,
    pub http_bytes: u64,
    pub p2p_bytes: u64,
}

/// 이벤트 저장용 구조체
#[derive(Row, Serialize, Deserialize, Clone)]
pub struct EventRow {
    pub session_id: String,
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
    pub timestamp: i64,
}
