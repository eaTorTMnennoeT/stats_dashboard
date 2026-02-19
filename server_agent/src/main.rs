use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::process::Command;
use std::thread;
use std::time::Duration;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, RefreshKind, System};

const REPORT_INTERVAL_SECS: u64 = 5;
const BLOCK_CHECK_INTERVAL_SECS: u64 = 10;
const NGINX_BLOCK_CONF: &str = "/etc/nginx/apiblack.conf";
const KST_OFFSET_HOURS: i64 = 9;

#[derive(Serialize)]
struct ServerReport {
    id: String,
    name: String,
    cpu: f64,
    memory_used: u64,
    memory_total: u64,
    rx_bytes: u64,
    tx_bytes: u64,
    connections: u64,
    uptime: u64,
}

#[derive(Deserialize, Debug)]
struct BlockCommand {
    ip: String,
    action: String,
    reason: String,
    timestamp: u64,
}

#[derive(Deserialize)]
struct PendingResponse {
    status: String,
    commands: Vec<BlockCommand>,
}

#[derive(Serialize)]
struct ConfirmRequest {
    server_id: String,
    ip: String,
    action: String,
    success: bool,
}

struct NetworkStats {
    rx_bytes: u64,
    tx_bytes: u64,
}

fn get_server_id() -> String {
    if let Ok(id) = fs::read_to_string("/etc/machine-id") {
        return id.trim().chars().take(12).collect();
    }
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_server_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_network_stats() -> NetworkStats {
    let mut rx_bytes = 0u64;
    let mut tx_bytes = 0u64;

    if let Ok(content) = fs::read_to_string("/proc/net/dev") {
        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 10 {
                let iface = parts[0].trim_end_matches(':');
                if iface != "lo" {
                    if let Ok(rx) = parts[1].parse::<u64>() {
                        rx_bytes += rx;
                    }
                    if let Ok(tx) = parts[9].parse::<u64>() {
                        tx_bytes += tx;
                    }
                }
            }
        }
    }

    NetworkStats { rx_bytes, tx_bytes }
}

fn get_tcp_connections() -> u64 {
    let mut count = 0u64;

    if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
        count += content.lines().count().saturating_sub(1) as u64;
    }
    if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
        count += content.lines().count().saturating_sub(1) as u64;
    }

    count
}

fn get_uptime() -> u64 {
    if let Ok(content) = fs::read_to_string("/proc/uptime") {
        if let Some(uptime_str) = content.split_whitespace().next() {
            if let Ok(uptime) = uptime_str.parse::<f64>() {
                return uptime as u64;
            }
        }
    }
    0
}

// IP가 이미 차단되어 있는지 확인
fn is_ip_blocked(ip: &str) -> bool {
    if let Ok(file) = fs::File::open(NGINX_BLOCK_CONF) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                // deny 1.2.3.4; 형식 체크
                if line.trim().starts_with("deny ") && line.contains(ip) {
                    return true;
                }
            }
        }
    }
    false
}

fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

fn block_ip(ip: &str, reason: &str) -> bool {
    if !is_valid_ip(ip) {
        eprintln!("[BLOCK] Invalid IP address: {}", ip);
        return false;
    }

    if is_ip_blocked(ip) {
        eprintln!("[BLOCK] {} already blocked, skipping", ip);
        return true;
    }

    // 파일이 없으면 생성
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(NGINX_BLOCK_CONF)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[BLOCK] Failed to open {}: {}", NGINX_BLOCK_CONF, e);
            return false;
        }
    };

    // 현재 시간 (KST)
    let now = chrono::Utc::now() + chrono::Duration::hours(KST_OFFSET_HOURS);
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();

    // deny IP; # 시간 - 사유
    let line = format!("deny {}; # {} - {}\n", ip, timestamp, reason);

    if let Err(e) = file.write_all(line.as_bytes()) {
        eprintln!("[BLOCK] Failed to write to {}: {}", NGINX_BLOCK_CONF, e);
        return false;
    }

    eprintln!("[BLOCK] Added {} to {}", ip, NGINX_BLOCK_CONF);

    // nginx reload
    reload_nginx()
}

fn unblock_ip(ip: &str) -> bool {
    if !is_valid_ip(ip) {
        eprintln!("[UNBLOCK] Invalid IP address: {}", ip);
        return false;
    }

    let content = match fs::read_to_string(NGINX_BLOCK_CONF) {
        Ok(c) => c,
        Err(_) => {
            eprintln!(
                "[UNBLOCK] {} not found, treating {} as already unblocked",
                NGINX_BLOCK_CONF, ip
            );
            return true;
        }
    };

    let new_content: String = content
        .lines()
        .filter(|line| {
            !line.contains(&format!("deny {};", ip)) && !line.contains(&format!("deny {} ;", ip))
        })
        .map(|line| format!("{}\n", line))
        .collect();

    if let Err(e) = fs::write(NGINX_BLOCK_CONF, new_content) {
        eprintln!("[UNBLOCK] Failed to write to {}: {}", NGINX_BLOCK_CONF, e);
        return false;
    }

    eprintln!("[UNBLOCK] Removed {} from {}", ip, NGINX_BLOCK_CONF);

    reload_nginx()
}

// nginx reload
fn reload_nginx() -> bool {
    match Command::new("nginx").args(["-s", "reload"]).output() {
        Ok(output) => {
            if output.status.success() {
                eprintln!("[NGINX] Reloaded successfully");
                true
            } else {
                eprintln!(
                    "[NGINX] Reload failed: {:?}",
                    String::from_utf8_lossy(&output.stderr)
                );
                false
            }
        }
        Err(e) => {
            eprintln!("[NGINX] Failed to execute reload: {}", e);
            false
        }
    }
}

// 대기 중인 차단 명령 폴링
fn poll_block_commands(
    server_url: &str,
    server_id: &str,
    last_timestamp: &mut u64,
    agent_secret: &Option<String>,
) {
    let url = format!(
        "{}/api/blacklist/pending?since={}",
        server_url, last_timestamp
    );

    let mut req = ureq::get(&url);
    if let Some(secret) = agent_secret {
        req = req.set("X-Agent-Secret", secret);
    }
    match req.call() {
        Ok(resp) => {
            if let Ok(data) = resp.into_json::<PendingResponse>() {
                if data.status == "ok" {
                    for cmd in data.commands {
                        eprintln!("[POLL] Command: {} {} ({})", cmd.action, cmd.ip, cmd.reason);

                        let success = if cmd.action == "block" {
                            block_ip(&cmd.ip, &cmd.reason)
                        } else if cmd.action == "unblock" {
                            unblock_ip(&cmd.ip)
                        } else {
                            eprintln!("[POLL] Unknown action: {}", cmd.action);
                            false
                        };

                        confirm_block(
                            server_url,
                            server_id,
                            &cmd.ip,
                            &cmd.action,
                            success,
                            agent_secret,
                        );

                        // 타임스탬프 업데이트
                        if cmd.timestamp > *last_timestamp {
                            *last_timestamp = cmd.timestamp;
                        }
                    }
                }
            } else {
                eprintln!("[POLL] Failed to parse response JSON");
            }
        }
        Err(e) => {
            eprintln!("[POLL] Error: {}", e);
        }
    }
}

// 차단 결과 확인 전송
fn confirm_block(
    server_url: &str,
    server_id: &str,
    ip: &str,
    action: &str,
    success: bool,
    agent_secret: &Option<String>,
) {
    let url = format!("{}/api/blacklist/confirm", server_url);
    let req = ConfirmRequest {
        server_id: server_id.to_string(),
        ip: ip.to_string(),
        action: action.to_string(),
        success,
    };

    if let Ok(body) = serde_json::to_string(&req) {
        let mut http_req = ureq::post(&url).set("Content-Type", "application/json");
        if let Some(secret) = agent_secret {
            http_req = http_req.set("X-Agent-Secret", secret);
        }
        match http_req.send_string(&body) {
            Ok(_) => eprintln!("[CONFIRM] {} {} success={}", action, ip, success),
            Err(e) => eprintln!("[CONFIRM] Error: {}", e),
        }
    } else {
        eprintln!(
            "[CONFIRM] Failed to serialize request for {} {}",
            action, ip
        );
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let server_url = if args.len() > 1 {
        args[1].clone()
    } else {
        eprintln!("Usage: server_agent <dashboard_url>");
        eprintln!("Example: server_agent http://37.27.122.163:8080");
        std::process::exit(1);
    };

    let report_url = format!("{}/api/servers/report", server_url);
    let server_id = get_server_id();
    let server_name = get_server_name();
    let agent_secret = std::env::var("AGENT_SECRET").ok();

    eprintln!("Server Agent started");
    eprintln!("  ID: {}", server_id);
    eprintln!("  Name: {}", server_name);
    eprintln!("  Report URL: {}", report_url);
    eprintln!("  Block conf: {}", NGINX_BLOCK_CONF);
    eprintln!("  Report interval: {}s", REPORT_INTERVAL_SECS);
    eprintln!("  Block check interval: {}s", BLOCK_CHECK_INTERVAL_SECS);

    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_cpu(CpuRefreshKind::everything())
            .with_memory(MemoryRefreshKind::everything()),
    );

    let mut prev_net = get_network_stats();
    let mut prev_time = std::time::Instant::now();
    let mut last_block_check = std::time::Instant::now();
    let mut last_block_timestamp: u64 = 0;

    loop {
        sys.refresh_cpu();
        thread::sleep(Duration::from_millis(200));
        sys.refresh_cpu();
        sys.refresh_memory();

        let cpu = sys.global_cpu_info().cpu_usage() as f64;
        let memory_used = sys.used_memory();
        let memory_total = sys.total_memory();

        let curr_net = get_network_stats();
        let elapsed = prev_time.elapsed().as_secs_f64();

        let rx_rate = if elapsed > 0.0 {
            ((curr_net.rx_bytes.saturating_sub(prev_net.rx_bytes)) as f64 / elapsed) as u64
        } else {
            0
        };
        let tx_rate = if elapsed > 0.0 {
            ((curr_net.tx_bytes.saturating_sub(prev_net.tx_bytes)) as f64 / elapsed) as u64
        } else {
            0
        };

        prev_net = curr_net;
        prev_time = std::time::Instant::now();

        let connections = get_tcp_connections();
        let uptime = get_uptime();

        let report = ServerReport {
            id: server_id.clone(),
            name: server_name.clone(),
            cpu,
            memory_used,
            memory_total,
            rx_bytes: rx_rate,
            tx_bytes: tx_rate,
            connections,
            uptime,
        };

        let body = match serde_json::to_string(&report) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("[ERR] Failed to serialize report: {}", e);
                thread::sleep(Duration::from_secs(REPORT_INTERVAL_SECS));
                continue;
            }
        };

        let mut req = ureq::post(&report_url).set("Content-Type", "application/json");
        if let Some(ref secret) = agent_secret {
            req = req.set("X-Agent-Secret", secret);
        }
        match req.send_string(&body) {
            Ok(_) => {
                eprintln!(
                    "[OK] CPU: {:.1}% | Mem: {}/{} MB | Net: {}/{} MB/s | Conn: {}",
                    cpu,
                    memory_used / 1024 / 1024,
                    memory_total / 1024 / 1024,
                    rx_rate / 1024 / 1024,
                    tx_rate / 1024 / 1024,
                    connections
                );
            }
            Err(e) => {
                eprintln!("[ERR] {}", e);
            }
        }

        // 차단 명령 폴링 (10초마다)
        if last_block_check.elapsed().as_secs() >= BLOCK_CHECK_INTERVAL_SECS {
            poll_block_commands(
                &server_url,
                &server_id,
                &mut last_block_timestamp,
                &agent_secret,
            );
            last_block_check = std::time::Instant::now();
        }

        thread::sleep(Duration::from_secs(REPORT_INTERVAL_SECS));
    }
}
