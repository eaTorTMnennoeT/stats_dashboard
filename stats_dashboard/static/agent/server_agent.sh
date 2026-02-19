#!/bin/bash
# Server Monitoring Agent (Shell Script Version)
# 모든 Linux 배포판에서 동작

VERSION="44"
DASHBOARD_URL="${1:-http://37.27.122.163:8080}"
AGENT_SECRET="${2:-}"  # 두 번째 인자로 시크릿 키 받음
REPORT_URL="${DASHBOARD_URL}/api/servers/report"
LOGS_URL="${DASHBOARD_URL}/api/servers/logs"
SCRIPT_URL="${DASHBOARD_URL}/agent/server_agent.sh"
CHECKSUM_URL="${DASHBOARD_URL}/agent/server_agent.sh.sha256"
BLOCK_PENDING_URL="${DASHBOARD_URL}/api/blacklist/pending"
BLOCK_CONFIRM_URL="${DASHBOARD_URL}/api/blacklist/confirm"
INSTALL_PATH="/usr/local/bin/server_agent"
SECRET_FILE="/etc/server_agent.secret"
SERVICE_FILE="/etc/systemd/system/server_agent.service"
INTERVAL=5
UPDATE_CHECK_INTERVAL=60  # 60회 = 5분마다 업데이트 체크

# 시크릿 키 로드 (파일 또는 인자)
load_secret() {
    if [ -n "$AGENT_SECRET" ]; then
        # 인자로 받은 경우 파일에 저장
        echo "$AGENT_SECRET" > "$SECRET_FILE"
        chmod 600 "$SECRET_FILE"
    elif [ -f "$SECRET_FILE" ]; then
        AGENT_SECRET=$(cat "$SECRET_FILE")
    fi

    if [ -z "$AGENT_SECRET" ]; then
        echo "[ERROR] Agent secret not provided!"
        echo "Usage: $0 <dashboard_url> <agent_secret>"
        echo "Or create $SECRET_FILE with the secret key"
        exit 1
    fi
}
load_secret

# 인증 헤더
AUTH_HEADER="X-Agent-Secret: $AGENT_SECRET"

# systemd 서비스 자동 등록
setup_systemd_service() {
    # 이미 서비스 파일 있으면 스킵
    [ -f "$SERVICE_FILE" ] && return 0

    # systemd 없으면 스킵
    command -v systemctl >/dev/null 2>&1 || return 0

    echo "[SETUP] Creating systemd service..."
    cat > "$SERVICE_FILE" << SVCEOF
[Unit]
Description=Server Monitoring Agent
After=network.target

[Service]
ExecStart=$INSTALL_PATH $DASHBOARD_URL
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable server_agent
    echo "[SETUP] Systemd service registered"

    # 현재 프로세스가 systemd에서 실행된 게 아니면 systemd로 재시작
    if [ -z "$INVOCATION_ID" ]; then
        echo "[SETUP] Restarting via systemd..."
        systemctl start server_agent
        exit 0
    fi
}

# SHA256 체크섬 계산
calculate_checksum() {
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# 서비스 등록 실행
setup_systemd_service

# PID lock — 중복 실행 방지
PIDFILE="/tmp/server_agent.pid"
if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE")
    if kill -0 "$OLD_PID" 2>/dev/null; then
        echo "[ERROR] Already running (PID $OLD_PID). Exiting."
        exit 1
    fi
    rm -f "$PIDFILE"
fi
echo $$ > "$PIDFILE"
trap 'rm -f "$PIDFILE"' EXIT

# 로그 수집 설정
LOG_DIR="/var/log/nginx"
LOG_POS_FILE="/tmp/agent_log_pos"

# IP 차단 설정
NGINX_BLOCK_FILE="/etc/nginx/apiblack.conf"
LAST_BLOCK_CHECK=0
BLOCK_CHECK_INTERVAL=10  # 10회 = 50초마다 차단 명령 체크

# nginx 경로 찾기
find_nginx() {
    # openresty 먼저 체크 (대부분 서버가 openresty 사용)
    for path in /usr/local/openresty/nginx/sbin/nginx /usr/local/nginx/sbin/nginx /usr/sbin/nginx $(which nginx 2>/dev/null); do
        [ -x "$path" ] && echo "$path" && return
    done
}
NGINX_BIN=$(find_nginx)
[ -z "$NGINX_BIN" ] && echo "[WARN] nginx not found" >&2

# 서버 ID (machine-id 또는 hostname)
if [ -f /etc/machine-id ]; then
    SERVER_ID=$(head -c 12 /etc/machine-id)
else
    SERVER_ID=$(hostname)
fi
SERVER_NAME=$(hostname)

echo "Server Agent started (v$VERSION)"
echo "  ID: $SERVER_ID"
echo "  Name: $SERVER_NAME"
echo "  Report URL: $REPORT_URL"
echo "  Logs URL: $LOGS_URL"
echo "  Interval: ${INTERVAL}s"
echo "  Auto-update: every $((UPDATE_CHECK_INTERVAL * INTERVAL))s"

# 자동 업데이트 체크 (체크섬 검증 포함)
check_update() {
    NEW_VERSION=$(curl -s --max-time 5 "$SCRIPT_URL" 2>/dev/null | grep '^VERSION=' | head -1 | cut -d'"' -f2)
    if [ -n "$NEW_VERSION" ] && [ "$NEW_VERSION" != "$VERSION" ]; then
        echo "[UPDATE] New version $NEW_VERSION available (current: $VERSION)"

        # 1. 서버에서 체크섬 가져오기
        EXPECTED_CHECKSUM=$(curl -s --max-time 5 "$CHECKSUM_URL" 2>/dev/null)
        if [ -z "$EXPECTED_CHECKSUM" ] || [ ${#EXPECTED_CHECKSUM} -ne 64 ]; then
            echo "[UPDATE ERR] Failed to get checksum from server"
            return
        fi

        # 2. 새 스크립트 다운로드
        curl -s --max-time 30 "$SCRIPT_URL" -o "${INSTALL_PATH}.new" 2>/dev/null
        if [ ! -s "${INSTALL_PATH}.new" ]; then
            echo "[UPDATE ERR] Failed to download new script"
            rm -f "${INSTALL_PATH}.new"
            return
        fi

        # 3. 체크섬 검증
        ACTUAL_CHECKSUM=$(calculate_checksum "${INSTALL_PATH}.new")
        if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
            echo "[UPDATE ERR] Checksum mismatch! Expected: $EXPECTED_CHECKSUM, Got: $ACTUAL_CHECKSUM"
            echo "[UPDATE ERR] Possible MITM attack detected. Update aborted."
            rm -f "${INSTALL_PATH}.new"
            return
        fi

        # 4. 체크섬 일치 - 업데이트 적용
        echo "[UPDATE] Checksum verified: $ACTUAL_CHECKSUM"
        mv "${INSTALL_PATH}.new" "$INSTALL_PATH"
        chmod +x "$INSTALL_PATH"
        echo "[UPDATE] Updated to v$NEW_VERSION, restarting..."
        exec "$INSTALL_PATH" "$DASHBOARD_URL"
    fi
}

# IP 차단/해제 처리
process_block_commands() {
    # 대기 중인 차단 명령 가져오기 (server_id 포함하여 이미 처리된 것 필터링)
    COMMANDS=$(curl -s --max-time 5 -H "$AUTH_HEADER" "${BLOCK_PENDING_URL}?server_id=${SERVER_ID}" 2>/dev/null)
    if [ -z "$COMMANDS" ] || ! echo "$COMMANDS" | grep -q '"commands"'; then
        return
    fi

    NEW_BLOCK_COUNT=0
    ALREADY_BLOCKED_COUNT=0
    NEED_RELOAD=0
    MAX_PER_CYCLE=50  # 한 사이클에 최대 50개만 처리 (메인 루프 차단 방지)
    PROCESSED=0

    # 각 command 객체 추출 후 파싱 (process substitution으로 서브셸 방지)
    while read -r obj; do
        PROCESSED=$((PROCESSED + 1))
        if [ $PROCESSED -gt $MAX_PER_CYCLE ]; then
            echo "[BLOCK] Reached max $MAX_PER_CYCLE per cycle, remaining deferred"
            break
        fi

        # 객체에서 각 필드 추출
        IP=$(echo "$obj" | grep -o '"ip":"[^"]*"' | sed 's/"ip":"//;s/"//')
        ACTION=$(echo "$obj" | grep -o '"action":"[^"]*"' | sed 's/"action":"//;s/"//')
        REASON=$(echo "$obj" | grep -o '"reason":"[^"]*"' | sed 's/"reason":"//;s/"//')

        if [ -z "$ACTION" ]; then
            continue
        fi

        SUCCESS="false"

        if [ "$ACTION" = "block" ]; then
            # 이미 차단된 IP인지 확인
            if grep -q "deny $IP;" "$NGINX_BLOCK_FILE" 2>/dev/null; then
                ALREADY_BLOCKED_COUNT=$((ALREADY_BLOCKED_COUNT + 1))
                SUCCESS="true"
            else
                # 파일 없으면 생성
                [ ! -f "$NGINX_BLOCK_FILE" ] && touch "$NGINX_BLOCK_FILE"

                # 차단 규칙 추가
                BLOCK_TIME=$(date '+%Y-%m-%d %H:%M:%S')
                echo "deny $IP; # $BLOCK_TIME | $REASON" >> "$NGINX_BLOCK_FILE"
                NEED_RELOAD=1
                NEW_BLOCK_COUNT=$((NEW_BLOCK_COUNT + 1))
                echo "[BLOCK] $IP added"
                SUCCESS="true"
            fi
        elif [ "$ACTION" = "unblock" ]; then
            # 차단 해제
            if grep -q "deny $IP;" "$NGINX_BLOCK_FILE" 2>/dev/null; then
                sed -i "/deny $IP;/d" "$NGINX_BLOCK_FILE"
                NEED_RELOAD=1
                echo "[UNBLOCK] $IP removed"
                SUCCESS="true"
            else
                echo "[UNBLOCK] $IP was not blocked"
                SUCCESS="true"
            fi
        fi

        # 결과 보고 (confirm)
        curl -s -X POST "$BLOCK_CONFIRM_URL" \
            -H "Content-Type: application/json" \
            -H "$AUTH_HEADER" \
            -d "{\"server_id\":\"$SERVER_ID\",\"ip\":\"$IP\",\"action\":\"$ACTION\",\"success\":$SUCCESS}" \
            --max-time 3 >/dev/null 2>&1
    done < <(echo "$COMMANDS" | grep -o '{[^{}]*}')

    # nginx reload 한 번만 (새 차단/해제가 있을 때만)
    if [ "$NEED_RELOAD" = "1" ]; then
        if [ -n "$NGINX_BIN" ] && $NGINX_BIN -t 2>/dev/null && $NGINX_BIN -s reload 2>/dev/null; then
            echo "[BLOCK] nginx reloaded ($NEW_BLOCK_COUNT new blocks)"
        else
            echo "[BLOCK ERR] nginx reload failed"
        fi
    fi

    [ $ALREADY_BLOCKED_COUNT -gt 0 ] && echo "[BLOCK] $ALREADY_BLOCKED_COUNT already blocked (confirmed)"
}

LOOP_COUNT=0
BLOCK_LOOP_COUNT=0

get_network_bytes() {
    # 트래픽 가장 큰 인터페이스 찾기 (lo 제외)
    tail -n +3 /proc/net/dev | grep -v 'lo:' | awk -F: '{
        iface=$1; gsub(/ /, "", iface)
        split($2, vals, " ")
        rx=vals[1]; tx=vals[9]
        total=rx+tx
        if (total > max_total) {
            max_total=total; max_rx=rx; max_tx=tx
        }
    } END { print max_rx, max_tx }'
}

# VOD 로그 파일 찾기 (vod2.log 우선, 없으면 vod.log, 마지막으로 access.log)
# -s 사용: 파일 존재 + 크기 > 0 (빈 파일 건너뜀)
find_vod_log() {
    if [ -s "$LOG_DIR/vod2.log" ]; then
        echo "$LOG_DIR/vod2.log"
    elif [ -s "$LOG_DIR/vod.log" ]; then
        echo "$LOG_DIR/vod.log"
    elif [ -s "$LOG_DIR/access.log" ]; then
        echo "$LOG_DIR/access.log"
    fi
}

# nginx 로그 파싱 및 전송
collect_and_send_logs() {
    LOG_FILE=$(find_vod_log)
    if [ -z "$LOG_FILE" ] || [ ! -f "$LOG_FILE" ]; then
        return
    fi

    # 현재 파일 크기와 inode
    CURR_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    CURR_INODE=$(stat -c%i "$LOG_FILE" 2>/dev/null || echo 0)

    # 이전 위치 읽기
    if [ -f "$LOG_POS_FILE" ]; then
        read PREV_INODE PREV_POS < "$LOG_POS_FILE"
    else
        PREV_INODE=0
        PREV_POS=0
    fi

    # 파일이 로테이션됐거나 초기화됐으면 끝에서 시작
    if [ "$CURR_INODE" != "$PREV_INODE" ] || [ "$CURR_SIZE" -lt "$PREV_POS" ]; then
        if [ "$CURR_SIZE" -gt 5242880 ]; then
            PREV_POS=$((CURR_SIZE - 5242880))
        else
            PREV_POS=0
        fi
        echo "[LOGS] File changed, starting from recent data"
    fi

    # 새 데이터 없으면 스킵
    if [ "$CURR_SIZE" -le "$PREV_POS" ]; then
        return
    fi

    # 100MB 이상 밀렸으면 최근 5MB 지점으로 스킵
    BEHIND=$((CURR_SIZE - PREV_POS))
    if [ "$BEHIND" -gt 104857600 ]; then
        PREV_POS=$((CURR_SIZE - 5242880))
        echo "[LOGS] Too far behind ($(( BEHIND / 1048576 ))MB), skipping to recent"
    fi

    # 새 로그 읽기 (최대 30000줄)
    NEW_LOGS=$(tail -c +$((PREV_POS + 1)) "$LOG_FILE" 2>/dev/null | head -30000)
    if [ -z "$NEW_LOGS" ]; then
        return
    fi

    # 읽은 바이트 수 계산
    BYTES_READ=$(echo "$NEW_LOGS" | wc -c)
    NEW_POS=$((PREV_POS + BYTES_READ))

    # 위치 저장
    echo "$CURR_INODE $NEW_POS" > "$LOG_POS_FILE"

    # nginx 로그를 JSON 배열로 변환 (KST 기준 -9시간)
    JSON_LOGS=$(printf '%s' "$NEW_LOGS" | perl -e '
    my @results;
    my %m = (Jan=>1,Feb=>2,Mar=>3,Apr=>4,May=>5,Jun=>6,Jul=>7,Aug=>8,Sep=>9,Oct=>10,Nov=>11,Dec=>12);

    while (<STDIN>) {
        chomp;
        next unless /^(\S+)\s+.*?\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+[^"]+"\s+(\d+)\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/;
        my ($ip,$t,$method,$path,$st,$by,$ref,$ua) = ($1,$2,$3,$4,$5,$6,$7,$8);
        next if $st eq "304" or $st eq "403" or $st eq "404";
        next if $path =~ /thumb\.png/;
        $by = 0 if $by eq "-";

        my $ts = time() * 1_000_000_000;
        if ($t =~ /(\d+)\/(\w+)\/(\d+):(\d+):(\d+):(\d+)/) {
            my $mon = $m{$2} || 1;
            my $year = $3;
            my $day = $1;
            my @mdays = (0,31,59,90,120,151,181,212,243,273,304,334);
            my $y = $year - 1970;
            my $leap_years = int(($year - 1) / 4) - int(($year - 1) / 100) + int(($year - 1) / 400) - 477;
            my $is_leap = ($year % 4 == 0 && $year % 100 != 0) || ($year % 400 == 0);
            my $mon_days = $mdays[$mon - 1];
            $mon_days++ if ($is_leap && $mon > 2);
            my $days = $y * 365 + $leap_years + $mon_days + $day - 1;
            $ts = ($days * 86400 + $4 * 3600 + $5 * 60 + $6 - 32400) * 1_000_000_000;
        }

        my $rt = 0;
        $rt = $1 if /req_time:"([\d.]+)"/;

        # 특수문자 이스케이프 강화 (백슬래시, 따옴표, 줄바꿈, 탭, 캐리지리턴)
        for my $s (\$path, \$ref, \$ua) {
            $$s =~ s/\\/\\\\/g;
            $$s =~ s/"/\\"/g;
            $$s =~ s/\n/\\n/g;
            $$s =~ s/\r/\\r/g;
            $$s =~ s/\t/\\t/g;
        }
        push @results, qq({"timestamp":"$ts","client_ip":"$ip","method":"$method","path":"$path","status":$st,"bytes_sent":$by,"response_time":$rt,"referer":"$ref","user_agent":"$ua"});
    }
    print "[" . join(",", @results) . "]";
    ' 2>/dev/null)

    # 빈 배열 또는 에러면 스킵
    if [ -z "$JSON_LOGS" ] || [ "$JSON_LOGS" = "[]" ] || [ "${JSON_LOGS:0:1}" != "[" ]; then
        return
    fi

    # gzip 압축 + base64 -> 임시 파일에 저장 (Argument list too long 방지)
    TMPFILE="/tmp/agent_logs_$$.json"
    COMPRESSED=$(echo "$JSON_LOGS" | gzip -c | base64 -w0)
    if [ -z "$COMPRESSED" ]; then
        echo "[LOGS ERR] gzip/base64 failed"
        return
    fi
    echo "{\"server_id\":\"$SERVER_ID\",\"data\":\"$COMPRESSED\"}" > "$TMPFILE"

    # 전송 (실패 시 1회 재시도)
    LOG_COUNT=$(echo "$NEW_LOGS" | wc -l)
    for attempt in 1 2; do
        RESPONSE=$(curl -s -X POST "$LOGS_URL" \
            -H "Content-Type: application/json" \
            -H "$AUTH_HEADER" \
            -d @"$TMPFILE" \
            --max-time 10 --retry 0 2>&1)

        if echo "$RESPONSE" | grep -q '"status":"ok"'; then
            INSERTED=$(echo "$RESPONSE" | grep -o '"inserted":[0-9]*' | cut -d: -f2)
            echo "[LOGS] Sent $LOG_COUNT lines, inserted: $INSERTED"
            rm -f "$TMPFILE"
            return
        fi

        [ $attempt -eq 1 ] && sleep 1
    done
    rm -f "$TMPFILE"
    echo "[LOGS ERR] $RESPONSE"
}

# 초기값 설정 (첫 번째 측정에서 올바른 속도 계산을 위해)
INIT_NET=$(get_network_bytes)
PREV_RX=$(echo "$INIT_NET" | awk '{print $1}')
PREV_TX=$(echo "$INIT_NET" | awk '{print $2}')
PREV_TIME=$(date +%s)

# 로그 파일 위치 초기화 (현재 끝에서 시작)
LOG_FILE=$(find_vod_log)
if [ -n "$LOG_FILE" ] && [ -f "$LOG_FILE" ]; then
    CURR_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    CURR_INODE=$(stat -c%i "$LOG_FILE" 2>/dev/null || echo 0)
    echo "$CURR_INODE $CURR_SIZE" > "$LOG_POS_FILE"
    echo "[LOGS] Watching: $LOG_FILE (starting from end)"
fi

sleep $INTERVAL

while true; do
    # CPU 사용률
    CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1 2>/dev/null || echo "0")

    # 메모리
    MEM_INFO=$(free -b | grep Mem)
    MEM_TOTAL=$(echo "$MEM_INFO" | awk '{print $2}')
    MEM_USED=$(echo "$MEM_INFO" | awk '{print $3}')

    # 네트워크 속도 계산
    NOW=$(date +%s)
    NET=$(get_network_bytes)
    CURR_RX=$(echo "$NET" | awk '{print $1}')
    CURR_TX=$(echo "$NET" | awk '{print $2}')

    ELAPSED=$((NOW - PREV_TIME))
    if [ $ELAPSED -gt 0 ]; then
        RX_RATE=$(( (CURR_RX - PREV_RX) / ELAPSED ))
        TX_RATE=$(( (CURR_TX - PREV_TX) / ELAPSED ))
    else
        RX_RATE=0
        TX_RATE=0
    fi

    PREV_RX=$CURR_RX
    PREV_TX=$CURR_TX
    PREV_TIME=$NOW

    # TCP 연결 수
    CONNECTIONS=$(cat /proc/net/tcp /proc/net/tcp6 2>/dev/null | wc -l)
    CONNECTIONS=$((CONNECTIONS - 2))

    # 업타임
    UPTIME=$(awk '{print int($1)}' /proc/uptime)

    # 디스크 사용량 (모든 물리 디스크 합산, tmpfs/devtmpfs 제외)
    DISK_STATS=$(df -B1 -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | tail -n +2 | awk '{total+=$2; used+=$3} END {print total, used}')
    DISK_TOTAL=$(echo "$DISK_STATS" | awk '{print $1}')
    DISK_USED=$(echo "$DISK_STATS" | awk '{print $2}')

    # JSON 생성 및 전송
    JSON=$(cat <<EOF
{
    "id": "$SERVER_ID",
    "name": "$SERVER_NAME",
    "version": "$VERSION",
    "cpu": $CPU,
    "memory_used": $MEM_USED,
    "memory_total": $MEM_TOTAL,
    "disk_used": $DISK_USED,
    "disk_total": $DISK_TOTAL,
    "rx_bytes": $RX_RATE,
    "tx_bytes": $TX_RATE,
    "connections": $CONNECTIONS,
    "uptime": $UPTIME
}
EOF
)

    RESPONSE=$(curl -s -X POST "$REPORT_URL" \
        -H "Content-Type: application/json" \
        -H "$AUTH_HEADER" \
        -d "$JSON" 2>/dev/null)

    if echo "$RESPONSE" | grep -q '"status":"ok"'; then
        echo "[OK] CPU: ${CPU}% | Mem: $((MEM_USED/1024/1024))/$((MEM_TOTAL/1024/1024)) MB | Net: $((RX_RATE/1024/1024))/$((TX_RATE/1024/1024)) MB/s | Conn: $CONNECTIONS"

        # 서버에서 업데이트 요청 시 즉시 업데이트
        if echo "$RESPONSE" | grep -q '"update":true'; then
            echo "[UPDATE] Server requested update"
            check_update
        fi
    else
        echo "[ERR] $RESPONSE"
    fi

    # nginx 로그 수집 및 전송
    collect_and_send_logs

    # 차단 명령 체크 (50초마다)
    BLOCK_LOOP_COUNT=$((BLOCK_LOOP_COUNT + 1))
    if [ $((BLOCK_LOOP_COUNT % BLOCK_CHECK_INTERVAL)) -eq 0 ]; then
        process_block_commands
    fi

    sleep $INTERVAL
done
