#!/bin/bash
# Server Agent 설치 스크립트
# 사용법: curl -sSL http://37.27.122.163:8080/agent/install.sh | bash -s -- http://37.27.122.163:8080

set -e

DASHBOARD_URL="${1:-http://37.27.122.163:8080}"
AGENT_URL="${DASHBOARD_URL}/agent/server_agent"
INSTALL_PATH="/usr/local/bin/server_agent"
SERVICE_PATH="/etc/systemd/system/server-agent.service"

echo "=== Server Agent 설치 ==="
echo "Dashboard URL: $DASHBOARD_URL"
echo ""

# 다운로드
echo "[1/4] 에이전트 다운로드..."
curl -sSL -o /tmp/server_agent "$AGENT_URL"
chmod +x /tmp/server_agent

# 설치
echo "[2/4] 설치..."
mv /tmp/server_agent "$INSTALL_PATH"

# systemd 서비스 생성
echo "[3/4] 서비스 등록..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=Server Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_PATH $DASHBOARD_URL
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 서비스 시작
echo "[4/4] 서비스 시작..."
systemctl daemon-reload
systemctl enable server-agent
systemctl restart server-agent

echo ""
echo "=== 설치 완료 ==="
echo "상태 확인: systemctl status server-agent"
echo "로그 확인: journalctl -u server-agent -f"
