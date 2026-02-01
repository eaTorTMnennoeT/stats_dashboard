#!/bin/bash
# Server Agent 자동 설치 스크립트
# 사용법: curl -sSL http://37.27.122.163:8080/agent/install.sh | bash

set -e

DASHBOARD_URL="http://37.27.122.163:8080"
INSTALL_PATH="/usr/local/bin/server_agent"
SERVICE_PATH="/etc/systemd/system/server-agent.service"

echo "========================================"
echo "  Server Monitoring Agent 설치"
echo "========================================"
echo ""

# 다운로드 (쉘 스크립트 버전 - 모든 Linux 호환)
echo "[1/4] 에이전트 다운로드..."
curl -sSL -o "$INSTALL_PATH" "${DASHBOARD_URL}/agent/server_agent.sh"
chmod +x "$INSTALL_PATH"

# 테스트
echo "[2/4] 동작 테스트..."
if ! bash -n "$INSTALL_PATH"; then
    echo "ERROR: 스크립트 문법 오류"
    exit 1
fi

# systemd 서비스 생성
echo "[3/4] 서비스 등록..."
cat > "$SERVICE_PATH" << EOF
[Unit]
Description=Server Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $INSTALL_PATH $DASHBOARD_URL
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# 서비스 시작
echo "[4/4] 서비스 시작..."
systemctl daemon-reload
systemctl enable server-agent >/dev/null 2>&1
systemctl restart server-agent

echo ""
echo "========================================"
echo "  설치 완료!"
echo "========================================"
echo ""
echo "상태 확인: systemctl status server-agent"
echo "로그 확인: journalctl -u server-agent -f"
echo ""
sleep 2
systemctl status server-agent --no-pager | head -8
