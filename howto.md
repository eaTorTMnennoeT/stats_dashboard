# P2P Stats 서비스 관리 가이드

## 서비스 목록

| 서비스 | 설명 | 포트 |
|--------|------|------|
| `simple-ws` | WebSocket 서버 | 8443 |
| `stats-dashboard` | 대시보드 | 8080 |

---

## 기본 명령어

### 시작
```bash
systemctl start simple-ws stats-dashboard
```

### 중지
```bash
systemctl stop simple-ws stats-dashboard
```

### 재시작
```bash
systemctl restart simple-ws stats-dashboard
```

### 상태 확인
```bash
systemctl status simple-ws stats-dashboard
```

---

## 개별 서비스 관리

### simple-ws만
```bash
systemctl start simple-ws
systemctl stop simple-ws
systemctl restart simple-ws
```

### stats-dashboard만
```bash
systemctl start stats-dashboard
systemctl stop stats-dashboard
systemctl restart stats-dashboard
```

---

## 로그 확인

### 실시간 로그
```bash
# simple-ws
journalctl -u simple-ws -f

# stats-dashboard
journalctl -u stats-dashboard -f

# 둘 다
journalctl -u simple-ws -u stats-dashboard -f
```

### 최근 로그 (100줄)
```bash
journalctl -u simple-ws -n 100 --no-pager
journalctl -u stats-dashboard -n 100 --no-pager
```

### 오늘 로그
```bash
journalctl -u simple-ws --since today
```

---

## 부팅 시 자동 시작

### 활성화 (이미 설정됨)
```bash
systemctl enable simple-ws stats-dashboard
```

### 비활성화
```bash
systemctl disable simple-ws stats-dashboard
```

---

## 빌드 후 재시작

```bash
# simple-ws 빌드 & 재시작
cd /opt/rust/simple_ws
cargo build --release
systemctl restart simple-ws

# stats-dashboard 빌드 & 재시작
cd /opt/rust/stats_dashboard
cargo build --release
systemctl restart stats-dashboard
```

---

## 문제 해결

### 포트 충돌 시
```bash
# 8443 포트 사용 프로세스 종료
fuser -k 8443/tcp

# 8080 포트 사용 프로세스 종료
fuser -k 8080/tcp

# 서비스 재시작
systemctl restart simple-ws stats-dashboard
```

### 서비스 실패 시
```bash
# 상세 로그 확인
journalctl -u simple-ws -n 50 --no-pager

# 서비스 파일 문법 확인
systemd-analyze verify /etc/systemd/system/simple-ws.service
```

### 설정 변경 후
```bash
systemctl daemon-reload
systemctl restart simple-ws stats-dashboard
```

---

## 시스템 튜닝 파일

| 파일 | 용도 |
|------|------|
| `/etc/systemd/system/simple-ws.service` | WebSocket 서비스 설정 |
| `/etc/systemd/system/stats-dashboard.service` | 대시보드 서비스 설정 |
| `/etc/security/limits.d/p2p-stats.conf` | 파일 디스크립터 제한 |
| `/etc/sysctl.d/99-p2p-stats.conf` | 커널 네트워크 튜닝 |

---

## 접속 URL

- 대시보드: http://localhost:8080
- WebSocket: wss://localhost:8443
