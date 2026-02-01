# 현재 진행 중인 작업

## 목표
Bunny CDN처럼 모든 서버의 Nginx 로그를 수집하여 QuestDB에 저장하고 분석

## 구현 완료

### 1. QuestDB 테이블 생성 ✅
```sql
CREATE TABLE nginx_logs (
  timestamp TIMESTAMP,
  server_id SYMBOL,
  client_ip VARCHAR,
  method SYMBOL,
  path VARCHAR,
  status SHORT,
  bytes_sent LONG,
  response_time DOUBLE,
  referer VARCHAR,
  user_agent VARCHAR
) TIMESTAMP(timestamp) PARTITION BY DAY;
```

### 2. 대시보드 API 추가 ✅ (main.rs)
- `POST /api/servers/logs` - 로그 수신 (gzip + base64 압축)
- `GET /api/servers/logs` - 로그 조회 (period, server_id, limit 파라미터)

### 3. 에이전트 v6 업데이트 ✅ (server_agent.sh)
- `/var/log/nginx/` 에서 가장 큰 로그 파일 자동 감지 (VOD 로그)
- 증분 읽기 (마지막 위치 기억, 로테이션 처리)
- nginx combined 로그 포맷 파싱
- gzip 압축 + base64 인코딩
- 5초마다 새 로그 전송

### 4. 로그 수집 동작 확인 ✅
```
현재 수집량 (일부 서버):
- 3bdf9d8613fa: 1577 logs
- 11d5ecf97e20: 1061 logs
- fbdde4624ac0: 608 logs

Status Code 분포:
- 304: 1825
- 200: 1566
- 404: 15
- 403: 9
```

## 다음 단계

### UI에 로그 분석 화면 추가
1. 실시간 로그 스트림 뷰
2. 통계 대시보드
   - 요청수/초
   - Status code 분포 (파이차트)
   - 바이트 전송량
   - 인기 경로 Top 20
   - 에러 로그 (4xx, 5xx)
3. 필터링 기능
   - 서버별
   - 기간별
   - Status code별

## 서버 현황
- 9개 서버 전부 에이전트 v6 실행 중
- 3개 서버에서 nginx 로그 수집 중 (나머지는 nginx 미사용 또는 다른 로그 경로)
- QuestDB: localhost:9002 (HTTP), localhost:9019 (ILP)

## API 사용법

### 로그 조회
```bash
# 최근 1시간 로그 100개
curl "http://localhost:8080/api/servers/logs?limit=100"

# 특정 서버 로그
curl "http://localhost:8080/api/servers/logs?server_id=11d5ecf97e20&limit=50"

# 기간 지정 (5m, 15m, 1h, 6h, 24h)
curl "http://localhost:8080/api/servers/logs?period=24h&limit=1000"
```

### QuestDB 직접 쿼리
```bash
# 서버별 로그 수
curl -G "http://localhost:9002/exec" --data-urlencode "query=SELECT server_id, count() FROM nginx_logs GROUP BY server_id"

# Status code 분포
curl -G "http://localhost:9002/exec" --data-urlencode "query=SELECT status, count() FROM nginx_logs GROUP BY status"

# 인기 경로
curl -G "http://localhost:9002/exec" --data-urlencode "query=SELECT path, count() as hits FROM nginx_logs GROUP BY path ORDER BY hits DESC LIMIT 20"
```

## 관련 파일
- `/opt/rust/stats_dashboard/src/main.rs` - 백엔드
- `/opt/rust/stats_dashboard/static/agent/server_agent.sh` - 에이전트
- `/opt/rust/stats_dashboard/static/index.html` - 프론트엔드
- `/opt/rust/stats_dashboard/doing.md` - 이 파일
