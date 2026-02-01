# IP 차단 시스템 문서

## 개요
AI 탐지로 어뷰저 IP를 자동/수동 차단하고, 모든 origin 서버에 자동 배포하는 시스템

## 아키텍처

```
[Dashboard] ──차단요청──> [QuestDB] + [Cloudflare API] + [Pending Queue]
                                                              │
                         ┌────────────────────────────────────┘
                         ▼
[Server Agent] ──폴링(50초)──> /api/blacklist/pending
       │
       ▼
[/etc/nginx/apiblack.conf] ──include──> [nginx]
       │
       ▼
[nginx -s reload]
       │
       ▼
[/api/blacklist/confirm] ──결과보고──> [Dashboard]
```

## 주요 컴포넌트

### 1. Dashboard (stats_dashboard)
- **위치**: `/opt/rust/stats_dashboard/`
- **포트**: 8080
- **역할**:
  - 차단 관리 UI (`#servers-blacklist`)
  - 차단 API 제공
  - Cloudflare API 연동
  - 에이전트 명령 큐 관리

### 2. Server Agent (Shell Script)
- **위치**: `/opt/rust/stats_dashboard/static/agent/server_agent.sh`
- **설치 경로**: `/usr/local/bin/server_agent`
- **현재 버전**: 29
- **역할**:
  - 서버 상태 모니터링 (CPU, 메모리, 네트워크)
  - nginx 로그 수집/전송
  - IP 차단 명령 처리
  - 자동 업데이트

### 3. Cloudflare 설정
- **저장소**: QuestDB `cf_settings` 테이블
- **계정**: MadW2000@proton.me
- 서버 재시작해도 유지됨 (DB 영구 저장)

## API 엔드포인트

### 차단 관련
| 엔드포인트 | 메소드 | 설명 |
|-----------|--------|------|
| `/api/blacklist` | GET | 차단 목록 조회 |
| `/api/blacklist/block` | POST | IP 차단 (DB + CF + pending) |
| `/api/blacklist/unblock` | POST | IP 차단 해제 |
| `/api/blacklist/pending` | GET | 대기 중인 차단 명령 (에이전트용) |
| `/api/blacklist/confirm` | POST | 차단 결과 보고 (에이전트용) |

### Cloudflare 설정
| 엔드포인트 | 메소드 | 설명 |
|-----------|--------|------|
| `/api/settings/cloudflare` | GET | CF 계정 조회 |
| `/api/settings/cloudflare` | POST | CF 계정 저장 |

## 차단 흐름

### 1. 수동 차단
```
UI에서 "차단" 클릭
  → POST /api/blacklist/block {ip, reason, server}
  → QuestDB blacklist 테이블에 저장
  → Cloudflare API로 차단 요청
  → PENDING_BLOCKS 큐에 추가
  → 에이전트가 폴링해서 처리
```

### 2. 자동 차단 (AI 탐지)
```
AI탐지 탭에서 abuser 로드
  → executeAutoBlock() 호출
  → 설정된 점수 이상 IP 자동 차단
  → 위와 동일한 흐름
```

### 3. 에이전트 처리
```
50초마다 /api/blacklist/pending 폴링
  → 명령 수신 시:
     1. /etc/nginx/apiblack.conf에 중복 체크
     2. 없으면 "deny IP; # 시간 | 사유" 추가
     3. nginx -t && nginx -s reload
     4. /api/blacklist/confirm으로 결과 보고
```

## 에이전트 배포/업데이트

### 최초 설치
```bash
# 서버에서 실행
curl -o /usr/local/bin/server_agent http://37.27.122.163:8080/agent/server_agent.sh
chmod +x /usr/local/bin/server_agent
/usr/local/bin/server_agent http://37.27.122.163:8080
# → systemd 서비스 자동 등록됨
```

### 자동 업데이트
1. `/opt/rust/stats_dashboard/static/agent/server_agent.sh`의 `VERSION` 수정
2. 에이전트가 5분마다 버전 체크
3. 새 버전 감지 시 자동 다운로드 & 재시작

### 즉시 업데이트 강제
대시보드 API 응답에 `"update": true` 포함 시 즉시 업데이트

## nginx 설정

### apiblack.conf include 추가
```nginx
# /etc/nginx/nginx.conf 또는 server block
http {
    include /etc/nginx/apiblack.conf;
    ...
}
```

### apiblack.conf 예시
```nginx
deny 1.2.3.4; # 2026-01-22 15:30:00 | [자동차단] AI탐지 85점
deny 5.6.7.8; # 2026-01-22 16:00:00 | 수동차단 - 어뷰저
```

## DB 테이블

### blacklist (QuestDB)
| 컬럼 | 타입 | 설명 |
|------|------|------|
| ip | VARCHAR | IP 주소 |
| action | SYMBOL | block/unblock |
| blocked_at | TIMESTAMP | 차단 시간 |
| reason | VARCHAR | 차단 사유 |
| blocked_by | VARCHAR | 차단자 (admin/auto) |
| server | VARCHAR | 사용 서버 |
| cf_blocked | BOOLEAN | CF 차단 여부 |

### cf_settings (QuestDB)
| 컬럼 | 타입 | 설명 |
|------|------|------|
| name | VARCHAR | 계정명 |
| email | VARCHAR | CF 이메일 |
| api_key | VARCHAR | CF API 키 |
| created_at | TIMESTAMP | 등록 시간 |

## 자동 차단 설정

localStorage에 저장:
```javascript
{
  enabled: true,      // 활성화 여부
  score: 85,          // 차단 점수 기준
  duration: '24h'     // 차단 기간 (미사용)
}
```

## 파일 위치 요약

| 파일 | 위치 |
|------|------|
| Dashboard 소스 | `/opt/rust/stats_dashboard/src/main.rs` |
| Dashboard UI | `/opt/rust/stats_dashboard/static/index.html` |
| Agent 스크립트 | `/opt/rust/stats_dashboard/static/agent/server_agent.sh` |
| 서버 차단 파일 | `/etc/nginx/apiblack.conf` (각 서버) |

## TODO / 개선사항

- [ ] 차단 해제 시 Cloudflare에서도 해제 (현재 미구현)
- [ ] 차단 기간 만료 시 자동 해제
- [ ] 대시보드에서 에이전트 상태 표시 (차단 성공/실패)
