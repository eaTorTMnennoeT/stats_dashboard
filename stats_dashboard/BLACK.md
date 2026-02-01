# 자동 IP 차단 시스템 개발 계획

## 1. 개요
AI 어뷰저 탐지 시스템과 연동하여 악성 IP를 자동으로 차단하는 시스템

## 2. 차단 대상
- `/etc/nginx/apiblack.conf` - 모든 서버 (9개)에 적용
- Cloudflare 방화벽 - 2개 계정 동시 차단

## 3. 구현 항목

### 3.1 Backend API (main.rs)
- [ ] `POST /api/blacklist/block` - IP 차단 API
  - 모든 서버 nginx apiblack.conf에 추가
  - Cloudflare API로 차단
  - 차단 정보 DB 저장 (ip, 시간, 사유)
  - 중복 체크 로직

- [ ] `DELETE /api/blacklist/unblock/{ip}` - IP 차단 해제 API
  - 모든 서버 nginx에서 제거
  - Cloudflare에서 제거
  - DB에서 삭제

- [ ] `GET /api/blacklist` - 차단 목록 조회 API
  - 전체 차단 IP 목록
  - 차단 시간, 사유 포함

### 3.2 Nginx 차단 (각 서버)
- [ ] 에이전트에 차단 기능 추가
  - 대시보드에서 차단 명령 수신
  - `/etc/nginx/apiblack.conf` 파일 관리
  - 형식: `deny IP; # 2026-01-22 10:30:00 | 사유: 초고속 다운로드`
  - nginx reload 실행

### 3.3 Cloudflare 차단
- [ ] Cloudflare API 연동
  - 계정 1: MadW2000@proton.me
  - 계정 2: (설정 필요)
  - mode: block, target: ip

### 3.4 Frontend (index.html)
- [ ] 블랙리스트 메뉴 추가 (`#blacklist`)
- [ ] 차단 목록 테이블
  - IP, 차단시간, 사유, 서버상태
  - 차단 해제 버튼
- [ ] 어뷰저 페이지에서 1클릭 차단 버튼

### 3.5 QuestDB 테이블
```sql
CREATE TABLE blacklist (
    ip VARCHAR,
    blocked_at TIMESTAMP,
    reason VARCHAR,
    blocked_by VARCHAR
) timestamp(blocked_at);
```

## 4. 차단 흐름
```
1. 관리자가 어뷰저 페이지에서 "차단" 클릭
2. POST /api/blacklist/block 호출
3. DB에 차단 정보 저장 (중복 체크)
4. Cloudflare API 호출 (2개 계정)
5. 모든 서버에 차단 명령 전송 (에이전트 통해)
6. 각 서버에서 apiblack.conf 업데이트 + nginx reload
```

## 5. 구현 순서
1. QuestDB blacklist 테이블 생성
2. Backend 차단/해제/조회 API
3. Cloudflare API 연동
4. 에이전트 차단 명령 수신 기능
5. Frontend 블랙리스트 페이지
6. 어뷰저 페이지 차단 버튼

## 6. 참고
- 기존 차단 스크립트: `/home/cfb.php`
- nginx 설정 위치: `/etc/nginx/apiblack.conf`
