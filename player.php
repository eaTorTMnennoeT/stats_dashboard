<?php
/* =========================================================
   공통 모듈 로드 (config.php)
   - Referrer 체크, 파라미터, 서버 선택, AES, src 복호화, 토큰 생성 등
========================================================= */
error_reporting(E_ALL);
ini_set('display_errors', '1');
header('Content-Type: text/html; charset=utf-8');

require_once __DIR__ . '/config.php';

/* 재생 URL 생성 (암호화됨) */
$myurl = generate_file_url();

/* (선택) thumb.png poster - 기본 OFF */
$USE_THUMB_POSTER = false;
$thumbURL = "https://{$base_url}/{$dir_path}/thumb.png";
$mythumb = encrypt_data($thumbURL, $key, $iv);
?>
<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <meta name="referrer" content="origin" />
  <title></title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+KR:wght@500;700&display=swap" rel="stylesheet">


  <link rel="stylesheet" href="<?= $styleToLoad ?>">

  <style>
    html, body{
      margin:0; padding:0;
      width:100%; height:100%;
      background:#000;
      overflow:hidden;
    }
    .play-box-main{
      position:fixed;
      inset:0;
      background:#000;
    }
    /* ✅ 아래 회색줄(틈) 제거 핵심 */
    #vod_player, .video-js{
      width:100% !important;
      height:100% !important;
      display:block;
      object-fit:cover;
    }
/* ===== Clean centered captions (no box, no stroke) ===== */
.video-js.vjs-netflix-captions .vjs-text-track-display{
  bottom: 10% !important;
  background: transparent !important;
}

.video-js.vjs-netflix-captions .vjs-text-track-display > div{
  width: 100% !important;
  text-align: center !important;
  padding: 0 6% !important;
  background: transparent !important;
}

/* cue */
.video-js.vjs-netflix-captions .vjs-text-track-cue,
.video-js.vjs-netflix-captions .vjs-text-track-cue > div{
  background: transparent !important;
  padding: 0 !important;
  border-radius: 0 !important;
  box-shadow: none !important;

  color: #fff !important;
  font-family: "Noto Sans KR","Apple SD Gothic Neo","Malgun Gothic","Nanum Gothic",system-ui,sans-serif !important;
  font-weight: 700 !important;
  line-height: 1.35 !important;
  letter-spacing: 0.02em;
  white-space: pre-line;

  /* ❌ stroke 제거 (깨짐 원인) */
  -webkit-text-stroke: 0 !important;

  /* ✅ 넷플릭스식 아웃라인(그림자) */
  text-shadow:
    2px 0 0 rgba(0,0,0,0.95),
   -2px 0 0 rgba(0,0,0,0.95),
    0 2px 0 rgba(0,0,0,0.95),
    0 -2px 0 rgba(0,0,0,0.95),
    2px 2px 0 rgba(0,0,0,0.85),
   -2px 2px 0 rgba(0,0,0,0.85),
    2px -2px 0 rgba(0,0,0,0.85),
   -2px -2px 0 rgba(0,0,0,0.85),
    0 6px 10px rgba(0,0,0,0.75) !important;
}

/* 크기 */
.video-js.vjs-netflix-captions .vjs-text-track-display{ font-size: 22px; }
@media (max-width:768px){
  .video-js.vjs-netflix-captions .vjs-text-track-display{ font-size: 18px; }
}
/* ===== HARD center (Video.js cue inline-style override) ===== */
.video-js.vjs-netflix-captions .vjs-text-track-display{
  left: 0 !important;
  right: 0 !important;
  width: 100% !important;
  display: flex !important;
  justify-content: center !important;
}

.video-js.vjs-netflix-captions .vjs-text-track-display > div{
  width: 100% !important;
  display: flex !important;
  justify-content: center !important;
  text-align: center !important;
  padding: 0 !important;            /* 좌우 패딩이 치우치면 여기서 제거 */
  margin: 0 auto !important;
}

/* cue가 오른쪽으로 밀리는 원인(left/transform/width) 강제 제거 */
.video-js.vjs-netflix-captions .vjs-text-track-cue{
  left: 0 !important;
  right: 0 !important;
  width: auto !important;
  margin: 0 auto !important;
  transform: none !important;
  text-align: center !important;
}

/* 글씨 덩어리도 중앙 */
.video-js.vjs-netflix-captions .vjs-text-track-cue > div{
  display: inline-block !important;
  text-align: center !important;
  margin: 0 auto !important;
}



  </style>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/crypto-js/3.1.9-1/crypto-js.js"></script>

  <!-- P2P Media Loader Import Map -->
  <script type="importmap">
    {
      "imports": {
        "p2p-media-loader-core": "https://cdn.jsdelivr.net/npm/p2p-media-loader-core@^1/dist/p2p-media-loader-core.es.min.js",
        "p2p-media-loader-hlsjs": "https://cdn.jsdelivr.net/npm/p2p-media-loader-hlsjs@^1/dist/p2p-media-loader-hlsjs.es.min.js"
      }
    }
  </script>

  <?php output_common_js_vars(1); ?>
</head>

<body>


  <div class="play-box-main">
    <video
      id="vod_player"
      class="video-js vjs-default-skin"
      controls
      preload="auto"
      playsinline
      webkit-playsinline
    ></video>
  </div>

  <!-- CAST -->
  <script src="https://www.gstatic.com/cv/js/sender/v1/cast_sender.js?loadCastFramework=1"></script>

  <!-- Video.js -->
  <script src="./videojs8/video.min.js"></script>

  <!-- hls.js (PC/Android)
  <script src="https://cdn.jsdelivr.net/npm/hls.js@1.4.14/dist/hls.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.6.14-0.canary.11525/hls.min.js"></script>
	<script src="/js/hls1224.js"></script>
	    <script src="https://cdnjs.cloudflare.com/ajax/libs/hls.js/1.6.13/hls.js"></script>
  -->
  
    <script src="https://cdn.jsdelivr.net/npm/hls.js@1/dist/hls.min.js"></script>

  <!-- Plugins -->
  <script src="./videojs8/nuevo.min2.js"></script>
  <script src="./videojs8/plugins/videojs-chromecast.min.js"></script>
  <script src="./videojs/plugins/videojs.airplay.js"></script>
  <script src="./videojs/plugins/videojs.hotkeys.min.js"></script>
  <script src="./videojs/NoSleep.min.js"></script>


  <script type="module">
    import { HlsJsP2PEngine } from "p2p-media-loader-hlsjs";

    /* ===== my() : HEX(AES-CBC) 복호화 ===== */
    function my(hexCipher){
      const ciphertext = CryptoJS.enc.Hex.parse(hexCipher);
      const key = CryptoJS.enc.Hex.parse('<?= $k ?>');
      const iv  = CryptoJS.enc.Hex.parse('<?= $i ?>');
      const decrypted = CryptoJS.AES.decrypt({ciphertext}, key, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC
      });
      return decrypted.toString(CryptoJS.enc.Utf8);
    }

    (function(){
      var hls_url = my("<?= $myurl ?>");
      // swarm_id는 config.php의 output_common_js_vars()에서 window.SWARM_ID로 선언됨

      // iPadOS(데스크탑 UA)까지 포함한 iOS 판별
      var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) ||
                  (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

      var hls = null;
      var isCasting = false;

      // P2P 지원 HLS.js 생성 (iOS가 아니고 HLS.js 지원 시)
      var HlsWithP2P = (!isIOS && window.Hls && Hls.isSupported()) ? HlsJsP2PEngine.injectMixin(window.Hls) : null;

      var player = videojs("vod_player", {
        autoplay: false,
        preload: "auto",
        html5: { vhs: { overrideNative: !isIOS } }
      });
      player.addClass('vjs-netflix-captions');

      // (선택) thumb.png poster
      <?php if ($USE_THUMB_POSTER) { ?>
      try {
        var poster_url = my("<?= $mythumb ?>");
        player.poster(poster_url);
      } catch(e) {}
      <?php } ?>

      // UI 플러그인들(있을 때만)
      try {
        if (player.nuevo) {
          player.nuevo({
            video_id: "<?= htmlspecialchars($src_in, ENT_QUOTES) ?>",
            resume: true,
            videoInfo: true,
            settingsButton: true,
            relatedMenu: false,
            shareMenu: false,
            infoTitle: '',
            infoDescription: 'ChromeCast & Airplay 지원',
            buttonForward: true,
            contextMenu: false,
            androidLock: true
          });
        }
      } catch(e) {}

      try { if (player.hotkeys) player.hotkeys({ volumeStep: 0.1, seekStep: 5 }); } catch(e) {}
      try { player.volume(1); } catch(e) {}

      try { if (player.chromecast) player.chromecast({ overlayButton: false }); } catch(e) {}
      try { if (player.airplay) player.airplay({ addButtonToControlBar: true }); } catch(e) {}

      // P2P + HLS.js 설정
      function attachHlsJs(){
        var hlsConfig = {
          enableWorker: true,
          lowLatencyMode: false,
          backBufferLength: 30,
          maxBufferLength: 90,
          maxMaxBufferLength: 180,
          fragLoadingTimeOut: 20000,
          fragLoadingMaxRetry: 6,
          fragLoadingRetryDelay: 800,
          fragLoadingMaxRetryTimeout: 120000,
          manifestLoadingTimeOut: 8000,
          manifestLoadingMaxRetry: 3,
          manifestLoadingRetryDelay: 1000,
          manifestLoadingMaxRetryTimeout: 20000,
          levelLoadingTimeOut: 10000,
          levelLoadingMaxRetry: 3,
          levelLoadingRetryDelay: 1000,
          levelLoadingMaxRetryTimeout: 20000
        };

        // P2P 설정
        var p2pConfig = {
          core: {
            swarmId: SWARM_ID,
            simultaneousHttpDownloads: 5,
            simultaneousP2PDownloads: 3,
            httpDownloadProbability: 0.15,
            p2pDownloadMaxPriority: 30,
            cachedSegmentExpiration: 120000,
            cachedSegmentsCount: 50,
            p2pSegmentDownloadTimeout: 5000,
            announceTrackers: [
              "wss://tracker.openwebtorrent.com",
              "wss://tracker.linkwang.org"
            ],
            rtcConfig: {
              iceServers: [
                { urls: "stun:stun.l.google.com:19302" },
                { urls: "stun:stun1.l.google.com:19302" },
                { urls: "stun:global.stun.twilio.com:3478" }
              ]
            },
            // 세그먼트 검증 - TS 헤더 체크
            validateSegment: function(data, segment) {
              if (data.byteLength < 188) return false;
              var arr = new Uint8Array(data);
              return arr[0] === 0x47; // TS sync byte
            }
          }
        };

        if (HlsWithP2P) {
          // P2P 지원 HLS.js 사용
          hls = new HlsWithP2P({ ...hlsConfig, p2p: p2pConfig });

          // P2P 엔진 참조
          var p2pEngine = hls.p2pEngine;

          // P2P 통계 모니터링 (전역으로 선언하여 WebSocket에서 접근 가능)
          window.p2pStats = { httpBytes: 0, p2pBytes: 0, p2pUpBytes: 0, peers: 0 };

          // 세그먼트 로드 이벤트로 통계 수집
          hls.on(Hls.Events.FRAG_LOADED, function(event, data) {
            if (data && data.frag && data.frag.stats) {
              var loaded = data.frag.stats.total || data.frag.stats.loaded || 0;
              window.p2pStats.httpBytes += loaded;
            }
          });

          // P2P 엔진 이벤트 리스너 (피어 연결/해제)
          if (p2pEngine) {
            p2pEngine.addEventListener('onPeerConnect', function(details) {
              window.p2pStats.peers++;
            });

            p2pEngine.addEventListener('onPeerClose', function(details) {
              window.p2pStats.peers = Math.max(0, window.p2pStats.peers - 1);
            });

            p2pEngine.addEventListener('onChunkDownloaded', function(bytesLength, downloadSource, peerId) {
              if (peerId) {
                window.p2pStats.p2pBytes += bytesLength;
              }
            });

            p2pEngine.addEventListener('onChunkUploaded', function(bytesLength, peerId) {
              window.p2pStats.p2pUpBytes += bytesLength;
            });
          }
        } else {
          // 일반 HLS.js 사용 (fallback)
          hls = new Hls(hlsConfig);
        }

        // 에러 추적 로그 (복구 없이 로그만)
        hls.on(Hls.Events.ERROR, function(event, data) {
          console.error('[HLS Error]', {
            type: data.type,
            details: data.details,
            fatal: data.fatal,
            url: data.url || '',
            reason: data.reason || '',
            response: data.response ? data.response.code : ''
          });

          if (data.fatal) {
            console.error('[HLS] 치명적 에러 발생 - type:', data.type);
          }
        });

        // 버퍼 상태 추적
        hls.on(Hls.Events.BUFFER_STALLED, function() {
          console.warn('[HLS] 버퍼 부족 - 재생 멈춤');
        });

        hls.on(Hls.Events.FRAG_LOAD_EMERGENCY_ABORTED, function(event, data) {
          console.warn('[HLS] 세그먼트 긴급 중단:', data.frag ? data.frag.url : '');
        });

        hls.loadSource(hls_url);
        hls.attachMedia(player.tech().el());
      }

      function attachNative(){
        player.src({ src: hls_url, type: 'application/x-mpegURL' });

        // iOS/네이티브 HLS용 전송량 추적
        if (!window.p2pStats) {
          window.p2pStats = { httpBytes: 0, p2pBytes: 0, p2pUpBytes: 0, peers: 0 };
        }

        var lastTime = 0;
        var estimatedBitrate = 2000000; // 기본 2Mbps (2,000,000 bits/s)

        // 재생 시간 변화를 추적하여 전송량 계산
        player.on('timeupdate', function() {
          try {
            var currentTime = player.currentTime() || 0;
            var timeDiff = currentTime - lastTime;

            // 정상적인 재생 중일 때만 (너무 큰 시간 점프는 시킹으로 간주)
            if (timeDiff > 0 && timeDiff < 5) {
              // 재생된 시간 × 비트레이트 = 전송된 바이트
              var bitsDownloaded = timeDiff * estimatedBitrate;
              var bytesDownloaded = Math.floor(bitsDownloaded / 8);
              window.p2pStats.httpBytes += bytesDownloaded;
            }

            lastTime = currentTime;
          } catch(e) {}
        });

        // loadedmetadata 이벤트에서 실제 비트레이트 확인 시도
        player.on('loadedmetadata', function() {
          try {
            var videoTrack = player.tech().vhs;
            if (videoTrack && videoTrack.playlists && videoTrack.playlists.media_) {
              var bandwidth = videoTrack.playlists.media_.attributes.BANDWIDTH;
              if (bandwidth) {
                estimatedBitrate = bandwidth;
                console.log('[Native Stats] 실제 비트레이트:', (bandwidth/1000000).toFixed(2), 'Mbps');
              }
            }
          } catch(e) {
            console.log('[Native Stats] 비트레이트 자동 감지 실패, 기본값 사용');
          }
        });
      }

      if (!isIOS && window.Hls && Hls.isSupported()) {
        attachHlsJs();
      } else {
        attachNative();
      }

      // ============ 통계 서버 WebSocket 연결 (Player 2) - 모든 환경에서 항상 연결 ============
      // 전역 플래그로 중복 실행 완전 차단
      if (window._statsInitializedPlayer2) {
        return;
      }
      window._statsInitializedPlayer2 = true;

      var statsWs = null;
      var statsConnected = false;
      var reconnectTimeout = null;
      var heartbeatInterval = null;
      var missedHeartbeats = 0;
      var reconnectAttempts = 0;
      var isPageVisible = !document.hidden;

      // WebSocket 완전 정리 함수
      function cleanupWebSocket() {
        if (reconnectTimeout) {
          clearTimeout(reconnectTimeout);
          reconnectTimeout = null;
        }
        if (heartbeatInterval) {
          clearInterval(heartbeatInterval);
          heartbeatInterval = null;
        }
        if (statsWs) {
          try {
            statsWs.onclose = null;
            statsWs.onerror = null;
            statsWs.onmessage = null;
            statsWs.onopen = null;
            if (statsWs.readyState === WebSocket.OPEN || statsWs.readyState === WebSocket.CONNECTING) {
              statsWs.close();
            }
          } catch(e) {}
          statsWs = null;
        }
        statsConnected = false;
      }

      function connectStatsServer() {
        // 기존 연결 완전 정리
        cleanupWebSocket();

        try {
          console.log('[WebSocket] Connecting to stats server...');
          statsWs = new WebSocket('wss://sk.netguard742.com:8443/ws');

          statsWs.onopen = function() {
            console.log('[WebSocket] Connected successfully');
            statsConnected = true;
            missedHeartbeats = 0;
            reconnectAttempts = 0;

            // 초기화 메시지 전송
            statsWs.send(JSON.stringify({
              type: 'init',
              swarmId: SWARM_ID,
              playerId: PLAYER_ID,
              filename: filenameFromUrl,
              server: SERVER_PARAM,
              referrer: document.referrer || 'direct',
              device: deviceType,
              deviceName: deviceName,
              netType: netType,
              browser: browserTag
            }));

            // 30초마다 heartbeat (연결 유지)
            heartbeatInterval = setInterval(function() {
              if (statsWs && statsWs.readyState === WebSocket.OPEN) {
                try {
                  // 3번 연속 응답 없으면 재연결 (먼저 체크)
                  if (missedHeartbeats >= 3) {
                    console.log('[WebSocket] Heartbeat timeout - reconnecting');
                    statsWs.close();
                    return;
                  }

                  // ping 전송 후 카운터 증가
                  statsWs.send(JSON.stringify({ type: 'ping' }));
                  missedHeartbeats++;
                } catch(e) {
                  console.error('[WebSocket] Heartbeat error:', e);
                  statsWs.close();
                }
              }
            }, 30000);
          };

          statsWs.onmessage = function(event) {
            try {
              var data = JSON.parse(event.data);
              if (data.type === 'pong') {
                missedHeartbeats = 0;
              }
            } catch(e) {}
          };

          statsWs.onclose = function(event) {
            console.log('[WebSocket] Connection closed:', event.code, event.reason);
            statsConnected = false;
            if (heartbeatInterval) {
              clearInterval(heartbeatInterval);
              heartbeatInterval = null;
            }

            // 정상 종료(1000)가 아니면 재연결 시도
            if (event.code !== 1000) {
              // 지수 백오프 재연결 (1초 → 2초 → 4초 → 8초 → 최대 30초)
              reconnectAttempts++;
              var delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);
              console.log('[WebSocket] Reconnecting in', delay/1000, 'seconds... (attempt', reconnectAttempts, ')');
              reconnectTimeout = setTimeout(connectStatsServer, delay);
            }
          };

          statsWs.onerror = function(e) {
            if (statsWs) {
              statsWs.close();
            }
          };
        } catch (e) {
          reconnectAttempts++;
          var delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);
          reconnectTimeout = setTimeout(connectStatsServer, delay);
        }
      }

      connectStatsServer();

      // 마지막 전송 값 추적 (증분 계산용)
      var lastSentStats = {
        httpBytes: 0,
        p2pBytes: 0,
        p2pUpBytes: 0
      };

      // 10초마다 통계 전송 (중복 방지 - window scope 사용)
      if (window._statsIntervalPlayer2) {
        clearInterval(window._statsIntervalPlayer2);
      }
      window._statsIntervalPlayer2 = setInterval(function() {
        // 백그라운드 탭이거나 연결 안됐으면 전송 안 함
        if (!isPageVisible || !statsConnected || !statsWs || statsWs.readyState !== WebSocket.OPEN) {
          return;
        }

        var statsData = {
          type: 'stats',
          playerId: PLAYER_ID
        };

        // window.p2pStats가 있으면 통계 포함 (PC/Android P2P 또는 iOS 네이티브)
        if (typeof window.p2pStats !== 'undefined') {
          var current = window.p2pStats;

          // 증분값 계산 (이번 전송 구간의 증가량만)
          var deltaHttp = current.httpBytes - lastSentStats.httpBytes;
          var deltaP2p = current.p2pBytes - lastSentStats.p2pBytes;
          var deltaUpload = current.p2pUpBytes - lastSentStats.p2pUpBytes;

          // 증분값 (서버가 이걸로 집계) - r prefix = real-time delta
          statsData.rhttpBytes = deltaHttp;
          statsData.rp2pBytes = deltaP2p;
          statsData.rp2pUpBytes = deltaUpload;

          // 누적 총합 (검증/모니터링용)
          statsData.totalHttpBytes = current.httpBytes;
          statsData.totalP2pBytes = current.p2pBytes;
          statsData.totalP2pUpBytes = current.p2pUpBytes;

          statsData.peers = current.peers;

          // 마지막 전송 값 업데이트
          lastSentStats.httpBytes = current.httpBytes;
          lastSentStats.p2pBytes = current.p2pBytes;
          lastSentStats.p2pUpBytes = current.p2pUpBytes;
        } else {
          // 통계가 아예 없을 때만 0
          statsData.rhttpBytes = 0;
          statsData.rp2pBytes = 0;
          statsData.rp2pUpBytes = 0;
          statsData.totalHttpBytes = 0;
          statsData.totalP2pBytes = 0;
          statsData.totalP2pUpBytes = 0;
          statsData.peers = 0;
        }

        try {
          statsWs.send(JSON.stringify(statsData));
        } catch(e) {
          // 전송 실패 시 재연결
          cleanupWebSocket();
          reconnectAttempts++;
          var delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);
          reconnectTimeout = setTimeout(connectStatsServer, delay);
        }
      }, 10000);

      // 페이지 가시성 변경 감지 (백그라운드 탭 처리)
      document.addEventListener('visibilitychange', function() {
        isPageVisible = !document.hidden;

        if (isPageVisible) {
          // 포그라운드로 돌아올 때 연결되어 있지 않으면 재연결
          if (!statsConnected || !statsWs || statsWs.readyState !== WebSocket.OPEN) {
            reconnectAttempts = 0;
            connectStatsServer();
          }
        } else {
          // 백그라운드로 가도 연결 유지 (모바일 대응)
          // cleanupWebSocket(); // 제거 - 연결 유지
          console.log('[WebSocket] Background mode - keeping connection alive');
        }
      });

// Chromecast 연결 시: 네이티브로 전환 + 싱크 보정(현재시간 유지)
player.on('chromecastConnected', function () {
  if (isCasting) return;
  isCasting = true;

  // ✅ 전환 직전 현재 위치 저장
  var t = 0;
  try { t = player.currentTime() || 0; } catch(e) { t = 0; }

  // ✅ hls.js 제거
  try { if (hls) { hls.destroy(); hls = null; } } catch(e) {}

  // ✅ 네이티브 HLS로 소스 교체
  attachNative();

  // ✅ 메타 로딩 후 시킹 → 재생
  player.one('loadedmetadata', function () {
    try { if (t > 0) player.currentTime(t); } catch(e) {}
    player.play();
  });
});

// Chromecast 종료 시: (선택) PC/안드면 다시 hls.js로 복귀
player.on('chromecastDisconnected', function () {
  isCasting = false;

  // iOS는 원래 네이티브니까 여기서 아무것도 안 함
  if (isIOS) return;

  // ✅ 다시 hls.js로 복귀(원하면 유지)
  try {
    // 현재 위치 유지
    var t = 0;
    try { t = player.currentTime() || 0; } catch(e) { t = 0; }

    // 네이티브 소스 제거 후 hls.js 재부착
    player.src({ src: "", type: "" });

    attachHlsJs();

    player.one('loadedmetadata', function () {
      try { if (t > 0) player.currentTime(t); } catch(e) {}
      // 필요하면 자동재생
      // player.play();
    });
  } catch(e) {}
});


      // 자막
<?php if (!empty($srt_url)) { ?>
player.on("loadedmetadata", function () {
  try {
    const track = player.addRemoteTextTrack({
      kind: "captions",
      src: "<?= htmlspecialchars($srt_url, ENT_QUOTES) ?>",
      srclang: "ko",
      label: "Korean",
      default: true
    }, false);

    // 🔥 강제 ON
    if (track && track.track) {
      track.track.mode = "showing";
    }
  } catch(e) {}
});
<?php } ?>



      // 플레이어 전환 버튼 추가 (상단 오른쪽 - player.php 스타일)
      player.ready(function() {
        // 플레이어 전환 시 저장된 시간으로 이동
        try {
          var switchData = localStorage.getItem('playerSwitchTime');
          if (switchData) {
            var data = JSON.parse(switchData);
            // 30초 이내에 저장된 시간만 사용 (오래된 데이터 무시)
            if (Date.now() - data.timestamp < 30000 && data.time > 0) {
              player.currentTime(data.time);
              localStorage.removeItem('playerSwitchTime');
            }
          }
        } catch(e) {}

        var topBtnWrap = document.createElement('div');
        topBtnWrap.className = 'vjs-switch-top-wrap';

        var switchBtn = document.createElement('button');
        switchBtn.className = 'vjs-switch-top-btn';
        switchBtn.title = '플레이어 전환';
        switchBtn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M21 3H3c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zm0 16H3V5h18v14zM10 8h4v8h-4z"/></svg>';

        switchBtn.addEventListener('click', function() {
          try {
            var t = player.currentTime() || 0;
            // 현재 재생 시간을 localStorage에 저장 (플레이어 간 공유용)
            localStorage.setItem('playerSwitchTime', JSON.stringify({
              time: t,
              timestamp: Date.now(),
              from: 1
            }));
            // 부모 페이지에 플레이어 전환 알림 (sessionStorage 저장용)
            if (window.parent && window.parent !== window) {
              window.parent.postMessage({ type: 'playerSwitch', player: 2 }, '*');
            }
          } catch(e) {}
          var params = window.location.search;
          var newUrl = 'index2.php' + params;
          window.location.href = newUrl;
        });

        topBtnWrap.appendChild(switchBtn);
        player.el().appendChild(topBtnWrap);
      });

      // 다음화 오버레이 10초 전 표시용
      var nextEpNotified = false;
      player.on('timeupdate', function() {
        var duration = player.duration() || 0;
        var currentTime = player.currentTime() || 0;
        if (duration > 15 && !nextEpNotified && (duration - currentTime) <= 10) {
          nextEpNotified = true;
          if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'videoNearEnd', player: 1, remaining: Math.ceil(duration - currentTime) }, '*');
          }
        }
      });

      // 시크 시 다시 알림 가능하도록
      player.on('seeked', function() {
        var duration = player.duration() || 0;
        var currentTime = player.currentTime() || 0;
        if ((duration - currentTime) > 10) nextEpNotified = false;
      });

      // 영상 종료 시 부모 페이지에 알림 (플레이어 정보 포함)
      player.on('ended', function() {
        if (window.parent && window.parent !== window) {
          window.parent.postMessage({ type: 'videoEnded', player: 1 }, '*');
        }
      });

      // 정리
      window.addEventListener('beforeunload', function(){
        // WebSocket 완전 정리 (좀비 연결 방지)
        cleanupWebSocket();

        // 통계 인터벌 정리
        if (window._statsIntervalPlayer2) {
          clearInterval(window._statsIntervalPlayer2);
          window._statsIntervalPlayer2 = null;
        }

        // 플레이어 정리
        try { if (hls) hls.destroy(); } catch(e) {}
        try { player.dispose(); } catch(e) {}
      });

      // 페이지 숨김(탭 닫기/전환) 시에도 정리
      window.addEventListener('pagehide', function(){
        cleanupWebSocket();
      });
    })();
  </script>

  <style>
    .vjs-switch-top-wrap {
      position: absolute;
      top: 10px;
      right: 10px;
      z-index: 2;
      opacity: 0;
      transition: opacity 0.2s;
    }
    .video-js:hover .vjs-switch-top-wrap,
    .video-js.vjs-user-active .vjs-switch-top-wrap {
      opacity: 1;
    }
    .vjs-switch-top-btn {
      width: 36px;
      height: 36px;
      background: rgba(0,0,0,0.5);
      border: none;
      border-radius: 4px;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 0;
    }
    .vjs-switch-top-btn:hover {
      background: rgba(0,0,0,0.7);
    }
    .vjs-switch-top-btn svg {
      width: 25px;
      height: 25px;
      fill: #fff;
    }
  </style>
</body>
</html>

