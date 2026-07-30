# 개발 계획 — 다중 음원 순차 재생 (플레이리스트)

작성일 2026-07-30 / 대상 `MSMP3FilePlayer` + `pulsar` `audiomulticast` 플러그인
선행 문서: [worklog.md](worklog.md)

---

## 1. 요구사항

### 1.1 확정 사양

**단일 음원 (N=1)**

```
 lead        음원 1        trail
|~~~~~|===================|~~~~~|
```

- `lead` 는 음원 시작 **전에만** 1회
- `trail` 은 음원이 **eof 에 도달했을 때만** 1회
- `pause` / `resume` / `stop` 에는 lead·trail 모두 **관여하지 않음**

**연속 음원 (N≥2)**

```
 lead      음원 1     gap    음원 2     gap    음원 3      trail
|~~~~~|=============|~~~~|=========|~~~~|===========|~~~~~~~~~|
```

- `lead` 는 **첫 음원 시작 전에만** 1회
- `trail` 은 **마지막 음원이 eof 에 도달했을 때만** 1회
- `gap` 은 **트랙과 트랙 사이 모든 경계에 동일한 값**으로 (N-1 회)
- `pause` / `resume` / `stop` 에는 lead·trail 모두 **관여하지 않음**
- 출력은 **단일 RTP 스트림**. 트랙 경계에서 세션/SSRC/타임스탬프 불연속 없음

> **해석 명시**: "첫 음원과 마지막 음원 사이" 를 **내부 경계 전체**(T1↔T2, T2↔T3, …,
> T(N-1)↔TN)로 해석했다. N=2 면 gap 1회, N=3 이면 2회다. 중간 트랙끼리만 넣고 T1↔T2 는
> 제외하는 해석은 의미가 성립하지 않아 배제했다.

**총 길이** = `lead` + Σ`Ti` + `(N-1) × gap` + `trail`

### 1.2 현행 동작과의 차이

| 사건 | 현행 | 요구사항 | 조치 |
|---|---|---|---|
| `OPEN` → 최초 `START` | lead O | lead O | 유지 |
| `pause` | **trail O** (`msmp3fileplayer.c:279-281`) | 없음 | **제거** |
| `resume` (`START`) | 없음 | 없음 | 유지 |
| `stop` | **trail O** (`audiograph_stop()` 이 `MS_PLAYER_PAUSE` 호출, `pulsar_audiomulticast.c:559`) | 없음 | pause 수정으로 자동 해결 |
| eof | trail O | trail O (마지막 트랙만) | 조건 추가 |
| 트랙 경계 | 개념 없음 | **gap** | **신규** |
| 배열 입력 | 없음 | 필요 | **신규** |

`MS_MP3FILE_PLAYER_STOP`(`mp3_player_stop`)은 소비자가 호출하지 않는다. stop 의 trail 은
pause 의 trail 을 물려받은 것이므로 **pause 에서 삽입을 제거하면 stop 도 함께 해결된다.**

---

## 2. 설계 결정

### 2.1 플레이리스트를 어디에 둘 것인가 → **필터 내부**

| | 소비자에서 eof 마다 재오픈 | 필터 내부 플레이리스트 |
|---|---|---|
| 트랙 경계 지연 | eof → async queue → handler 스레드 → CLOSE/OPEN/START. **수십 ms ~ 부정형** | 같은 tick 안에서 전환. **0** |
| gap 정확도 | 위 지연이 gap 에 그대로 더해짐 | 샘플 단위 정확 |
| 그래프 | ticker detach/attach 또는 재설정 필요 | 손대지 않음 |
| RTP | 재구성 시 SSRC/ts 불연속 위험 | 완전 연속 |
| 포맷 상이 시 | resampler 가 그래프 생성 시점에 고정돼 대응 불가 | 필터가 사전 검증 가능 |

→ **필터가 배열을 보관하고 `process()` 안에서 다음 트랙을 연다.** 소비자는 파일 배열을 넘기고
기존처럼 하나의 트랙으로 제어한다.

### 2.2 타임라인은 `d->ts` 가 아니라 "밀어넣은 샘플 수" 가 결정한다 (조사 결과)

```
MSMP3FilePlayer(d->ts)
  → msresample : 레이트 같으면 블록 통과(ts 보존) / 다르면 자기 카운터로 재스탬프
  → msopus_enc : MSBufferizer 로 PCM 을 이어붙이고 ptime 단위로 잘라 자기 카운터로 스탬프
                 (msopus.c:301-304)
  → msrtp      : mblk_get_timestamp_info(im) + tsoff 로 송신 (msrtp.c:332-349)
```

**Opus 인코더가 입력 타임스탬프를 버리고 누적 PCM 바이트 수로 RTP 타임스탬프를 만든다.** 따라서:

- 트랙 경계에서 ts 를 맞추는 산술이 **불필요**하다. PCM 을 끊김 없이 이어 붙이면 된다.
- lead/gap/trail 의 실제 길이는 **밀어넣은 0 샘플의 개수**가 결정한다.
- `d->ts` 는 이 그래프에서 관측되지 않는다. 규약은 유지하되 설계를 여기에 기대지 않는다.

### 2.3 포맷 이질성 정책 → **Phase 1 은 엄격 검증**

트랙마다 레이트/채널이 다르면 `audiograph_add()` 에서 1회 설정한 `MS_RESAMPLE` 입력 설정이
어긋난다.

- **Phase 1 (권장)**: `OPEN_PLAYLIST` 에서 전 트랙을 프로브해 rate/channels 가 트랙 0 과
  일치하는지 검사, 하나라도 다르면 `-1` → 소비자가 `notExistTrack` 으로 거절.
- **Phase 2 (선택)**: `msresample` 은 런타임 입력 rate/채널 변경을 지원한다
  (`msresample.c:181-218`). 트랙 전환 시 `MS_FILTER_OUTPUT_FMT_CHANGED` 를 통지하고 소비자가
  resampler 를 재설정하면 이종 포맷도 가능하나 검증 부담이 크다. 요구가 생길 때 착수.

### 2.4 gap 값의 출처 → **전역 설정 키**

기존 lead/trail 이 `audio_lead_silence_ms` / `audio_trail_silence_ms` 전역 설정에서
`addTrack` 시 source 로 복사되는 구조를 그대로 따라 `audio_gap_silence_ms` 를 신설한다.
기본값 **0** (= 갭리스, 기존 동작 보존). 요청별 오버라이드가 필요해지면 `addTrack` JSON 에
`gapsilence` 필드를 더하는 것으로 쉽게 확장 가능하다.

---

## 3. 확정 동작 규칙

| 사건 | lead | gap | trail | 비고 |
|---|---|---|---|---|
| `OPEN_PLAYLIST` 후 최초 `START` | **O** | - | - | 트랙 0 선두 진입 시 1회 |
| 트랙 N → N+1 전환 (N+1 ≤ 마지막) | X | **O** | X | 모든 내부 경계 |
| 마지막 트랙 eof (loop 없음) | - | X | **O** | trail 을 **다 흘려보낸 뒤** EOF 통지 |
| 마지막 트랙 eof (loop 있음) | O | X | O | trail → (loop_after) → lead 순. 경계에 gap 없음 |
| `MS_PLAYER_PAUSE` | X | X | X | **기존 trail 삽입 제거** |
| `PAUSE` 후 `START` (재개) | X | X | X | 멈춘 지점부터. gap 중이었다면 **남은 gap 부터 이어서** |
| `MS_MP3FILE_PLAYER_STOP` | X | X | X | 트랙 0 선두로 되감고 lead 재무장, 무음 미출력 |
| N=1 | O | - | O | gap 은 발생하지 않음 |

**lead 와 trail 의 성질이 다르다는 점**이 설계의 축이다.

- `lead` 는 `lead_silence_pending` **플래그** — "스트림이 선두에 있다" 는 상태 표시.
  `pause()` 는 되감지 않으므로 플래그가 이미 소진된 상태라 재개 시 자연히 미적용된다.
- `trail` 은 현재 **즉시 동작** — `mp3_player_pause()` 안에서 handler 스레드가 큐에 직접
  밀어 넣는다. 그래서 "재생이 멈추는 모든 순간" 에 딸려 나온다.
- 변경안은 `gap` 과 `trail` 을 모두 `process()`(ticker 스레드) 안에서만 생성하도록 옮긴다.

### 3.1 trail 을 pause/stop 에서 걷어내는 이유

요구사항 불일치 외에 두 가지 실질적 결함이 있다.

**(1) 짧은 pause 후 재개 시 RTP 타임스탬프 구간이 겹친다.**
pause 시 trail 1000ms 가 한 번에 방출되는데, Opus 인코더가 자기 카운터로 스탬프를 찍으므로
이 패킷들은 `now ~ now+1000ms` 구간을 점유한 채 **즉시** 나간다. 300ms 뒤 재개하면
`msrtp.c:339` 의 재조정이 걸리고(`|20ms - 300ms| > rate/5`), `tsoff = curts - packet_ts` 로
재베이스되어 재개 첫 패킷이 `now+300ms` 를 받는다 → 이미 보낸 무음과 **700ms 중첩**.
수신측 지터버퍼 구현에 따라 한쪽이 버려져 재개 직후 오디오가 유실된다.
일반화하면 **`trail_silence_ms` 보다 짧은 pause 는 그 차이만큼 재개 오디오를 손상시킨다.**
현재 설정 기본값이 `audio_trail_silence_ms = 0` 이라 드러나지 않았을 뿐이다.

**(2) 출력 큐 레이스.** `ms_filter_lock` 은 플레이어 자신의 `process()` 와만 배타적이고,
같은 큐를 드레인하는 리샘플러와는 배타적이지 않다.

→ 무음 생성을 전부 `process()` 안으로 옮기면 두 결함이 함께 사라진다.

**소비자에 미치는 영향**: `finished` 이벤트가 trail 길이만큼 늦게 발생한다(기존은 eof 즉시,
변경안은 trail 배출 완료 후). 의미상 이쪽이 맞으나, 클라이언트가 이벤트 시각으로 다음 동작을
스케줄한다면 확인이 필요하다.

### 3.2 `gap == 0` 과 `gap > 0` 의 차이

같은 코드 경로를 타지만 **트랙 경계의 성질이 근본적으로 다르다.** 각각의 고유 위험이 있다.

| | `gap == 0` (갭리스) | `gap > 0` |
|---|---|---|
| 경계 위치 | tick 중간. **한 mblk 안에 트랙 N 끝 + 트랙 N+1 시작이 섞인다** | 오디오끼리는 섞이지 않음 (무음이 분리) |
| eof tick 의 작업량 | 잔여 read + `mpg123_open` + **트랙 N+1 첫 read**(디코더 초기화 포함) | 잔여 read + `mpg123_open` + `memset`. 첫 read 는 다음 tick 이후로 밀림 |
| tick 예산 (리스크 A) | **최악** | 여유 있음 |
| 파형 불연속(클릭) | 이론상 위험 (원본 무음이 대개 완화 — 아래 주석) | 없음 |
| 무음 버스트 (§4.3) | 발생 안 함 | **N-1 회 발생 → 페이싱 필수** |
| pause 가 걸릴 수 있는 상태 | 트랙 재생 중만 | 트랙 재생 중 + **gap 배출 중** |
| EOF 통지 시점 | `trail==0` 이면 eof 와 같은 tick (현행과 동일) | trail 배출 완료 tick |

#### `gap == 0` 고유 고려사항

**(1) 한 mblk 에 두 트랙이 섞이므로 샘플 포맷이 반드시 동일해야 한다 — 기존 결함 발견.**
현재 `mp3_player_open()` 은 `mpg123_format_all()`(`:177`) 로 **모든 인코딩을 허용**하고
`d->samplesize = mpg123_encsize(encoding)` 로 받아쓴다. 그런데 다운스트림은 16bit 고정이다
(`msresample.c:151` 이 `/(2 * nchannels)` 하드코딩, opus enc 도 `SIGNAL_SAMPLE_SIZE`=2).
MP3 가 보통 16bit 로 디코딩되어 지금까지 드러나지 않았을 뿐, **float32 가 선택되면 현재도
그래프가 깨진다.** 플레이리스트에서는 여기에 더해 트랙마다 인코딩이 달라지면
`bytes = nsamples * d->samplesize` 로 예산을 잡은 뒤 mblk 중간에 샘플 크기가 바뀌어
`d->ts += filled / d->samplesize` 와 다운스트림 해석이 동시에 깨진다.

→ **인코딩을 16bit 로 고정한다.**

```c
static void mp3_setup_format(mpg123_handle *h) {
	const long *rates; size_t n, i;
	mpg123_format_none(h);
	mpg123_rates(&rates, &n);
	for (i = 0; i < n; i++)
		mpg123_format(h, rates[i], MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_16);
}
```

이러면 `d->samplesize` 는 항상 2 이고, 2.3 의 엄격 검증은 rate/channels 만 보면 충분해진다.

**(2) tick 예산이 가장 빡빡하다.** 리스크 A 가 `gap==0` 구성에 집중된다. 같은 tick 에
[잔여 read + `mpg123_open` + 다음 트랙 첫 read] 가 모두 들어가기 때문이다. 전환 소요시간
계측은 이 구성에서 반드시 확인한다.

> **원본 음원의 무음은 고려 대상이 아니다.** MP3 는 인코더 지연/패딩 때문에 파일 앞뒤에 수십
> ms 의 무음을 품고 있는 경우가 많다. 따라서 실제 트랙 사이 무음은
> `원본 뒤쪽 무음 + 우리 gap + 원본 앞쪽 무음` 이 된다. 이는 음원 자체의 성질이며 결함이
> 아니다 — 우리는 그 위에 gap 을 얹을지 말지만 정한다. 정확한 간격이 필요하면 원본을 트리밍할
> 일이지 코드가 개입할 문제가 아니다. 부수적으로, 이 무음이 남아 있으면 경계 파형 불연속으로
> 인한 클릭/팝 위험도 함께 낮아진다.

#### `gap > 0` 고유 고려사항

**(1) 무음 버스트가 N-1 회로 증폭된다.** §4.3 의 페이싱 수정이 선택이 아니라 필수가 되는 이유.

**(2) pause / stop 이 gap 도중에 걸릴 수 있다.**
- `pause`: `silence_remaining_bytes` 를 **보존** → 재개 시 남은 gap 부터 이어서 배출한 뒤
  다음 트랙 시작. (테스트 #6)
- `stop`: `silence_remaining_bytes = 0` 으로 **버린다** → 잔여 무음 없이 즉시 종료.

**(3) gap 이 tick 배수가 아니어도 무방하다.** gap=25ms, tick=10ms 면 2 tick 을 무음으로 채우고
3번째 tick 에 [무음 5ms + 트랙 N+1 PCM 5ms] 가 한 mblk 에 담긴다. 총량은 정확하다.
다만 worklog §5 의 **프레임 정렬 제약은 그대로 적용**된다 — `ms × rate` 가 1000 으로 나누어
떨어져야 한다(44.1kHz 면 10ms 단위). `silence_bytes_from_ms()` 가 프레임 단위로 내림하므로
어긋나면 설정값보다 미세하게 짧아진다.

**(4) 재생 중 `SET_GAP_SILENCE` 변경 시맨틱.** **다음 경계부터 적용**한다. 이미
`silence_remaining_bytes` 에 반영된 진행 중인 gap 은 바꾸지 않는다.

#### 공통 — 회귀 기준선

`lead == gap == trail == 0` 이면 **현행 단일 파일 동작과 바이트 단위로 동일**해야 한다.
페이싱·지연 EOF·인코딩 고정이 모두 무해 변경임을 이 조건으로 검증한다 (테스트 #11).

---

## 4. mediastreamer2 변경

### 4.1 헤더 API (`include/mediastreamer2/msmp3fileplayer.h`)

메서드 번호는 **재사용 금지** (worklog §2 의 전례). 0~8 사용 중 → 9 부터 할당.

```c
typedef struct _MSMP3PlaylistDesc {
	const char **files; /* nfiles 개의 경로. 필터가 내부에서 복사한다 */
	int nfiles;
} MSMP3PlaylistDesc;

/* 배열 재생. 성공 0, 파일 접근 실패/포맷 불일치 시 -1 */
#define MS_MP3FILE_PLAYER_OPEN_PLAYLIST   MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 9,  MSMP3PlaylistDesc)
#define MS_MP3FILE_PLAYER_GET_TRACK_COUNT MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 10, int)
#define MS_MP3FILE_PLAYER_GET_CUR_TRACK   MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 11, int)
/* 트랙과 트랙 사이에 넣을 무음(ms). 기본 0 = 갭리스 */
#define MS_MP3FILE_PLAYER_SET_GAP_SILENCE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 12, int)
```

- `MS_FILTER_METHOD` 의 argsize 는 8bit 마스크(`msfilter.h:599`)이므로 16바이트 구조체는 안전.
- 호출 규약은 `MSPinFormat` 과 동일하게 **구조체 주소를 넘긴다**.
- **`MS_MP3FILE_PLAYER_OPEN`(0) 은 그대로 둔다.** 내부적으로 `nfiles==1` 인 플레이리스트로
  위임 → 기존 호출자 무변경, N=1 경로와 N≥2 경로가 같은 코드를 탄다.

### 4.2 `PlayerData` 필드

```c
	char **tracks;                 /* strdup 배열 */
	int    ntracks;
	int    cur_track;
	int    lead_silence_ms;        /* 기존 */
	int    trail_silence_ms;       /* 기존 */
	int    gap_silence_ms;         /* 신규 */
	bool_t lead_silence_pending;   /* 기존 */
	int    silence_remaining_bytes;/* 신규: 아직 내보내지 못한 무음 (lead/gap/trail 공용) */
	bool_t finished;               /* 신규: 마지막 트랙 소진, trail 배출 중 */
```

`silence_remaining_bytes` 하나로 lead/gap/trail 을 모두 처리한다. 어느 무음인지 구분할 필요가
없기 때문이다 — 넣는 시점만 다르고 배출 방식은 동일하다.

### 4.3 무음 출력을 **버스트 → tick 분할**로 변경

현재 `mp3_player_put_silence()` 는 무음 전체를 `mblk` 하나로 한 tick 에 투입한다
(worklog §7). 500ms @48k 스테레오 = 88KB → RTP 25패킷 동시 방출.

`msrtp.c:339` 의 ts 재조정 임계값이 `rate/5`(200ms 상당)이고 비교가 **패킷당** 이루어지므로
(`diffts`=20ms, `difftime_ts`≈0 → 차이 20ms < 200ms) 버스트가 타임라인을 붕괴시키지는
**않는다**. 무음 길이 자체는 지금도 정확히 전달된다.

그러나 **gap 이 들어오면서 이 문제는 선택이 아니라 필수 수정이 된다.** N 트랙이면 버스트가
`1 + (N-1) + 1` 회 발생한다. 10트랙 · gap 500ms 면 재생 중 9번의 88KB 버스트가 터진다.
WAV 경로가 이미 쓰는 `pause_time` 패턴이 정답이다.

→ `silence_remaining_bytes` 카운터를 두고 tick 당 `bytes` 만큼만 채운다.

> **주의 — 이 변경을 단독으로 하면 trail 무음이 사라진다.**
> 현재 eof 경로는 무음 블록을 큐에 넣고 **곧바로** `MS_MP3FILE_PLAYER_EOF` 를 통지한다.
> 소비자는 이 통지로 `internal_stopTrack` → `audiograph_stop()`(ticker detach + 필터 파괴)
> 을 수행한다. 지금은 무음이 한 tick 에 전부 나가므로 우연히 살아남는다. 25 tick 에 나눠
> 보내면 그래프가 먼저 헐린다.
> **⇒ EOF 통지는 `silence_remaining_bytes == 0` 이 된 뒤로 미뤄야 한다** (4.4 참조).
> 두 변경은 **반드시 같은 커밋**에서.

### 4.4 `mp3_player_process()` 재작성

한 tick 분(`bytes`)을 **무음 / PCM / 다음 트랙 PCM** 으로 이어 채운다.

```c
static int silence_bytes_from_ms(PlayerData *d, int ms) {
	/* int 오버플로 방지: 64bit 로 계산 후 프레임 정렬 (worklog §5 의 11초 상한 해소) */
	int frame = d->samplesize * d->nchannels;
	int64_t b = (int64_t)ms * d->rate * frame / 1000;
	if (b > INT_MAX) b = (INT_MAX / frame) * frame;
	return (int)(b - (b % frame));
}

static void mp3_player_process(MSFilter *f) {
	PlayerData *d = f->data;
	/* nsamples / bytes 계산은 기존 그대로 */
	ms_filter_lock(f);
	if (d->state != MSPlayerPlaying || !d->is_mp3) goto end;

	mblk_t *om = allocb(bytes, 0);
	int filled = 0;

	while (filled < bytes) {
		if (d->silence_remaining_bytes > 0) {            /* (1) 무음 배출 (lead/gap/trail 공용) */
			int n = MIN(bytes - filled, d->silence_remaining_bytes);
			memset(om->b_wptr + filled, 0, n);
			filled += n;  d->silence_remaining_bytes -= n;
			continue;
		}
		if (d->finished) break;                          /* (2) 전부 끝남 */
		if (d->lead_silence_pending) {                   /* (3) lead — 첫 트랙 선두에서 1회 */
			d->lead_silence_pending = FALSE;
			if (d->lead_silence_ms > 0) {
				d->silence_remaining_bytes = silence_bytes_from_ms(d, d->lead_silence_ms);
				continue;
			}
		}
		size_t done = 0;                                 /* (4) PCM */
		int err = mpg123_read(d->mpg123, om->b_wptr + filled, bytes - filled, &done);
		filled += (int)done;

		if (err == MPG123_DONE) {                        /* (5) 현재 트랙 eof */
			if (mp3_advance_track(f, d) == 0) {          /*     다음 트랙 진입 성공 */
				if (d->gap_silence_ms > 0)               /*     → gap */
					d->silence_remaining_bytes = silence_bytes_from_ms(d, d->gap_silence_ms);
				continue;                                /*     gap → 다음 트랙 PCM 순으로 채워짐 */
			}
			if (d->trail_silence_ms > 0)                 /*     마지막 트랙이었음 → trail */
				d->silence_remaining_bytes = silence_bytes_from_ms(d, d->trail_silence_ms);
			d->finished = TRUE;
			continue;
		}
		if (err != MPG123_OK && err != MPG123_NEW_FORMAT) {
			ms_warning("MSMP3FilePlayer[%p]: read error %d on track %d", f, err, d->cur_track);
			d->finished = TRUE; continue;
		}
		if (done == 0) break;                            /* 방어 */
	}

	if (filled > 0) {
		om->b_wptr += filled;
		mblk_set_timestamp_info(om, d->ts);
		d->ts += filled / d->samplesize;                 /* ← 부분 읽기 버그 수정 (5장) */
		ms_queue_put(f->outputs[0], om);
	} else freemsg(om);

	if (d->finished && d->silence_remaining_bytes == 0) { /* trail 배출 완료 후에만 */
		if (d->loop_after >= 0 && mp3_open_track(f, d, 0) == 0) {
			d->finished = FALSE;
			d->lead_silence_pending = TRUE;              /* 루프 재시작 → lead. gap 아님 */
		} else {
			d->state = MSPlayerPaused;
			ms_filter_notify_no_arg(f, MS_PLAYER_EOF);
			ms_filter_notify_no_arg(f, MS_MP3FILE_PLAYER_EOF);
		}
	}
end:
	ms_filter_unlock(f);
}
```

이 구조가 요구사항을 만족하는 근거:

- **lead** 는 `lead_silence_pending` 이 참일 때만, 그것도 (3) 에서 즉시 `FALSE` 로 소진되므로
  플레이리스트 전체에서 1회. 플래그는 `open_playlist()` 와 루프 재시작에서만 세팅된다.
- **gap** 은 (5) 에서 `mp3_advance_track()` 이 성공했을 때만 — 즉 **다음 트랙이 존재할 때만**
  삽입된다. 마지막 트랙 eof 에서는 이 분기를 타지 않으므로 gap 이 붙지 않는다. N=1 이면
  `mp3_advance_track()` 이 항상 실패하므로 gap 은 구조적으로 발생 불가.
- **trail** 은 `mp3_advance_track()` 실패, 즉 **마지막 트랙 eof 에서만** 삽입된다.
- **pause/resume/stop** 은 이 함수를 거치지 않으므로 어떤 무음도 만들지 않는다. pause 는
  `state` 만 바꾸고, `silence_remaining_bytes` 는 보존되므로 gap 도중에 멈췄다면 재개 시
  **남은 gap 부터** 이어진다.

### 4.5 `mp3_open_track()` / `mp3_advance_track()`

```c
static int mp3_open_track(MSFilter *f, PlayerData *d, int index) {
	long rate = 0; int ch = 0, enc = 0;
	mpg123_close(d->mpg123);                 /* 미개방 핸들에도 안전 */
	if (mpg123_open(d->mpg123, d->tracks[index]) != MPG123_OK) return -1;
	if (mpg123_getformat(d->mpg123, &rate, &ch, &enc) != MPG123_OK) return -1;
	if (index > 0 && ((int)rate != d->rate || ch != d->nchannels)) return -1; /* Phase 1 엄격 */
	d->rate = (int)rate; d->nchannels = ch;
	d->samplesize = mpg123_encsize(enc);
	d->cur_track = index;
	return 0;
}

/* 다음 트랙으로 진입. 성공 0, 더 없거나 전부 실패하면 -1 */
static int mp3_advance_track(MSFilter *f, PlayerData *d) {
	int i = d->cur_track + 1;
	for (; i < d->ntracks; i++) {
		if (mp3_open_track(f, d, i) == 0) return 0;
		ms_error("MSMP3FilePlayer[%p]: cannot open track %d (%s), skipping", f, i, d->tracks[i]);
	}
	return -1;
}
```

전 트랙을 `OPEN_PLAYLIST` 에서 이미 검증했으므로 중간 실패는 "재생 중 파일이 사라진" 이례적
상황이다. 재생 전체를 중단시키기보다 **해당 트랙을 건너뛰고 계속**한다. 남은 트랙이 모두
실패하면 마지막 트랙 취급이 되어 trail 이 붙고 정상 종료된다.

> gap 바이트를 `mp3_advance_track()` **이후**에 계산하므로 새 트랙의 rate 를 쓴다. Phase 1 은
> 전 트랙 포맷이 동일하므로 차이가 없다. Phase 2 로 갈 때 재검토 대상.

### 4.6 `open_playlist` / `stop` / `pause` / `close`

- **`open_playlist`**: 경로 배열 `strdup` 복사 → 전 트랙 순회 프로브(open / getformat /
  `mpg123_length` 로 길이 누적 / close) → 하나라도 실패하거나 포맷 불일치면 정리 후 `-1` →
  성공 시 트랙 0 을 열고 `state = MSPlayerPaused`, `lead_silence_pending = TRUE`,
  `cur_track = 0`, `finished = FALSE`, `silence_remaining_bytes = 0`.
  프로브에서 얻은 총 길이로 `d->duration = lead + Σ길이 + (N-1)×gap + trail` 을 채워
  `MS_PLAYER_GET_DURATION` 을 MP3 에서도 유효하게 만든다(현재는 MP3 에서 항상 0).
  *단, gap/trail 이 `OPEN` 이후에 설정될 수 있으므로 duration 은 조회 시점에 계산하는 편이
  안전하다.*
- **`stop`**: 트랙 0 재오픈, `lead_silence_pending = TRUE`,
  `silence_remaining_bytes = 0`(**진행 중이던 gap/trail 은 버린다**), `finished = FALSE`,
  `state = MSPlayerPaused`. **무음 미출력.**
- **`pause`**: `state = MSPlayerPaused` 만. **`mp3_player_put_silence()` 호출 삭제.**
  `silence_remaining_bytes` 는 **보존**한다 → gap 도중이었다면 재개 시 남은 gap 부터 이어짐.
- **`close`**: `mpg123_close` + `mpg123_delete` + 트랙 배열 free + 인덱스/카운터 초기화.
  (현재 `close` 는 mpg123 핸들을 전혀 정리하지 않아 재오픈 시 누수 — 함께 수정)
- **`set_gap_silence`**: `d->gap_silence_ms` 대입. **다음 경계부터 적용**되며 진행 중인 gap 은
  바꾸지 않는다. lead/trail 세터와 동일 형태.
- **인코딩 고정**: 핸들 생성 직후 `mp3_setup_format()`(3.2) 호출로 16bit 강제. 이로써
  `d->samplesize == 2` 가 불변이 되어 트랙 경계에서 샘플 크기가 바뀔 여지가 없어진다.

---

## 5. 함께 고칠 기존 결함

| 위치 | 내용 | 이번 작업과의 관계 |
|---|---|---|
| `msmp3fileplayer.c:367-368` | eof 부분 읽기에서 `done < bytes` 인데 `d->ts += nsamples`(전체 tick) 로 과전진 | 트랙마다 1회씩 누적 → **반드시 수정** (4.4 반영) |
| `:369` | `done == 0` 이어도 빈 mblk 를 큐에 투입 | 4.4 의 `filled > 0` 조건으로 해소 |
| `:167` | `mpg123_init()` 실패 경로가 `int` 함수에서 `return;` | 경로 재작성 중 자연히 수정 |
| `:185` | `mpg123_getformat()` 에 `long*` 대신 `int*`(`&d->rate`) 전달 | 트랙마다 호출하므로 **반드시 수정** (4.5 반영) |
| `:177` | `mpg123_format_all()` 로 전 인코딩 허용. 다운스트림은 16bit 고정인데 float32 등이 선택되면 그래프가 깨짐 | `gap==0` 에서 mblk 내 포맷 혼재까지 유발 → **반드시 수정** (3.2 반영) |
| `:279-281` | `pause()` 의 trail 삽입 | 요구사항상 **삭제** |
| `close()` | mpg123 핸들 미정리 | 4.6 |
| worklog §5 | 무음 ms 상한 ~11초 (int 오버플로) | 4.4 의 64bit 계산으로 해소 |

---

## 6. 소비자(pulsar `audiomulticast`) 변경

`apps/voipserver/source/plugins/pulsar_audiomulticast.c`

### 6.1 JSON API

```jsonc
{
  "request": "addTrack",
  "id": 123,
  "filenames": ["/a.mp3", "/b.mp3", "/c.mp3"],  // 신규. 순서대로 재생
  "filename": "/a.mp3",                          // 기존. filenames 없을 때만 사용
  "remoteip": "239.0.0.1", "remoteport": 5004,
  "autoplay": true
}
```

- `add_parameters[]` 에서 `filename` 의 `REQUIRED` 를 해제하고 `filenames`(`JSON_ARRAY`)를
  추가한 뒤, **둘 다 없으면 `MISSING_ELEMENT`** 로 수동 검사.
- 배열 원소는 전부 비어있지 않은 문자열, 개수 상한(예: 64) 검사.
- `stopTrack` / `pauseTrack` / `playTrack` 및 이벤트(`playing`/`paused`/`stopped`/`finished`)는
  **그대로**. 플레이리스트 전체가 하나의 `id` 로 제어되고, `finished` 는 마지막 트랙의 trail
  까지 끝난 뒤 1회 발생한다.

### 6.2 설정 (`config/plugin.audiomulticast.jcfg`)

```
audio_lead_silence_ms  = 500   ; 첫 음원 앞에 1회
audio_gap_silence_ms   = 0     ; 트랙과 트랙 사이마다 (신규)
audio_trail_silence_ms = 0     ; 마지막 음원 뒤에 1회
```

권장 범위는 worklog §5 와 동일하다: **20 ~ 11000 ms, 20 단위.** 11025Hz 를 제외한 모든 MP3
레이트에서 정확히 떨어지고 Opus ptime(20ms)과도 정렬된다. (4.4 의 64bit 계산으로 상한 자체는
사라지지만, 과도한 값은 지터버퍼 부담이므로 권장 범위는 유지한다.)

### 6.3 코드

| 위치 | 변경 |
|---|---|
| 전역 (`:216-217`) | `audio_gap_silence` 추가 |
| 설정 파싱 (`:934-946`) | `audio_gap_silence_ms` 키 파싱 추가 |
| `pulsar_audiomulticast_source` (`:284`) | `char* mp3_file` → `char** mp3_files; int nfiles;` / `audio_gap_silence` 필드 추가 |
| `..._source_free` (`:649`) | `g_free(source->mp3_file)` → 루프 free + 배열 free |
| `audiograph_add` 사전검증 (`:376-396`) | 전 파일에 대해 존재/가독/ID3·프레임싱크 검사. 실패 시 인덱스와 경로 보존 |
| `audiograph_add` (`:410`) | `MS_MP3FILE_PLAYER_OPEN` → `MS_MP3FILE_PLAYER_OPEN_PLAYLIST`(구조체 주소 전달) |
| `audiograph_add` (`:416-424`) | `MS_MP3FILE_PLAYER_SET_GAP_SILENCE` 호출 추가 |
| `notExistTrack` 이벤트 (`:1448-1453`) | `result` 에 `"index"`, `"filename"` 추가 |
| `query_session` (`:721`) | `"filenames"` 배열 추가, `"filename"` 은 첫 트랙으로 유지 |
| `addTrack` 핸들러 (`:1168-1184`) | `filenames` 파싱 → `mp3_files` 채우기, 없으면 `filename` 1개. `audio_gap_silence` 복사 |

`audiograph_play` / `audiograph_pause` / `audiograph_stop` 은 **무변경**.

---

## 7. 하위 호환성 — 단일 음원 경로 유지

**단일 음원 재생은 계속 지원해야 한다.** 세 레이어로 나눠 본다.

### 7.1 완전히 유지되는 것

| 레이어 | 항목 | 보장 방식 |
|---|---|---|
| 필터 API | `MS_MP3FILE_PLAYER_OPEN`(0) | **제거하지 않는다.** `nfiles==1` 인 플레이리스트로 위임 |
| 필터 API | `START` / `PAUSE` / `LOOP` / `SET_LEAD_SILENCE` / `SET_TRAIL_SILENCE` / `GET_SAMPLE_RATE` / `GET_NCHANNELS` | 시그니처·번호 무변경 |
| 필터 ABI | 메서드 번호 0~8 | 재사용 없음. 신규는 9~12 |
| 이벤트 | `MS_MP3FILE_PLAYER_EOF` / `MS_PLAYER_EOF` | 무변경 |
| 소비자 API | `addTrack` 의 `"filename"` 문자열 | `filenames` 없을 때 폴백. 1개짜리 배열로 변환 |
| 소비자 API | `playTrack` / `pauseTrack` / `stopTrack` | 무변경 |
| 소비자 이벤트 | `playing` / `paused` / `stopped` / `finished` / `notExistTrack` | 이름·구조 무변경 (`notExistTrack` 에 필드만 추가) |
| 설정 | 기존 `.jcfg` (신규 키 없음) | `audio_gap_silence_ms` 기본 0 |

**N=1 과 N≥2 가 같은 코드를 탄다.** `OPEN` 을 별도 경로로 남기지 않고 위임하므로, 단일 음원
경로만 썩는 일이 없다. gap 은 `mp3_advance_track()` 성공 시에만 삽입되는데 N=1 에서는 항상
실패하므로 **구조적으로 발생 불가**다 (§4.4).

### 7.2 의도적으로 바뀌는 동작 (단일 음원에도 적용)

요구사항에 따른 변경이므로 "호환성 파기" 가 아니라 **명시적 사양 변경**이다.

| 변경 | 영향 | 근거 |
|---|---|---|
| `pause` / `stop` 시 trail 미출력 | `audio_trail_silence_ms > 0` 으로 운영 중이면 pause/stop 때 나오던 무음이 사라짐 | 요구사항. 현재 기본값 0 (§1.2, §3.1) |
| `finished` 이벤트가 trail 만큼 지연 | 클라이언트가 이벤트 시각으로 다음 동작을 스케줄하면 영향 | trail 을 끝까지 보내려면 불가피 (§4.3) |
| lead/trail 이 버스트 → tick 분할 배출 | 총 길이 동일, **패킷 타이밍만 균등해짐** | §4.3 |
| 디코딩 인코딩 16bit 고정 | float32 가 선택되던 파일이 있었다면 정상화 | 기존 결함 수정 (§3.2-(1)) |
| eof 부분 읽기 `ts` 정정 | 미세한 타임스탬프 과전진 제거 | 기존 결함 수정 (§5) |
| `MS_PLAYER_GET_DURATION` 이 MP3 에서 유효값 반환 | 기존 0 → 실제 길이 | 개선 (§4.6) |

**운영 확인 필요**: 배포 전 실제 `plugin.audiomulticast.jcfg` 의
`audio_trail_silence_ms` 값을 확인한다. 0 이면 §7.2 첫 두 항목의 체감 영향이 없다.

### 7.3 검증

§10.3 (테스트 #11~#15) 이 이 절의 검증 항목이다. 특히 **#11(바이트 단위 동일)** 을 기준선으로
삼아, 페이싱·지연 EOF·인코딩 고정이 모두 무해 변경임을 입증한다.

---

## 8. 리스크

**(A) ticker 스레드에서의 `mpg123_open`.** 트랙 전환이 `process()` 안에서 일어나므로 tick(10ms)
안에 파일 열기 + 포맷 파싱이 끝나야 한다. `OPEN_PLAYLIST` 프로브에서 전 파일을 이미 한 번
읽으므로 page cache 에 올라와 있어 통상 1ms 미만이지만, 대용량/네트워크 파일시스템에서는
오버런 가능. **대응**: Phase 1 은 인라인 오픈 + 전환 소요시간 계측 로그(임계 초과 시
`ms_warning`). 문제가 확인되면 Phase 2 로 사전 오픈(핸들 2개 교대) 또는 워커 스레드.
**`gap == 0` 구성에서 가장 위험하다** — 같은 tick 에 [잔여 read + open + 다음 트랙 첫 read]
가 모두 들어간다. `gap > 0` 이면 다음 트랙 첫 read 가 뒤 tick 으로 밀려 여유가 생긴다(§3.2).
따라서 계측은 **`gap == 0` 구성에서 반드시** 확인한다.

**(B) 무음 페이싱과 EOF 통지 순서.** 4.3 의 경고 그대로. 두 변경은 **반드시 같은 커밋**에서.

**(C) ABI.** 메서드 번호 9~12 신규 할당(재사용 없음)이므로 구 바이너리가 새 `.so` 를 써도
조용한 오동작은 없다(미지원 메서드 → `-1`). 새 헤더로 빌드한 소비자 + 구 `.so` 조합은
`OPEN_PLAYLIST` 가 `-1` 을 반환해 `notExistTrack` 으로 드러난다. worklog §8 대로
**헤더와 `.so` 를 함께 배포**.

**(D) `pause` 의 trail 제거는 동작 변경.** 현재 설정 기본값이
`audio_trail_silence_ms = 0` 이라 실환경 영향은 없을 가능성이 높으나 운영 설정 확인 필요.

**(E) `finished` 이벤트 지연.** 3.1 말미 참조.

---

## 9. 작업 순서

| # | 작업 | 산출물 |
|---|---|---|
| 1 | 헤더에 `MSMP3PlaylistDesc` + 메서드 9~12 추가 | `msmp3fileplayer.h` |
| 2 | `PlayerData` 확장, `mp3_setup_format()`(16bit 고정) / `mp3_open_track()` / `mp3_advance_track()` / `open_playlist()` 구현. `OPEN` 은 1개짜리로 위임 | `msmp3fileplayer.c` |
| 3 | 무음을 `silence_remaining_bytes` 페이싱으로 전환, `put_silence()` 제거 | 〃 |
| 4 | `process()` 재작성 (트랙 전환, lead/gap/trail, 지연 EOF, ts 수정) | 〃 |
| 5 | `pause` trail 제거 / `stop` 되감기 / `close` 정리 / `set_gap_silence` | 〃 |
| 6 | 5장 부수 결함 수정 | 〃 |
| 7 | 필터 단독 검증 (9장) | 테스트 로그 |
| 8 | 소비자 `filenames` 파싱·검증·구조체 변경, `audio_gap_silence_ms` 배선 | `pulsar_audiomulticast.c`, `.jcfg` |
| 9 | worklog 추가 | 문서 |

1~7 은 이 리포, 8~9 는 `pulsar` 리포. **7 을 통과하기 전에 8 로 넘어가지 않는다** —
소비자를 먼저 고치면 실패 원인 분리가 어려워진다.

---

## 10. 테스트 계획

필터 단독 검증에는 플러그인에 이미 있는 `MS_FILE_REC` 경로(`pulsar_audiomulticast.c:457`
`#if 0` 블록)를 켜서 그래프 출력을 `test.wav` 로 받아 구간 길이를 재는 것이 가장 빠르다.
(`tester/` 에는 MP3 플레이어 테스트가 없다.)

**gap 유무를 축으로 나눈다.** 두 경우가 다른 코드 경로를 타지는 않지만 위험이 서로 다르므로
(§3.2) 주요 시나리오는 양쪽 모두에서 확인한다.

### 10.1 길이·구성 검증

| # | 시나리오 | 기대 |
|---|---|---|
| 1 | **N=1**, lead 500 / trail 1000 / **gap 500** | `500 + T1 + 1000`. **gap 이 나타나지 않을 것** |
| 2 | **N=3**, lead 500 / **gap 300** / trail 1000 | `500 + T1 + 300 + T2 + 300 + T3 + 1000` (±1 tick) |
| 3 | **N=3**, lead 500 / **gap 0** / trail 1000 | `500 + ΣTi + 1000`. **우리가 삽입한 무음 0** — 원본이 품은 앞뒤 무음은 그대로 남는 것이 정상 (§3.2 주석) |
| 4 | N=2, gap 25ms (tick 비배수) | 총량 정확. 44.1kHz 면 프레임 정렬로 미세하게 짧아지는 것까지 확인 |

### 10.2 제어 조작

| # | 시나리오 | 기대 |
|---|---|---|
| 5 | 트랙 2 재생 중 `pauseTrack` → `playTrack` (gap 0 / gap 300 양쪽) | 무음 삽입 없음, 멈춘 지점부터 이어짐 |
| 6 | **gap 구간에서 `pauseTrack`** → `playTrack` | 남은 gap 부터 이어서 배출 후 다음 트랙 시작 |
| 7 | **gap 구간에서 `stopTrack`** | 잔여 gap 버리고 즉시 종료 |
| 8 | 재생 중 `stopTrack` | trail 없이 즉시 종료, `stopped` 1회 |
| 9 | trail 500ms 설정 후 pause → 200ms 뒤 resume | 타임스탬프 중첩·오디오 유실 없음 (§3.1-(1) 회귀) |
| 10 | loop 활성, N=3, gap 300 | 반복 사이 간격 = trail + lead. **경계에 gap 없음** |

### 10.3 하위 호환 (§7)

**단일 음원 경로가 이번 작업의 회귀 기준선이다.** 아래를 통과하지 못하면 배포 불가.

| # | 시나리오 | 기대 |
|---|---|---|
| 11 | **lead=gap=trail=0**, 구 `filename` 문자열 요청 | **현행 출력과 바이트 단위 동일** (기준선) |
| 12 | N=1, lead 500 / trail 1000, 구 `filename` 요청 | 재생 구간·총 길이 현행과 동일. **차이는 pause/stop 시 trail 미출력뿐** |
| 13 | N=1, `MS_MP3FILE_PLAYER_OPEN`(0) 직접 호출 (구 소비자 바이너리 + 새 `.so`) | 정상 재생. 위임 경로가 살아 있음을 확인 |
| 14 | 새 소비자 + **구 `.so`** | `OPEN_PLAYLIST` 가 `-1` → `notExistTrack`. 조용한 오동작 없음 |
| 15 | 기존 `.jcfg`(`audio_gap_silence_ms` 키 없음) | gap 0 으로 기본값 적용, 경고 없이 기동 |

### 10.4 예외·오류

| # | 시나리오 | 기대 |
|---|---|---|
| 16 | 중간에 존재하지 않는 파일 | `OPEN_PLAYLIST` 실패 → `notExistTrack`(index 포함), 그래프 미생성 |
| 17 | 44.1k + 48k 혼합 | Phase 1 정책대로 거절 |
| 18 | 인코딩 상이 파일 혼합 | `mp3_setup_format()` 으로 전부 16bit 출력됨을 로그로 확인 (§3.2-(1)) |
| 19 | 재생 중 트랙 3 파일 삭제 (N=5) | 트랙 3 건너뛰고 4 로 진행, gap 정상, `finished` 정상 |

### 10.5 계측

| # | 시나리오 | 기대 |
|---|---|---|
| 20 | 수신측 RTP 캡처 (gap 300, N=3) | 시퀀스/타임스탬프 연속, 무음 구간이 버스트가 아닌 균등 페이싱 |
| 21 | 트랙 전환 소요시간 로그 — **`gap 0` 구성 필수** | tick(10ms) 대비 여유 확인 (리스크 A) |
| 22 | `finished` 발생 시각 | eof + trail 이후임을 확인 (리스크 E) |

---

## 11. 유보 항목

- **`gap > 0` 일 때 다음 트랙 오픈을 gap 마지막 tick 으로 지연** — 리스크 A 를 더 줄일 수
  있으나, gap 을 쓰면 이미 여유가 있어 복잡도 대비 이득이 작다.
- **원본 음원의 앞뒤 무음 트리밍** — 정확한 간격이 요구될 때에 한해. 코드가 아니라 음원 준비
  단계의 문제다.
- `trackChanged` 이벤트 — 통지 콜백이 ticker 스레드에서 돌아 메시지 할당이 필요하고 현재
  클라이언트가 소비하지 않음. 필요해지면 Phase 2.
- 트랙별 개별 gap 값 — 요구는 "동일한 silence" 이므로 단일 값. 필요해지면 배열로 확장.
- 요청별 gap 오버라이드(`addTrack` JSON `gapsilence`) — 2.4 참조. 전역 설정으로 충분한지 확인 후.
- 이종 포맷 자동 대응 (2.3 Phase 2).
- 재생 중 플레이리스트 동적 추가/삭제.
