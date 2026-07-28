# Worklog

## 2026-07-29 — MP3 플레이어 무음 삽입 기능 분리 및 루프 타임스탬프 수정

관련 커밋

| 커밋 | 내용 |
|---|---|
| `cee4bbf` | 음원 시작 무음과 음원 종료 무음삽입기능 분리 |
| `1a0119e` | 유령간격문제 해결 |

변경 파일: `include/mediastreamer2/msmp3fileplayer.h`, `src/audiofilters/msmp3fileplayer.c`

---

### 1. 배경

`MSMP3FilePlayer` 는 이 포크에만 있는 커스텀 필터로, `pulsar` 프로젝트의 `apps/voipserver`
(`source/plugins/pulsar_audiomulticast.c`) 가 유일한 소비자다. 해당 플러그인은 다음 그래프로
MP3 를 Opus RTP 멀티캐스트로 송출한다.

```
MS_MP3FILE_PLAYER → MS_RESAMPLE → MS_OPUS_ENC → MS_RTP_SEND
```

기존 `MS_MP3FILE_PLAYER_SET_SILENCE` 는 무음을 **파일 끝에만** 삽입할 수 있었고, 앞쪽에 넣을
수단이 없었다. 재생 시작 전 무음이 필요해져 기능을 앞/뒤로 분리했다.

---

### 2. 무음 삽입 메서드 분리

`MS_MP3FILE_PLAYER_SET_SILENCE`(7) 를 제거하고 두 개로 나눴다.

| 메서드 | 번호 | 삽입 시점 |
|---|---|---|
| `MS_MP3FILE_PLAYER_SET_LEAD_SILENCE` | 7 | `OPEN` 직후 첫 tick, 그리고 매 루프 반복 시작 |
| `MS_MP3FILE_PLAYER_SET_TRAIL_SILENCE` | 8 | 매 eof, 그리고 `MS_PLAYER_PAUSE` |

**주의**: 7번은 원래 `SET_SILENCE`(= 뒤 무음)의 번호였다. 재빌드하지 않은 구 바이너리가 7번을
호출하면 에러 없이 **앞 무음**이 설정된다. `.so` 교체 시 소비자도 반드시 함께 재빌드할 것.

#### 구현 방식

세 군데에 중복돼 있던 무음 블록 생성 코드를 헬퍼 하나로 통합했다.

```c
static void mp3_player_put_silence(MSFilter *f, PlayerData *d, int duration_ms) {
	int silence_bytes = duration_ms * d->rate * d->nchannels * d->samplesize / 1000;
	int silence_samples = silence_bytes / d->samplesize;
	...
	mblk_set_timestamp_info(silence_block, d->ts);
	d->ts += silence_samples;      /* 이번 변경으로 추가 */
	ms_queue_put(f->outputs[0], silence_block);
}
```

앞 무음은 `lead_silence_pending` 플래그로 **"스트림이 파일 선두에 있는 상태"** 를 표시하고
`process()` 의 첫 tick 에서 소진한다.

- 플래그 세팅: `open()` MP3 성공 시, 루프 seek 성공 시
- 플래그 소진: `process()` 의 `is_mp3` 분기 진입부
- `pause()` → `start()` 재개 시에는 삽입되지 않음 (선두가 아니므로)

큐 조작을 ticker 스레드(`process()`) 안에서 하므로 `start()` 에서 직접 넣는 것보다 안전하다.
또 플래그와 duration 값을 분리했기 때문에 `SET_LEAD_SILENCE` 를 `OPEN` 전후 어느 쪽에서
호출해도 동작한다.

뒤 무음은 기존 로직(단일 블록)을 그대로 유지했다.

---

### 3. 무음 블록 타임스탬프 전진

기존 코드는 무음 블록에 `d->ts` 를 붙이기만 하고 `d->ts` 를 증가시키지 않았다. 그 결과 무음
구간과 뒤따르는 오디오가 같은 타임스탬프 구간을 갖게 되어, 수신 측에서 무음 간격이 제대로
반영되지 않았다.

정상 재생 경로가 매 tick `d->ts += nsamples` 하는 것과 동일한 규약(전 채널 합산 샘플 수)으로
`d->ts += silence_samples` 를 추가했다.

---

### 4. 루프 타임스탬프 이중 전진 제거 (유령 간격)

#### 증상

루프 재생 시 반복 사이에 **파일 길이와 동일한 길이의 침묵**이 끼어들었다. 3초 MP3 라면
"3초 재생 → 3초 침묵 → 3초 재생 → ..." 으로 6초 주기가 된다.

#### 원인

eof 처리부의 다음 코드다.

```c
if (d->total_samples == 0) d->total_samples = d->ts;   /* N 저장 */
...
d->ts += d->total_samples;                             /* ts 가 2N 이 됨 */
```

재생 중 `d->ts += nsamples` 로 이미 파일 길이(N)만큼 전진한 상태에서 다시 N 을 더하고 있었다.
타임스탬프를 되감지 않으려는 의도로 보이나, 정상 경로가 이미 전진시킨다는 점을 놓친 것으로
보인다.

#### 조건부로만 드러났던 이유

`msresample.c` 는 두 경로로 동작한다.

| 조건 | 동작 | 플레이어 ts |
|---|---|---|
| `output_rate == input_rate` | 블록을 그대로 통과 | **보존** |
| 레이트가 다름 | `mblk_set_timestamp_info(om, dt->ts); dt->ts += outlen;` | **버려짐** |

즉 리샘플러는 실제 리샘플링이 일어날 때 자기 카운터로 타임스탬프를 재생성한다. 따라서 유령
간격은 **MP3 원본이 target 레이트와 같을 때(48kHz)만** 실제로 들렸고, 44.1kHz 파일에서는
리샘플러가 가려주고 있었다.

원본 레이트에 따라 동작이 갈리는 상태였으므로, 어느 경우든 동일하게 만들기 위해 제거했다.

#### 조치

- `d->ts += d->total_samples;` 삭제
- 유일한 소비처가 사라진 `total_samples` 필드 및 `open()` 초기화 삭제
- 매 루프마다 stdout 에 찍히던 디버그 `printf` 삭제

이제 반복 사이 간격은 **삽입한 무음 블록만으로 결정된다.**

---

### 5. 파라미터 범위

무음 값은 밀리초 단위 정수다. 상한과 최소 단위 모두 **MP3 파일의 원본 레이트**에 의존한다
(target 레이트가 아님 — 무음 블록은 리샘플러 이전 단계에서 만들어진다).

#### 상한

`duration_ms * rate * nchannels * samplesize` 가 `int` 산술이라 오버플로한다.

| MP3 원본 포맷 | 상한 |
|---|---|
| 48000Hz 스테레오 16bit | 약 11,184 ms |
| 44100Hz 스테레오 16bit | 약 12,174 ms |
| 44100Hz 모노 16bit | 약 24,348 ms |

`INT_MAX ÷ (rate × nchannels × samplesize)` 이다. 넘으면 `silence_bytes` 가 음수가 되어
`allocb()` 에 음수 크기가 들어간다. 실운영에서 그 정도 값을 쓸 요건이 없어 미수정으로 두었다.

#### 최소 단위

`ms × rate` 가 1000 으로 나누어떨어져야 온전한 샘플 프레임이 된다.

| MP3 원본 레이트 | 최소 단위 |
|---|---|
| 48000 / 32000 / 24000 / 16000 / 12000 / 8000 | 1 ms |
| 44100 | 10 ms |
| 22050 | 20 ms |
| 11025 | 40 ms |

어긋나면 반 프레임이 남고, 리샘플러가 `inlen = size / (2 × nchannels)` 정수 나눗셈에서 남는
바이트를 버린다. 오디오상 영향은 없으나 설정값이 정확히 나오지는 않는다.

#### 권장

**20 ~ 11000 ms, 20 단위.** 11025Hz 를 제외한 모든 MP3 레이트에서 정확히 떨어지고,
소비자 측 Opus ptime(20ms)과도 정렬된다.

---

### 6. 소비자 측 대응 (`pulsar` 리포, 별도 커밋)

`apps/voipserver/source/plugins/pulsar_audiomulticast.c`

- 전역/세션 필드를 `audio_lead_silence` / `audio_trail_silence` 로 분리, 코드 기본값 모두 0
- 설정 키 `audio_lead_silence_ms` / `audio_trail_silence_ms` 신설
- 구 키 `audio_insert_silence_ms` 는 뒤 무음으로 폴백하고 deprecation 경고 로그 출력
  (설정 파일은 컴파일 에러 없이 조용히 기본값으로 되돌아가므로 즉시 제거하지 않음)

`apps/voipserver/config/plugin.audiomulticast.jcfg`

- `audio_lead_silence_ms = 500`, `audio_trail_silence_ms = 0`
- 권장범위 및 상한 주의사항 주석 추가

---

### 7. 알려진 제약 (미수정)

**무음 블록 버스트.** 무음 전체를 `mblk` 하나로 만들어 한 tick 에 투입한다. 500ms @ 48kHz
스테레오 = 88KB, ptime 20ms 기준 RTP 25패킷이 한 번에 몰린다. 다운스트림(resampler, encoder)은
tick 당 소비량이 고정이므로 무음이 시간축으로 흐르지 않고 버스트로 밀린다.

파일 내 WAV 경로(`:391` 부근)가 쓰는 `pause_time` 패턴 — tick 당 `bytes` 만큼만 내보내고
`pause_time -= f->ticker->interval` — 이 올바른 방식이며, MP3 분기에도 같은 코드가 주석 처리된
채 남아 있다. 값이 짧으면(100~500ms) 실사용상 문제되지 않아 이번에는 두었다.

**기존 결함 2건.** `mp3_player_open()` 의 `mpg123_init()` 실패 경로가 `int` 함수에서 값 없이
`return;` 하고(`:167`), `mpg123_getformat()` 에 `long*` 대신 `int*` 를 넘긴다(`:186`).
이번 작업 범위 밖이라 손대지 않았다.

---

### 8. 빌드 반영

빌드 스크립트가 GitHub 에서 clone 하므로 **push 없이는 반영되지 않는다.**

```
pulsar_mediastreamer2 push
  → pulsar/scripts/build-libmediastreamer2-host.sh   (또는 vmware/scripts/build-libmediastreamer2.sh)
  → voipserver 재빌드
```

새 헤더 없이 voipserver 만 빌드하면 `MS_MP3FILE_PLAYER_SET_LEAD_SILENCE` 미정의로 실패한다.

2026-07-29 기준 `vmware/3rdparty/libmediastreamer2` 는 갱신 완료,
`pulsar/3rdparty/libmediastreamer2` (host 빌드용) 는 미갱신 상태다.
