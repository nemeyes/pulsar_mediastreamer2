 
#ifndef msmp3fileplayer_h
#define msmp3fileplayer_h

#include <mediastreamer2/msfilter.h>


 
//  /*methods*/
// #define MS_MP3FILE_PLAYER_OPEN MS_FILTER_METHOD(MS_MP3FILE_PLAYER_ID, 0, const char *)
// #define MS_MP3FILE_PLAYER_START MS_FILTER_METHOD_NO_ARG(MS_MP3FILE_PLAYER_ID, 1)
// #define MS_MP3FILE_PLAYER_STOP MS_FILTER_METHOD_NO_ARG(MS_MP3FILE_PLAYER_ID, 2)
// #define MS_MP3FILE_PLAYER_CLOSE MS_FILTER_METHOD_NO_ARG(MS_MP3FILE_PLAYER_ID, 3)
// /* set loop mode:
//     -1: no looping,
//     0: loop at end of file,
//     x>0, loop after x miliseconds after eof
// */
//  #define MS_MP3FILE_PLAYER_LOOP MS_FILTER_METHOD(MS_MP3FILE_PLAYER_ID, 4, int)
//  #define MS_MP3FILE_PLAYER_DONE MS_FILTER_METHOD(MS_MP3FILE_PLAYER_ID, 5, int)
//  #define MS_MP3FILE_PLAYER_BIG_BUFFER MS_FILTER_METHOD(MS_MP3FILE_PLAYER_ID, 6, int)

// /*events*/
// #define MS_MP3FILE_PLAYER_EOF MS_FILTER_EVENT_NO_ARG(MS_MP3FILE_PLAYER_ID, 0)



 /*methods*/
#define MS_MP3FILE_PLAYER_OPEN MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 0, const char *)
#define MS_MP3FILE_PLAYER_START MS_FILTER_METHOD_NO_ARG(MSFilterMP3PlayerInterface, 1)
#define MS_MP3FILE_PLAYER_STOP MS_FILTER_METHOD_NO_ARG(MSFilterMP3PlayerInterface, 2)
#define MS_MP3FILE_PLAYER_CLOSE MS_FILTER_METHOD_NO_ARG(MSFilterMP3PlayerInterface, 3)
/* set loop mode:
    -1: no looping,
    0: loop at end of file,
    x>0, loop after x miliseconds after eof
*/
 #define MS_MP3FILE_PLAYER_LOOP MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 4, int)
 #define MS_MP3FILE_PLAYER_DONE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 5, int)
 #define MS_MP3FILE_PLAYER_BIG_BUFFER MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 6, int)
/* silence in milliseconds inserted once before the first sample of the playlist, each time
   playback enters the head of the first track (open, MS_MP3FILE_PLAYER_STOP and every loop
   iteration). Never inserted on pause/resume, nor between tracks. */
 #define MS_MP3FILE_PLAYER_SET_LEAD_SILENCE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 7, int)
/* silence in milliseconds inserted once after the last sample of the *last* track, when it
   reaches eof. Never inserted on pause/stop, nor between tracks. */
 #define MS_MP3FILE_PLAYER_SET_TRAIL_SILENCE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 8, int)

/* Accepted range for the silences and the fades, in milliseconds. A value outside the range
   is clamped to it, and logged; the call still succeeds. 0 means "none".
   The silence ceiling is what keeps one block from growing unreasonably - at 48kHz stereo
   the maximum is already some 5.8 MB - and the fade ceiling keeps a stop from taking that
   much longer to complete. Both are far above anything either is useful for. */
#define MS_MP3FILE_PLAYER_SILENCE_MIN_MS 0
#define MS_MP3FILE_PLAYER_SILENCE_MAX_MS 30000
#define MS_MP3FILE_PLAYER_FADE_MIN_MS 0
#define MS_MP3FILE_PLAYER_FADE_MAX_MS 5000

/* A playlist of files played back-to-back as a single, continuous stream.
   'files' holds 'nfiles' paths; the filter copies them, the caller keeps ownership. */
typedef struct _MSMP3PlaylistDesc {
	const char **files;
	int nfiles;
} MSMP3PlaylistDesc;

/* Open a playlist. Tracks that cannot be opened are dropped and the rest still plays; the
   call only fails, with -1, when no track at all is playable. Use GET_TRACK_STATUS to learn
   which ones were dropped. Tracks may differ in sample rate and channel count: the player
   converts them to the format of the first track, so its output format never changes.
   MS_MP3FILE_PLAYER_OPEN is the single-file case of this and remains supported. */
 #define MS_MP3FILE_PLAYER_OPEN_PLAYLIST MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 9, MSMP3PlaylistDesc)
/* Number of tracks that will actually be played, i.e. excluding the dropped ones. */
 #define MS_MP3FILE_PLAYER_GET_TRACK_COUNT MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 10, int)
 #define MS_MP3FILE_PLAYER_GET_CUR_TRACK MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 11, int)
/* silence in milliseconds inserted at every track-to-track boundary (nfiles - 1 times).
   Defaults to 0, i.e. gapless. Takes effect from the next boundary on. */
 #define MS_MP3FILE_PLAYER_SET_GAP_SILENCE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 12, int)

/* Per-track outcome of the last OPEN_PLAYLIST. The caller provides an array of 'nfiles'
   ints, indexed exactly like the list it passed to OPEN_PLAYLIST; each is filled with 1
   when the track is going to be played and 0 when it could not be opened. */
typedef struct _MSMP3PlaylistStatus {
	int *status;
	int nfiles;
} MSMP3PlaylistStatus;

 #define MS_MP3FILE_PLAYER_GET_TRACK_STATUS MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 13, MSMP3PlaylistStatus)

/* Length in milliseconds of the ramps applied where the waveform would otherwise step, and
   click: playback resuming from silence fades in, playback being paused or stopped fades
   out. 0 disables one of them. Both default to 8 ms.
   The fade-in only scales samples that were going out anyway, so it costs nothing; the
   fade-out is generated after the last sample, so it makes the stream that much longer and
   delays the moment a stop completes. */
 #define MS_MP3FILE_PLAYER_SET_FADE_IN MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 14, int)
 #define MS_MP3FILE_PLAYER_SET_FADE_OUT MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 15, int)

/* Native format of a track, as reported by TRACK_FORMAT_CHANGED. */
typedef struct _MSMP3TrackFormat {
	int index;     /* position in the list passed to OPEN_PLAYLIST */
	int rate;      /* this track's own sample rate */
	int nchannels; /* this track's own channel count */
} MSMP3TrackFormat;

/*events*/
/* End of the whole playlist, notified once the trail silence has been fully emitted. */
#define MS_MP3FILE_PLAYER_EOF MS_FILTER_EVENT_NO_ARG(MSFilterMP3PlayerInterface, 0)
/* Playback moved on to a track whose native rate or channel count differs from the previous
   one. Informational: the audio itself stays correct, the player converts it to the output
   format. Not raised for the first track, nor while the playlist is being opened. */
#define MS_MP3FILE_PLAYER_TRACK_FORMAT_CHANGED MS_FILTER_EVENT(MSFilterMP3PlayerInterface, 1, MSMP3TrackFormat)


#endif
