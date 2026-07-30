 
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

/* A playlist of files played back-to-back as a single, continuous stream.
   'files' holds 'nfiles' paths; the filter copies them, the caller keeps ownership. */
typedef struct _MSMP3PlaylistDesc {
	const char **files;
	int nfiles;
} MSMP3PlaylistDesc;

/* Open a playlist. All tracks must share the same sample rate and channel count, and all
   must be readable: the whole playlist is rejected otherwise. Returns 0, or -1 on failure.
   MS_MP3FILE_PLAYER_OPEN is the single-file case of this and remains supported. */
 #define MS_MP3FILE_PLAYER_OPEN_PLAYLIST MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 9, MSMP3PlaylistDesc)
 #define MS_MP3FILE_PLAYER_GET_TRACK_COUNT MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 10, int)
 #define MS_MP3FILE_PLAYER_GET_CUR_TRACK MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 11, int)
/* silence in milliseconds inserted at every track-to-track boundary (nfiles - 1 times).
   Defaults to 0, i.e. gapless. Takes effect from the next boundary on. */
 #define MS_MP3FILE_PLAYER_SET_GAP_SILENCE MS_FILTER_METHOD(MSFilterMP3PlayerInterface, 12, int)

/*events*/
/* End of the whole playlist, notified once the trail silence has been fully emitted. */
#define MS_MP3FILE_PLAYER_EOF MS_FILTER_EVENT_NO_ARG(MSFilterMP3PlayerInterface, 0)


#endif
