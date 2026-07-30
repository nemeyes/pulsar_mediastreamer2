
#if defined(HAVE_CONFIG_H)
#include "mediastreamer-config.h"
#endif

#include "asyncrw.h"
#include "mediastreamer2/msmp3fileplayer.h"
#include "mediastreamer2/msticker.h"
#include "waveheader.h"
#include <bctoolbox/defs.h>
#include <bctoolbox/vfs.h>

#include <limits.h>
#include <mpg123.h>


#include "fd_portab.h" // keep this include at the end of the inclusion sequence.

static int mp3_player_close(MSFilter *f, void *arg);
static int mp3_player_open_playlist(MSFilter *f, void *arg);

struct _PlayerData {
	bctbx_vfs_file_t *fp;
	MSAsyncReader *reader;
	MSPlayerState state;
	int rate;
	int nchannels;
	int hsize;
	int loop_after;
	int pause_time;
	int count;
	int samplesize;
	char *mime;
	uint32_t ts;
	int async_read_too_late;
	uint64_t current_pos_bytes;
	int duration;
	bool_t swap;
	bool_t is_raw;
	int lead_silence_ms;
	int trail_silence_ms;
	int gap_silence_ms;
	bool_t lead_silence_pending;

	/* playlist: the filter plays 'ntracks' files back-to-back as one continuous stream.
	   A single file is just the ntracks==1 case, it takes the very same code path. */
	char **tracks;
	int ntracks;
	int cur_track;
	int tracks_duration_ms; /* sum of the tracks, silences excluded */
	/* silence still owed to the output, drained at most one tick at a time. Holds the lead,
	   a track-to-track gap or the trail indifferently: only the moment they are armed
	   differs, never the way they are emitted. */
	int silence_remaining_bytes;
	bool_t finished; /* last track exhausted; the trail may still be draining */

	mpg123_handle* mpg123;
	int is_mp3;
};

typedef struct _PlayerData PlayerData;

static void mp3_player_init(MSFilter *f) {
	
	PlayerData *d = ms_new0(PlayerData, 1);
	d->state = MSPlayerClosed;
	d->swap = FALSE;
	d->rate = 44100;
	d->nchannels = 2;
	d->samplesize = 2;
	d->mime = "pcm";
	d->hsize = 0;
	d->loop_after = -1; /*by default, don't loop*/
	d->pause_time = 0;
	d->count = 0;
	d->ts = 0;
	d->current_pos_bytes = 0; /* excluding wav header */
	d->duration = 0;
	d->is_raw = TRUE;
	d->lead_silence_ms = 0;
	d->trail_silence_ms = 0;
	d->gap_silence_ms = 0;
	d->lead_silence_pending = FALSE;
	d->tracks = NULL;
	d->ntracks = 0;
	d->cur_track = 0;
	d->tracks_duration_ms = 0;
	d->silence_remaining_bytes = 0;
	d->finished = FALSE;

	f->data = d;
}

int ms_mp3read_wav_header_from_fp(wave_header_t *header, bctbx_vfs_file_t *fp) {
	int count;
	int skip;
	int hsize = 0;
	riff_t *riff_chunk = &header->riff_chunk;
	format_t *format_chunk = &header->format_chunk;
	data_t *data_chunk = &header->data_chunk;

	ssize_t len = bctbx_file_read2(fp, (char *)riff_chunk, sizeof(riff_t));
	if (len != sizeof(riff_t)) {
		ms_error("Wrong wav header: cannot read the RIFF header");
		goto not_a_wav;
	}

	if (0 != strncmp(riff_chunk->riff, "RIFF", 4) || 0 != strncmp(riff_chunk->wave, "WAVE", 4)) {
		ms_error("Wrong wav header: invalid FourCC[%4.4s] or RIFF format[%4.4s]", riff_chunk->riff, riff_chunk->wave);
		goto not_a_wav;
	}

	len = bctbx_file_read2(fp, (char *)format_chunk, sizeof(format_t));
	if (len != sizeof(format_t)) {
		ms_error("Wrong wav header: cannot read 'format' chunk");
		goto not_a_wav;
	}

	if ((skip = le_uint32(format_chunk->len) - 0x10) > 0) {
		bctbx_file_seek(fp, skip, SEEK_CUR);
	}
	hsize = sizeof(wave_header_t) - 0x10 + le_uint32(format_chunk->len);

	count = 0;
	do {
		len = bctbx_file_read2(fp, data_chunk, sizeof(data_t));
		if (len != sizeof(data_t)) {
			ms_error("Wrong wav header: cannot read data chunk[count=%i]", count);
			goto not_a_wav;
		}
		if (strncmp(data_chunk->data, "data", 4) != 0) {
			ms_warning("skipping chunk=%4.4s len=%i", data_chunk->data, data_chunk->len);
			bctbx_file_seek(fp, le_uint32(data_chunk->len), SEEK_CUR);
			count++;
			hsize += (int)len + le_uint32(data_chunk->len);
		} else {
			hsize += (int)len;
			break;
		}
	} while (count < 30);
	return hsize;

not_a_wav:
	/*rewind*/
	bctbx_file_seek(fp, 0, SEEK_SET);
	return -1;
}

static int mp3read_wav_header(PlayerData *d) {
	wave_header_t header;
	format_t *format_chunk = &header.format_chunk;
	int ret = ms_mp3read_wav_header_from_fp(&header, d->fp);

	if (ret == -1) goto not_a_wav;

	d->rate = le_uint32(format_chunk->rate);
	d->nchannels = le_uint16(format_chunk->channel);
	if (d->nchannels == 0) goto not_a_wav;
	d->samplesize = le_uint16(format_chunk->blockalign) / d->nchannels;
	d->hsize = ret;

#ifdef WORDS_BIGENDIAN
	if (le_uint16(format_chunk->blockalign) == le_uint16(format_chunk->channel) * 2) d->swap = TRUE;
#endif
	d->is_raw = FALSE;
	return 0;

not_a_wav:
	/*rewind*/
	bctbx_file_seek(d->fp, 0, SEEK_SET);
	d->hsize = 0;
	d->is_raw = TRUE;
	return -1;
}

static void mp3_playlist_free(PlayerData *d) {
	int i;
	if (d->tracks) {
		for (i = 0; i < d->ntracks; i++) {
			if (d->tracks[i]) ms_free(d->tracks[i]);
		}
		ms_free(d->tracks);
		d->tracks = NULL;
	}
	d->ntracks = 0;
	d->cur_track = 0;
	d->tracks_duration_ms = 0;
}

/* Restrict the decoder to 16 bit output. The rest of the graph assumes it: the resampler
   divides by (2 * nchannels) and the encoders work on 2-byte samples. Letting mpg123 pick
   freely could hand them float samples. It also pins d->samplesize to 2, so the sample size
   can never change under us halfway through a block when we cross a track boundary. */
static void mp3_setup_format(mpg123_handle *h) {
	const long *rates = NULL;
	size_t nrates = 0, i;
	mpg123_format_none(h);
	mpg123_rates(&rates, &nrates);
	for (i = 0; i < nrates; i++) {
		mpg123_format(h, rates[i], MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_16);
	}
}

/* Size of a silence of 'ms', rounded down to a whole sample frame. Computed on 64 bits:
   the product overflows an int past ~11 seconds at 48kHz stereo. */
static int mp3_silence_bytes_from_ms(PlayerData *d, int ms) {
	int frame = d->samplesize * d->nchannels;
	int64_t b;
	if (ms <= 0 || frame <= 0) return 0;
	b = ((int64_t)ms * (int64_t)d->rate * (int64_t)frame) / 1000LL;
	if (b > (int64_t)INT_MAX) b = (INT_MAX / frame) * frame;
	return (int)(b - (b % frame));
}

/* Make 'index' the current track. Every track but the first must match the format of the
   first one: the resampler downstream is configured once, when the graph is built. */
static int mp3_open_track(MSFilter *f, PlayerData *d, int index) {
	long rate = 0;
	int ch = 0, enc = 0;

	if (d->mpg123 == NULL || index < 0 || index >= d->ntracks) return -1;

	mpg123_close(d->mpg123);
	if (mpg123_open(d->mpg123, d->tracks[index]) != MPG123_OK) {
		ms_warning("MSMP3FilePlayer[%p]: failed to open track %i (%s)", f, index, d->tracks[index]);
		return -1;
	}
	if (mpg123_getformat(d->mpg123, &rate, &ch, &enc) != MPG123_OK) {
		ms_warning("MSMP3FilePlayer[%p]: cannot read format of track %i (%s)", f, index, d->tracks[index]);
		mpg123_close(d->mpg123);
		return -1;
	}
	if (index > 0 && ((int)rate != d->rate || ch != d->nchannels)) {
		ms_error("MSMP3FilePlayer[%p]: track %i (%s) is %liHz/%ich, expected %iHz/%ich", f, index,
		         d->tracks[index], rate, ch, d->rate, d->nchannels);
		mpg123_close(d->mpg123);
		return -1;
	}
	d->rate = (int)rate;
	d->nchannels = ch;
	d->samplesize = mpg123_encsize(enc);
	d->cur_track = index;
	return 0;
}

/* Move on to the next playable track. Returns 0 on success, -1 once the playlist is over.
   A track that cannot be opened anymore (deleted since the playlist was validated) is
   skipped rather than aborting the whole playback. */
static int mp3_advance_track(MSFilter *f, PlayerData *d) {
	int i;
	for (i = d->cur_track + 1; i < d->ntracks; i++) {
		if (mp3_open_track(f, d, i) == 0) return 0;
		ms_error("MSMP3FilePlayer[%p]: skipping track %i", f, i);
	}
	return -1;
}

static int mp3_player_open(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	bctbx_vfs_file_t *fp;
	const char *file = (const char *)arg;
	int64_t fsize;

	if (strstr(file, ".mp3") || strstr(file, ".MP3")) {
		/* a single file is a one-entry playlist, nothing more */
		MSMP3PlaylistDesc pl;
		pl.files = &file;
		pl.nfiles = 1;
		return mp3_player_open_playlist(f, &pl);
	}
	else {
		d->is_mp3 = 0;
		return -1;

		if (d->fp) {
			mp3_player_close(f, NULL);
		}
		if ((fp = bctbx_file_open2(bctbx_vfs_get_default(), file, O_RDONLY | O_BINARY)) == NULL) {
			ms_warning("MSMP3FilePlayer[%p]: failed to open %s: %s", f, file, strerror(errno));
			return -1;
		}

		d->state = MSPlayerPaused;
		d->fp = fp;
		d->ts = 0;
		d->async_read_too_late = 0;

		if (mp3read_wav_header(d) != 0 && strstr(file, ".wav")) {
			ms_warning("File %s has .wav extension but wav header could be found.", file);
		}
		d->reader = ms_async_reader_new(d->fp);

		if ((fsize = bctbx_file_size(fp)) != BCTBX_VFS_ERROR) {
			d->duration = (int)((1000LL * ((uint64_t)fsize - (uint64_t)d->hsize) /
				((uint64_t)d->samplesize * (uint64_t)d->nchannels)) /
				(uint64_t)d->rate);
		}
		else {
			ms_error("MSMP3FilePlayer[%p]: fstat() failed: %s", f, strerror(errno));
		}
		d->current_pos_bytes = 0;
		ms_filter_notify_no_arg(f, MS_FILTER_OUTPUT_FMT_CHANGED);
		ms_message("MSMP3FilePlayer[%p]: %s opened: rate=%i,channel=%i, length=%i ms", f, file, d->rate, d->nchannels,
			d->duration);
	}
	return 0;
}

static int mp3_player_open_playlist(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	const MSMP3PlaylistDesc *pl = (const MSMP3PlaylistDesc *)arg;
	static int mpg123_initialized = 0;
	int total_ms = 0;
	int i;

	if (pl == NULL || pl->files == NULL || pl->nfiles <= 0) {
		ms_error("MSMP3FilePlayer[%p]: empty playlist", f);
		return -1;
	}

	if (!mpg123_initialized) {
		if (mpg123_init() != MPG123_OK) {
			ms_error("MSMP3FilePlayer[%p]: failed to initialize libmpg123", f);
			return -1;
		}
		mpg123_initialized = 1;
	}

	/* Everything below is read by process() on the ticker thread. In practice this runs
	   before the filter is attached to a ticker, so the lock is never contended; it is held
	   for correctness should the playlist ever be replaced on a live filter. */
	ms_filter_lock(f);

	/* re-opening on a filter that was already used: drop whatever it held */
	if (d->mpg123) {
		mpg123_close(d->mpg123);
		mpg123_delete(d->mpg123);
		d->mpg123 = NULL;
	}
	mp3_playlist_free(d);
	d->is_mp3 = 0;

	d->mpg123 = mpg123_new(NULL, NULL);
	if (d->mpg123 == NULL) {
		ms_error("MSMP3FilePlayer[%p]: cannot create a mpg123 handle", f);
		ms_filter_unlock(f);
		return -1;
	}
	mpg123_param(d->mpg123, MPG123_RESYNC_LIMIT, -1, 0);
	mp3_setup_format(d->mpg123);

	d->tracks = ms_new0(char *, pl->nfiles);
	d->ntracks = pl->nfiles;
	for (i = 0; i < d->ntracks; i++) {
		if (pl->files[i] == NULL || pl->files[i][0] == '\0') {
			ms_error("MSMP3FilePlayer[%p]: playlist entry %i is empty", f, i);
			goto fail;
		}
		d->tracks[i] = ms_strdup(pl->files[i]);
	}

	/* Validate the whole playlist up front: every track must be readable and share the
	   format of the first one. Doing it here means a bad playlist is rejected before the
	   graph runs, rather than in the middle of playback on the ticker thread. It also
	   warms the page cache, which keeps the mid-playback track switches cheap. */
	for (i = 0; i < d->ntracks; i++) {
		off_t len;
		if (mp3_open_track(f, d, i) != 0) goto fail;
		len = mpg123_length(d->mpg123);
		if (len > 0 && d->rate > 0) total_ms += (int)((1000LL * (int64_t)len) / (int64_t)d->rate);
	}

	if (mp3_open_track(f, d, 0) != 0) goto fail;

	d->is_mp3 = 1;
	d->is_raw = FALSE;
	d->hsize = 0;
	d->tracks_duration_ms = total_ms;
	d->state = MSPlayerPaused;
	/* the stream sits at the head of the first track: the lead silence is due on the first
	   tick of playback. Keeping it as a pending flag rather than emitting it here means
	   SET_LEAD_SILENCE works whether it is called before or after this, and that resuming
	   from a pause never re-inserts it. */
	d->lead_silence_pending = TRUE;
	d->silence_remaining_bytes = 0;
	d->finished = FALSE;

	ms_filter_unlock(f);
	ms_message("MSMP3FilePlayer[%p]: playlist opened: %i track(s), rate=%i, channels=%i, length=%i ms", f,
	           d->ntracks, d->rate, d->nchannels, total_ms);
	return 0;

fail:
	mp3_playlist_free(d);
	if (d->mpg123) {
		mpg123_close(d->mpg123);
		mpg123_delete(d->mpg123);
		d->mpg123 = NULL;
	}
	d->is_mp3 = 0;
	d->state = MSPlayerClosed;
	ms_filter_unlock(f);
	return -1;
}

static int mp3_player_start(MSFilter *f, BCTBX_UNUSED(void *arg)) {
	PlayerData *d = (PlayerData *)f->data;
	if (d->state == MSPlayerPaused) d->state = MSPlayerPlaying;
	return 0;
}

/* Rewind to the head of the playlist. No silence is emitted: the lead is only re-armed, so
   that it plays before the first sample whenever playback starts again. */
static int mp3_player_stop(MSFilter *f, BCTBX_UNUSED(void *arg)) {
	PlayerData *d = (PlayerData *)f->data;
	ms_filter_lock(f);
	if (d->state != MSPlayerClosed) {
		d->state = MSPlayerPaused;
		d->silence_remaining_bytes = 0; /* a gap or trail in flight is dropped */
		d->finished = FALSE;
		if (d->is_mp3 && d->ntracks > 0) {
			if (mp3_open_track(f, d, 0) == 0) {
				d->lead_silence_pending = TRUE;
			} else {
				ms_warning("MSMP3FilePlayer[%p]: failed to rewind to the first track.", f);
			}
		}
		if (d->reader) {
			ms_async_reader_seek(d->reader, d->hsize);
			d->current_pos_bytes = 0;
		}
	}
	ms_filter_unlock(f);
	return 0;
}

/* Freeze where we are. Neither the lead nor the trail is involved: the lead is a "we are at
   the head of the playlist" flag, already spent, and the trail belongs to the end of the last
   track only. silence_remaining_bytes is kept as is, so pausing in the middle of a gap
   resumes with the remainder of that gap. */
static int mp3_player_pause(MSFilter *f, BCTBX_UNUSED(void *arg)) {
	PlayerData *d = (PlayerData *)f->data;
	ms_filter_lock(f);
	if (d->state == MSPlayerPlaying) {
		d->state = MSPlayerPaused;
	}
	ms_filter_unlock(f);
	return 0;
}

static int mp3_player_close(MSFilter *f, BCTBX_UNUSED(void *arg)) {
	PlayerData *d = (PlayerData *)f->data;
	ms_filter_lock(f);
	if (d->mpg123) {
		mpg123_close(d->mpg123);
		mpg123_delete(d->mpg123);
		d->mpg123 = NULL;
	}
	mp3_playlist_free(d);
	d->is_mp3 = 0;
	d->silence_remaining_bytes = 0;
	d->lead_silence_pending = FALSE;
	d->finished = FALSE;

	if (d->reader) {
		ms_async_reader_destroy(d->reader);
		d->reader = NULL;
	}
	if (d->fp) bctbx_file_close(d->fp);
	d->fp = NULL;
	d->state = MSPlayerClosed;
	ms_filter_unlock(f);
	if (d->async_read_too_late > 0) {
		ms_warning("MSMP3FilePlayer[%p] had %i late read events.", f, d->async_read_too_late);
	}
	return 0;
}

static int mp3_player_get_state(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*(int *)arg = d->state;
	return 0;
}

static void mp3_player_uninit(MSFilter *f) {
	PlayerData *d = (PlayerData *)f->data;
	mp3_player_close(f, NULL);
	ms_free(d);
}

static void swap_bytes(unsigned char *bytes, int len) {
	int i;
	unsigned char tmp;
	for (i = 0; i < len; i += 2) {
		tmp = bytes[i];
		bytes[i] = bytes[i + 1];
		bytes[i + 1] = tmp;
	}
}

static void mp3_player_process(MSFilter *f) {
	PlayerData *d = (PlayerData *)f->data;
	int nsamples = (f->ticker->interval * d->rate * d->nchannels) / 1000;
	int bytes;	 

	/*send an even number of samples each tick. At 22050Hz the number of samples per 10 ms chunk is odd.
	Odd size buffer of samples cause troubles to alsa. Fixing in alsa is difficult, so workaround here.
	*/
	if (nsamples & 0x1) { // odd number of samples
		if (d->count & 0x1) nsamples++;
		else nsamples--;
	}
	bytes = nsamples * d->samplesize;
	d->count++;
	ms_filter_lock(f);
	if (d->state == MSPlayerPlaying) {
		if (d->is_mp3) {
			/* Fill exactly one tick worth of output, taking from the pending silence, from
			   the current track, and - when it ends - from the next one, in that order. The
			   whole playlist is emitted as one continuous PCM stream: nothing here has to
			   line a track boundary up with a block boundary. */
			mblk_t *om = allocb(bytes, 0);
			int filled = 0;

			while (filled < bytes) {
				/* (1) drain the pending silence, whichever one it is */
				if (d->silence_remaining_bytes > 0) {
					int n = bytes - filled;
					if (n > d->silence_remaining_bytes) n = d->silence_remaining_bytes;
					memset(om->b_wptr + filled, 0, n);
					filled += n;
					d->silence_remaining_bytes -= n;
					continue;
				}
				/* (2) last track exhausted and its trail already out */
				if (d->finished) break;
				/* (3) head of the playlist: the lead is due, once */
				if (d->lead_silence_pending) {
					d->lead_silence_pending = FALSE;
					if (d->lead_silence_ms > 0) {
						d->silence_remaining_bytes = mp3_silence_bytes_from_ms(d, d->lead_silence_ms);
						continue;
					}
				}
				/* (4) audio */
				{
					size_t done = 0;
					int err = mpg123_read(d->mpg123, om->b_wptr + filled, bytes - filled, &done);
					filled += (int)done;
					if (err == MPG123_DONE) {
						/* A track just ended. If another one follows, this is an inner
						   boundary: arm the gap and keep filling. The gap is armed here and
						   nowhere else, so it can never land before the first track or after
						   the last one. */
						if (mp3_advance_track(f, d) == 0) {
							if (d->gap_silence_ms > 0) {
								d->silence_remaining_bytes = mp3_silence_bytes_from_ms(d, d->gap_silence_ms);
							}
							continue;
						}
						/* that was the last track: the trail belongs here, and only here */
						if (d->trail_silence_ms > 0) {
							d->silence_remaining_bytes = mp3_silence_bytes_from_ms(d, d->trail_silence_ms);
						}
						d->finished = TRUE;
						continue;
					}
					if (err != MPG123_OK && err != MPG123_NEW_FORMAT) {
						ms_warning("MSMP3FilePlayer[%p]: failed to read track %i (error %i).", f, d->cur_track, err);
						d->finished = TRUE;
						continue;
					}
					if (done == 0) break; /* nothing more to be had this tick */
				}
			}

			if (filled > 0) {
				om->b_wptr += filled;
				mblk_set_timestamp_info(om, d->ts);
				/* advance by what was really produced: on the last block of a track the
				   decoder usually returns less than a full tick */
				d->ts += filled / d->samplesize;
				ms_queue_put(f->outputs[0], om);
			} else {
				freemsg(om);
			}

			/* Report the end only once the trail has been fully emitted. The consumer tears
			   the graph down on this event, so notifying earlier would cut the trail off. */
			if (d->finished && d->silence_remaining_bytes == 0) {
				if (d->loop_after >= 0 && mp3_open_track(f, d, 0) == 0) {
					/* d->ts is never reset nor jumped: it advanced with every block actually
					   sent, so the next iteration carries on where this one stopped. The
					   space between iterations comes from the silences alone. */
					d->finished = FALSE;
					d->lead_silence_pending = TRUE; /* back at the head: the lead is due again */
				} else {
					if (d->loop_after >= 0) {
						ms_warning("MSMP3FilePlayer[%p]: failed to restart the playlist.", f);
					} else {
						ms_message("MSMP3FilePlayer[%p]: end of playlist reached.", f);
					}
					d->state = MSPlayerPaused;
					ms_filter_notify_no_arg(f, MS_PLAYER_EOF);
					ms_filter_notify_no_arg(f, MS_MP3FILE_PLAYER_EOF);
				}
			}
		}
		else {
			int err;
			mblk_t *om = allocb(bytes, 0);
			if (d->pause_time > 0) {
				err = bytes;
				memset(om->b_wptr, 0, bytes);
				d->pause_time -= f->ticker->interval;
			} else {
				err = ms_async_reader_read(d->reader, om->b_wptr, bytes);
			}
			if (err >= 0) {
				if (d->swap) swap_bytes(om->b_wptr, bytes);
				if (err != 0) {
					if (err < bytes) memset(om->b_wptr + err, 0, bytes - err);
					om->b_wptr += bytes;
					mblk_set_timestamp_info(om, d->ts);
					d->ts += nsamples;
					d->current_pos_bytes += bytes;
					ms_queue_put(f->outputs[0], om);
				} else freemsg(om);
				if (err < bytes) {
					ms_async_reader_seek(d->reader, d->hsize);
					d->current_pos_bytes = 0;

					/* special value for playing file only once */
					if (d->loop_after < 0) {
						d->state = MSPlayerPaused;
					} else if (d->loop_after >= 0) {
						d->pause_time = d->loop_after;
					}
					ms_filter_notify_no_arg(f, MS_PLAYER_EOF);
					/*for compatibility:*/     
					ms_filter_notify_no_arg(f, MS_MP3FILE_PLAYER_EOF);
				}
			} else {
				if (err != -BCTBX_EWOULDBLOCK) ms_warning("MSFilePlayer[%p]: fail to read %i bytes.", f, bytes);
				else d->async_read_too_late++;
				freemsg(om);
			}
		}
	}
	ms_filter_unlock(f);
}

static int mp3_player_get_sr(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*((int *)arg) = d->rate;
	return 0;
}

static int mp3_player_set_sr(MSFilter *f, void *arg) {
	/* This function should be used only when playing a PCAP or raw file */
	PlayerData *d = (PlayerData *)f->data;
	d->rate = *((int *)arg);
	if (!d->is_raw) {
		ms_warning("MSMP3FilePlayer[%p]: rate explicitely while playing a wav file. Hoping it is intended.", f);
	}
	return 0;
}

static int mp3_player_loop(MSFilter *f, void *arg) {	
	PlayerData *d = (PlayerData *)f->data;
	d->loop_after = *((int *)arg);
	return 0;
}

static int mp3_player_set_lead_silence(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	d->lead_silence_ms = *((int *)arg);
	return 0;
}

static int mp3_player_set_trail_silence(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	d->trail_silence_ms = *((int *)arg);
	return 0;
}

/* Applies from the next track boundary on; a gap already in flight is left alone. */
static int mp3_player_set_gap_silence(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	d->gap_silence_ms = *((int *)arg);
	return 0;
}

static int mp3_player_get_track_count(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*((int *)arg) = d->ntracks;
	return 0;
}

static int mp3_player_get_cur_track(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*((int *)arg) = d->cur_track;
	return 0;
}

static int mp3_player_eof(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	if (d->fp == NULL && d->state == MSPlayerClosed) *((int *)arg) = TRUE; /* 1 */
	else *((int *)arg) = FALSE;                                            /* 0 */
	return 0;
}

static int mp3_player_get_nch(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*((int *)arg) = d->nchannels;
	return 0;
}

static int mp3_player_get_fmtp(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	MSPinFormat *pinfmt = (MSPinFormat *)arg;
	if (pinfmt->pin == 0) pinfmt->fmt = ms_factory_get_audio_format(f->factory, d->mime, d->rate, d->nchannels, NULL);
	return 0;
}

static int mp3_player_set_fmtp(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	MSPinFormat *pinfmt = (MSPinFormat *)arg;
	ms_filter_lock(f);
	d->rate = pinfmt->fmt->rate;
	d->nchannels = pinfmt->fmt->nchannels;
	d->mime = pinfmt->fmt->encoding;
	if (strcmp(d->mime, "L16") == 0) {
		d->swap = TRUE;
	} else {
		d->swap = FALSE;
	}
	ms_filter_unlock(f);
	return 0;
}

/* Computed on the fly rather than stored, because the silences may be set after the playlist
   was opened. */
static int mp3_player_get_duration(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	if (d->is_mp3 && d->ntracks > 0) {
		*(int *)arg = d->lead_silence_ms + d->tracks_duration_ms +
		              (d->ntracks - 1) * d->gap_silence_ms + d->trail_silence_ms;
	} else {
		*(int *)arg = d->duration;
	}
	return 0;
}

static int mp3_player_get_current_position(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	int cur_pos_ms = (int)((1000LL * (d->current_pos_bytes / (d->samplesize * d->nchannels))) / (uint64_t)d->rate);
	*(int *)arg = cur_pos_ms;
	return 0;
}

static int mp3_player_seek_position(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	int target_position_ms = *((int *)arg);
	ms_filter_lock(f);
	if (d->reader) {
		d->current_pos_bytes =
		    (uint64_t)(target_position_ms * (uint64_t)d->rate * d->samplesize * d->nchannels) / 1000LL;
		off_t seek = (off_t)(d->hsize + d->current_pos_bytes);
		ms_async_reader_seek(d->reader, seek);
	}
	ms_filter_unlock(f);
	return 0;
}

static MSFilterMethod mp3_player_methods[] = {{MS_MP3FILE_PLAYER_OPEN, mp3_player_open},
                                          {MS_MP3FILE_PLAYER_START, mp3_player_start},
                                          {MS_MP3FILE_PLAYER_STOP, mp3_player_stop},
                                          {MS_MP3FILE_PLAYER_CLOSE, mp3_player_close},
                                           {MS_FILTER_GET_SAMPLE_RATE, mp3_player_get_sr},
                                           {MS_FILTER_SET_SAMPLE_RATE, mp3_player_set_sr},
                                           {MS_FILTER_GET_NCHANNELS, mp3_player_get_nch},
                                           {MS_MP3FILE_PLAYER_LOOP, mp3_player_loop},
                                           {MS_MP3FILE_PLAYER_DONE, mp3_player_eof},
										   {MS_MP3FILE_PLAYER_OPEN_PLAYLIST, mp3_player_open_playlist},
										   {MS_MP3FILE_PLAYER_GET_TRACK_COUNT, mp3_player_get_track_count},
										   {MS_MP3FILE_PLAYER_GET_CUR_TRACK, mp3_player_get_cur_track},
										   {MS_MP3FILE_PLAYER_SET_LEAD_SILENCE, mp3_player_set_lead_silence},
										   {MS_MP3FILE_PLAYER_SET_TRAIL_SILENCE, mp3_player_set_trail_silence},
										   {MS_MP3FILE_PLAYER_SET_GAP_SILENCE, mp3_player_set_gap_silence},
                                           {MS_PLAYER_GET_DURATION, mp3_player_get_duration},
                                           {MS_PLAYER_GET_CURRENT_POSITION, mp3_player_get_current_position},
                                           {MS_PLAYER_SEEK_MS, mp3_player_seek_position},
										  /* this wav file player implements the MSFilterPlayerInterface*/
                                          {MS_PLAYER_OPEN, mp3_player_open},
                                          {MS_PLAYER_START, mp3_player_start},
                                          {MS_PLAYER_PAUSE, mp3_player_pause},
                                          {MS_PLAYER_CLOSE, mp3_player_close},
                                           {MS_PLAYER_GET_STATE, mp3_player_get_state},
                                           {MS_PLAYER_SET_LOOP, mp3_player_loop},
                                           {MS_FILTER_GET_OUTPUT_FMT, mp3_player_get_fmtp},
                                           {MS_FILTER_SET_OUTPUT_FMT, mp3_player_set_fmtp},										 
                                          {0, NULL}};

#ifdef _WIN32

MSFilterDesc ms_mp3file_player_desc = {MS_MP3FILE_PLAYER_ID,
                                    "MSMP3FilePlayer",
                                    N_("mp3 reader"),
                                    MS_FILTER_OTHER,
                                    NULL,
                                    0,
                                    1,
									mp3_player_init,
                                    NULL,
									mp3_player_process,
                                    NULL,
									mp3_player_uninit,
								    mp3_player_methods};

#else

MSFilterDesc ms_mp3file_player_desc = {.id = MS_MP3FILE_PLAYER_ID,
                                    .name = "MSMP3FilePlayer",
                                    .text = N_("mp3 reader"),
                                    .category = MS_FILTER_OTHER,
                                    .ninputs = 0,
                                    .noutputs = 1,
                                    .init = mp3_player_init,
                                    .process = mp3_player_process,
                                    .uninit = mp3_player_uninit,
                                    .methods = mp3_player_methods};

#endif

MS_FILTER_DESC_EXPORT(ms_mp3file_player_desc)
