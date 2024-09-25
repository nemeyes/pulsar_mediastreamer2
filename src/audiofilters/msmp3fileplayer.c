
#if defined(HAVE_CONFIG_H)
#include "mediastreamer-config.h"
#endif

#include "asyncrw.h"
#include "mediastreamer2/msmp3fileplayer.h"
#include "mediastreamer2/msticker.h"
#include "waveheader.h"
#include <bctoolbox/defs.h>
#include <bctoolbox/vfs.h>

#include <mpg123.h>
 

#include "fd_portab.h" // keep this include at the end of the inclusion sequence.

static int mp3_player_close(MSFilter *f, void *arg);

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
	int silence_duration_ms;

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
	d->silence_duration_ms = 0;
 
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

static int mp3_player_open(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	bctbx_vfs_file_t *fp;
	const char *file = (const char *)arg;
	int64_t fsize;

	if (strstr(file, ".mp3") || strstr(file, ".MP3")) {

		static int mpg123_initialized = 0;
		if (!mpg123_initialized) {
			if (mpg123_init() != MPG123_OK) {
				ms_error("MSMP3FilePlayer: Failed to initialize libmpg123");
				return;
			}
			mpg123_initialized = 1;
		}

		d->mpg123 = mpg123_new(NULL, NULL);
		mpg123_param(d->mpg123, MPG123_RESYNC_LIMIT, -1, 0);
		mpg123_format_none(d->mpg123);
		//mpg123_format(d->mpg123, MPG123_ANY, MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_8 | MPG123_ENC_UNSIGNED_8 | MPG123_ENC_SIGNED_16 | MPG123_ENC_UNSIGNED_16 | MPG123_ENC_FLOAT_32);
		// mpg123_format(d->mpg123, 44100, MPG123_MONO | MPG123_STEREO, MPG123_ENC_SIGNED_16);
		//mpg123_param(d->mpg123, MPG123_ADD_FLAGS, MPG123_ENC_SIGNED_16, 0);  		
		mpg123_format_all(d->mpg123);  

		d->is_mp3 = 0;
		d->state = MSPlayerPaused;

		if (mpg123_open(d->mpg123, file) == MPG123_OK) {
			d->is_mp3 = 1;
			int encoding;
			mpg123_getformat(d->mpg123, &d->rate, &d->nchannels, &encoding);			
			d->samplesize = mpg123_encsize(encoding);
			//d->samplesize = 2;
			d->hsize = 0;
			d->is_raw = FALSE; 
		}
		else {
			ms_warning("MSMP3FilePlayer[%p]: failed to open MP3 file %s", f, file);
			return -1;
		}
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

static int mp3_player_start(MSFilter *f, BCTBX_UNUSED(void *arg)) {	 
	PlayerData *d = (PlayerData *)f->data;
	if (d->state == MSPlayerPaused) d->state = MSPlayerPlaying;
	return 0;
}

static int mp3_player_stop(MSFilter *f, BCTBX_UNUSED(void *arg)) {	 
	PlayerData *d = (PlayerData *)f->data;
	ms_filter_lock(f);
	if (d->state != MSPlayerClosed) {
		d->state = MSPlayerPaused;
		if (d->reader) {
			ms_async_reader_seek(d->reader, d->hsize);
			d->current_pos_bytes = 0;
		}
	}
	ms_filter_unlock(f);
	return 0;
}

static int mp3_player_pause(MSFilter *f, BCTBX_UNUSED(void *arg)) {
	PlayerData *d = (PlayerData *)f->data;
	ms_filter_lock(f);
	if (d->state == MSPlayerPlaying) {
		d->state = MSPlayerPaused;

		if ( d->silence_duration_ms > 0 ) {  
			int silence_bytes = d->silence_duration_ms * d->rate * d->nchannels * d->samplesize / 1000;
			mblk_t *silence_block = allocb(silence_bytes, 0);
			memset(silence_block->b_wptr, 0, silence_bytes);   
			silence_block->b_wptr += silence_bytes;
			mblk_set_timestamp_info(silence_block, d->ts);
			ms_queue_put(f->outputs[0], silence_block);  
		}

	}
	ms_filter_unlock(f);
	return 0;
}

static int mp3_player_close(MSFilter *f, BCTBX_UNUSED(void *arg)) {	
	PlayerData *d = (PlayerData *)f->data;
	mp3_player_stop(f, NULL);
 
	if (d->reader) {
		ms_async_reader_destroy(d->reader);
		d->reader = NULL;
	}
	if (d->fp) bctbx_file_close(d->fp);
	d->fp = NULL;
	d->state = MSPlayerClosed;
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
	if (d->fp) mp3_player_close(f, NULL);
	if (d->is_mp3) {
		mpg123_close(d->mpg123);
		mpg123_delete(d->mpg123);
		d->mpg123 = NULL;
	}
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
			size_t done = 0;			 
			mblk_t* om = allocb(bytes, 0);
		/*	if (d->pause_time > 0) {
				err = bytes;
				memset(om->b_wptr, 0, bytes);
				d->pause_time -= f->ticker->interval;
			}
			else {*/
			{
				int err = mpg123_read(d->mpg123, om->b_wptr, bytes, &done);
				if (err == MPG123_OK || err == MPG123_DONE) {
					om->b_wptr += done;
					mblk_set_timestamp_info(om, d->ts);
					d->ts += nsamples;
					ms_queue_put(f->outputs[0], om);					
				}
				else {
					ms_warning("MSMP3FilePlayer[%p]: fail to read MP3 data.", f);
					freemsg(om);
				}
				if (err == MPG123_DONE) {

					if ( d->silence_duration_ms > 0 ) {  
						int silence_bytes = d->silence_duration_ms * d->rate * d->nchannels * d->samplesize / 1000;
						mblk_t *silence_block = allocb(silence_bytes, 0);
						memset(silence_block->b_wptr, 0, silence_bytes);   
						silence_block->b_wptr += silence_bytes;
						mblk_set_timestamp_info(silence_block, d->ts);
						ms_queue_put(f->outputs[0], silence_block);   
					}

					ms_warning("MSMP3FilePlayer[%p]: fail to read MP3 data.");
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

static int mp3_player_set_silence(MSFilter *f, void *arg) {	
	PlayerData *d = (PlayerData *)f->data;
	d->silence_duration_ms= *((int *)arg);
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

static int mp3_player_get_duration(MSFilter *f, void *arg) {
	PlayerData *d = (PlayerData *)f->data;
	*(int *)arg = d->duration;
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
										   {MS_MP3FILE_PLAYER_SET_SILENCE, mp3_player_set_silence},
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
