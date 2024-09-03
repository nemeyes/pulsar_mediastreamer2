
#include <bctoolbox/defs.h>

#include "mediastreamer2/msfilter.h"
#include "mediastreamer2/msticker.h"

#include <mpg123.h>

#ifdef __ANDROID__
#include "cpu-features.h"
#endif

#ifdef _WIN32
#include <malloc.h> /* for alloca */
#endif


typedef struct {
    mpg123_handle *mh;
    int err;                
    long rate;
    int channels;
    int encoding;            //16-bit signed PCM
} MP3DecodeFilterData;
 
static void mp3_decode_filter_init(MSFilter *f) {
    MP3DecodeFilterData *d = (MP3DecodeFilterData *)ms_new(MP3DecodeFilterData, 1);
    d->mh = NULL;
    d->rate = 44100;
    d->channels = 2;
    d->encoding = MPG123_ENC_SIGNED_16;
    f->data = d;  
}

static void mp3_decode_filter_uninit(MSFilter *f) {
    MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;
    if (d) {
        if (d->mh) {
            mpg123_close(d->mh);
            mpg123_delete(d->mh);
        }
        ms_free(d);
    }
}

static void mp3_dec_preprocess(MSFilter *f) {
    MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;

     static int mpg123_initialized = 0;
    if (!mpg123_initialized) {
        if (mpg123_init() != MPG123_OK) {
            ms_error("MP3DecodeFilter: Failed to initialize libmpg123");
            return;
        }
        mpg123_initialized = 1;
    }
   
    d->mh = mpg123_new(NULL, &d->err);
    if (d->mh == NULL) {
        ms_error("MP3DecodeFilter: mpg123_new() failed: %s", mpg123_plain_strerror(d->err));
        return;
    }

   // mpg123_param(d->mh, MPG123_RESYNC_LIMIT, -1, 0);
     
    if (mpg123_open_feed(d->mh) != MPG123_OK) {
        ms_error("MP3DecodeFilter: mpg123_open_feed() failed: %s", mpg123_strerror(d->mh));
        mpg123_delete(d->mh);
        d->mh = NULL;
        return;
    }

   // 44100 Hz, stereo, 16-bit signed PCM)
    if (mpg123_format_none(d->mh) != MPG123_OK ||
        mpg123_format(d->mh, 44100, 2, MPG123_ENC_SIGNED_16) != MPG123_OK) {
        ms_error("MP3DecodeFilter: mpg123_format() failed: %s", mpg123_strerror(d->mh));
        mpg123_close(d->mh);
        mpg123_delete(d->mh);
        d->mh = NULL;
        return;
    }
}

static void mp3_dec_postprocess(MSFilter *f) {
}

static void mp3_decode_filter_process(MSFilter *f) {
    MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;
    mblk_t *im;
    
    while ((im = ms_queue_get(f->inputs[0])) != NULL) {
        unsigned char *input_data = im->b_rptr;
        size_t input_size = im->b_wptr - im->b_rptr;
        
        if (mpg123_feed(d->mh, input_data, input_size) != MPG123_OK) {
            ms_error("MP3DecodeFilter: mpg123_feed() failed: %s", mpg123_strerror(d->mh));
            freemsg(im);
            continue;
        }

        freemsg(im);
        
        while (1) {
            unsigned char output_buffer[8192];
            size_t done = 0;
            int ret = mpg123_decode(d->mh, NULL, 0, output_buffer, sizeof(output_buffer), &done);

            if (ret == MPG123_OK) {
                if (done > 0) {                    
                    mblk_t *om = allocb(done, 0);
                    if (!om) {
                        ms_error("MP3DecodeFilter: Failed to allocate output buffer");
                        break;
                    }
                    memcpy(om->b_wptr, output_buffer, done);
                    om->b_wptr += done;
                    ms_queue_put(f->outputs[0], om);
                }
            } else if (ret == MPG123_NEW_FORMAT) {
                long rate;
                int channels, encoding;
                mpg123_getformat(d->mh, &rate, &channels, &encoding);
                                
                ms_error("MP3DecodeFilter: Detected new format, but fixed format is used.");
                break;
            } else if (ret == MPG123_NEED_MORE) {             
                break;
            } else if (ret == MPG123_ERR) {             
                ms_error("MP3DecodeFilter: mpg123_decode() error: %s", mpg123_strerror(d->mh));
                break;
            } else {
                break;
            }
        }
    }
}

static int set_rate(MSFilter *f, void *arg) {
	MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;
	d->rate = ((int *)arg)[0];
	return 0;
}

static int get_rate(MSFilter *f, void *arg) {
	MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;
	((int *)arg)[0] = d->rate;
	return 0;
}

static int set_nchannels(MSFilter *f, void *arg) {
	MP3DecodeFilterData *d = (MP3DecodeFilterData *)f->data;
	d->channels = ((int *)arg)[0];
	return 0;
}

static MSFilterMethod mp3_decode_methods[] = {{MS_FILTER_SET_SAMPLE_RATE, set_rate},
                                       {MS_FILTER_GET_SAMPLE_RATE, get_rate},
                                       {MS_FILTER_SET_NCHANNELS, set_nchannels},
                                       {0, NULL}};
 
#ifdef _MSC_VER

MSFilterDesc mp3_decode_filter_desc = {
    MS_MP3_DEC_ID,
    "MP3DecodeFilter",
    N_("MP3 Decode Filter using libmpg123"),
    MS_FILTER_DECODER,
    1,
    1,
    mp3_decode_filter_init,
    mp3_dec_preprocess,
    mp3_decode_filter_process,
    NULL,
    mp3_decode_filter_uninit,
    mp3_decode_methods
};

#else

MSFilterDesc mp3_decode_filter_desc = {
    .id = MS_MP3_DEC_ID,
    .name = "MP3DecodeFilter",
    .text = N_("MP3 Decode Filter"),
    .category = MS_FILTER_DECODER,
    .ninputs = 1,
    .noutputs = 1,
    .init = mp3_decode_filter_init,
    .preprocess = mp3_dec_preprocess,
    .process = mp3_decode_filter_process,
    .postprocess = NULL,
    .uninit = mp3_decode_filter_uninit,
    .methods = mp3_decode_methods
};

#endif

MS_FILTER_DESC_EXPORT(mp3_decode_filter_desc)
