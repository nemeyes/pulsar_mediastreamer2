/*
 * Copyright (c) 2010-2022 Belledonne Communications SARL.
 *
 * This file is part of mediastreamer2
 * (see https://gitlab.linphone.org/BC/public/mediastreamer2).
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
#include "mediastreamer2/msfilter.h"

extern MSFilterDesc ms_alaw_dec_desc;
extern MSFilterDesc ms_alaw_enc_desc;
extern MSFilterDesc ms_ulaw_dec_desc;
extern MSFilterDesc ms_ulaw_enc_desc;
extern MSFilterDesc ms_rtp_send_desc;
extern MSFilterDesc ms_rtp_recv_desc;
extern MSFilterDesc ms_dtmf_gen_desc;
extern MSFilterDesc ms_volume_desc;
extern MSFilterDesc ms_equalizer_desc;
extern MSFilterDesc ms_speex_dec_desc;
extern MSFilterDesc ms_speex_enc_desc;
extern MSFilterDesc ms_speex_ec_desc;
extern MSFilterDesc ms_file_player_desc;
extern MSFilterDesc ms_file_rec_desc;
extern MSFilterDesc ms_resample_desc;
extern MSFilterDesc aq_read_desc;
extern MSFilterDesc aq_write_desc;
extern MSFilterDesc ms_equalizer_desc;
extern MSFilterDesc ms_gsm_dec_desc;
extern MSFilterDesc ms_gsm_enc_desc;
extern MSFilterDesc ms_mpeg4_enc_desc;
extern MSFilterDesc ms_mpeg4_dec_desc;
extern MSFilterDesc ms_vp8_enc_desc;
extern MSFilterDesc ms_vp8_dec_desc;
extern MSFilterDesc ms_h263_enc_desc;
extern MSFilterDesc ms_h263_dec_desc;
extern MSFilterDesc ms_h263_old_dec_desc;
extern MSFilterDesc ms_h264_dec_desc;
extern MSFilterDesc ms_mediacodec_h265_dec_desc;
extern MSFilterDesc ms_mediacodec_h264_enc_desc;
extern MSFilterDesc ms_pix_conv_desc;
extern MSFilterDesc ms_size_conv_desc;
extern MSFilterDesc ms_tone_detector_desc;
extern MSFilterDesc ms_audio_mixer_desc;
extern MSFilterDesc ms_g722_dec_desc;
extern MSFilterDesc ms_g722_enc_desc;
extern MSFilterDesc ms_l16_enc_desc;
extern MSFilterDesc ms_l16_dec_desc;
extern MSFilterDesc ms_aac_eld_dec_desc;
extern MSFilterDesc ms_aac_eld_enc_desc;
extern MSFilterDesc ms_jpeg_writer_desc;
#if defined(BUILD_WEBRTC_AECM)
extern MSFilterDesc ms_webrtc_aec_desc;
#endif
extern MSFilterDesc ms_opus_dec_desc;
extern MSFilterDesc ms_opus_enc_desc;
extern MSFilterDesc ms_mkv_recorder_desc;
extern MSFilterDesc ms_mkv_player_desc;
extern MSFilterDesc ms_itc_source_desc;
extern MSFilterDesc ms_itc_sink_desc;
extern MSFilterDesc ms_vad_dtx_desc;
extern MSFilterDesc ms_genericplc_desc;
extern MSFilterDesc ms_rtt_4103_sink_desc;
extern MSFilterDesc ms_rtt_4103_source_desc;
extern MSFilterDesc mp3_decode_filter_desc;
extern MSFilterDesc ms_mp3file_player_desc;

MSFilterDesc *ms_voip_filter_descs[] = {&ms_alaw_dec_desc,
                                        &ms_alaw_enc_desc,
                                        &ms_ulaw_dec_desc,
                                        &ms_ulaw_enc_desc,
                                        &ms_rtp_send_desc,
                                        &ms_rtp_recv_desc,
                                        &ms_dtmf_gen_desc,
                                        &ms_volume_desc,
                                        &ms_speex_dec_desc,
                                        &ms_speex_enc_desc,
                                        &ms_speex_ec_desc,
                                        &ms_file_player_desc,
                                        &ms_file_rec_desc,
                                        &ms_resample_desc,
                                        &ms_equalizer_desc,
                                        &ms_gsm_enc_desc,
                                        &ms_gsm_dec_desc,
                                        &ms_tone_detector_desc,
                                        &ms_audio_mixer_desc,
                                        &ms_g722_dec_desc,
                                        &ms_g722_enc_desc,
                                        &ms_l16_enc_desc,
                                        &ms_l16_dec_desc,
                                        &ms_aac_eld_enc_desc,
                                        &ms_aac_eld_dec_desc,
#ifdef VIDEO_ENABLED
                                        &ms_mpeg4_dec_desc,
                                        &ms_h263_dec_desc,
                                        &ms_h263_old_dec_desc,
                                        &ms_h264_dec_desc,
                                        &ms_mediacodec_h265_dec_desc,
                                        &ms_mediacodec_h264_enc_desc,
                                        &ms_pix_conv_desc,
                                        &ms_size_conv_desc,
                                        &ms_vp8_enc_desc,
                                        &ms_vp8_dec_desc,
                                        &ms_jpeg_writer_desc,
#ifdef HAVE_MATROSKA
                                        &ms_mkv_recorder_desc,
                                        &ms_mkv_player_desc,
#endif
#endif // VIDEO_ENABLED
#if defined(BUILD_WEBRTC_AECM)
                                        &ms_webrtc_aec_desc,
#endif
#ifdef HAVE_OPUS
                                        &ms_opus_dec_desc,
                                        &ms_opus_enc_desc,
#endif
                                        &ms_itc_source_desc,
                                        &ms_itc_sink_desc,
                                        &ms_vad_dtx_desc,
                                        &ms_genericplc_desc,
                                        &ms_rtt_4103_sink_desc,
                                        &ms_rtt_4103_source_desc,
					&mp3_decode_filter_desc,
                    &ms_mp3file_player_desc,
                                        NULL};
