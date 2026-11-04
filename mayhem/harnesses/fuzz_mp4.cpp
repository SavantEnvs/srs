// Fuzz the MP4 demuxer: box discovery/decoding, the moov sample tables, then sample lookup.
//
// This walks the boxes itself instead of calling SrsMp4Decoder::initialize(). That function loops on
// SrsMp4Decoder::load_next_box() and, for a top-level box whose size field is 0, SrsMp4BoxReader::skip()
// erases 0 bytes from its stream, so the same box is read again forever (upstream bug, reproducer in
// mayhem/fuzz_mp4/known-findings/). A Mayhem run that finds it fails its regression smoketest on
// every run, because the hanging input is replayed from the stored corpus.
// Per ISO/IEC 14496-12 section 4.2, size 0 marks the last box of the file, so the walk ends there; every
// box, including that one, still goes through the library's own discovery() and decode().
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_error.hpp>
#include <srs_kernel_mp4.hpp>

#include <string.h>

static void touch_moov(SrsMp4MovieBox *moov, const uint8_t *data, size_t size)
{
    // The queries SrsMp4Decoder::parse_moov() makes on the movie box.
    SrsMp4MovieHeaderBox *mvhd = moov->mvhd();
    if (!mvhd) {
        return;
    }
    (void)mvhd->duration();

    SrsMp4TrackBox *vide = moov->video();
    SrsMp4TrackBox *soun = moov->audio();
    if (!vide && !soun) {
        return;
    }
    if (soun && soun->mp4a()) {
        (void)soun->mp4a()->samplerate_;
        (void)soun->mp4a()->samplesize_;
        (void)soun->mp4a()->channelcount_;
    }
    SrsMp4AvccBox *avcc = vide ? vide->avcc() : NULL;
    SrsMp4DecoderSpecificInfo *asc = soun ? soun->asc() : NULL;
    (void)(vide ? vide->vide_codec() : SrsVideoCodecIdForbidden);
    (void)(soun ? soun->soun_codec() : SrsAudioCodecIdForbidden);
    (void)(avcc ? avcc->avc_config_.size() : 0);
    (void)(asc ? asc->asc_.size() : 0);
    (void)moov->nb_vide_tracks();
    (void)moov->nb_soun_tracks();

    SrsMp4SampleManager samples;
    srs_error_t err = samples.load(moov);
    if (err != srs_success) {
        delete err;
        return;
    }
    // Like SrsMp4Decoder::read_sample(): look the samples up in order and read their bytes.
    for (uint32_t i = 0; i < 256; i++) {
        SrsMp4Sample *ps = samples.at(i);
        if (!ps) {
            break;
        }
        (void)ps->dts_ms();
        (void)ps->pts_ms();
        if (ps->offset_ >= 0 && (uint64_t)ps->offset_ + ps->nb_data_ <= size) {
            volatile uint8_t sink = 0;
            for (uint32_t k = 0; k < ps->nb_data_; k += 64) {
                sink = data[ps->offset_ + k];
            }
            (void)sink;
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint64_t off = 0;
    while (off < size) {
        SrsBuffer peek((char *)data + off, (int)(size - off));
        SrsMp4Box *raw = NULL;
        srs_error_t err = SrsMp4Box::discovery(&peek, &raw);
        if (err != srs_success) {
            delete err;
            break;
        }
        SrsMp4Box *box = raw;
        uint64_t sz = box->sz();

        // SrsMp4BoxReader hands the decoder a box only once all of it is available (mdat: its header).
        if (!box->is_mdat() && sz > size - off) {
            delete box;
            break;
        }

        SrsBuffer buf((char *)data + off, (int)(size - off));
        err = box->decode(&buf);
        if (err != srs_success) {
            delete err;
            delete box;
            break;
        }

        if (box->is_moov()) {
            touch_moov(dynamic_cast<SrsMp4MovieBox *>(box), data, size);
        }
        delete box;

        if (sz == 0) {
            break;
        }
        off += sz;
    }
    return 0;
}
