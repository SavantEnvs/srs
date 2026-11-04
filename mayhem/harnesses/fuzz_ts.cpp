// Fuzz the MPEG-TS demuxer (PAT/PMT/PES), then demux the elementary stream payloads.
#include <srs_kernel_error.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_stream.hpp>
#include <srs_kernel_ts.hpp>
#include <srs_protocol_raw_avc.hpp>

#include <vector>

class Handler : public ISrsTsHandler
{
public:
    virtual srs_error_t on_ts_message(SrsTsMessage *msg)
    {
        if (!msg->payload_ || msg->payload_->length() <= 0) {
            return srs_success;
        }
        std::vector<char> pl(msg->payload_->bytes(), msg->payload_->bytes() + msg->payload_->length());
        SrsBuffer es(pl.data(), (int)pl.size());
        if (msg->is_video()) {
            SrsRawH264Stream avc;
            for (int i = 0; i < 64 && !es.empty(); i++) {
                char *frame = NULL;
                int nb = 0;
                srs_error_t err = avc.annexb_demux(&es, &frame, &nb);
                if (err != srs_success) {
                    delete err;
                    break;
                }
                if (nb > 0 && frame) {
                    (void)SrsAvcNaluTypeParse(frame[0]);
                }
            }
        } else if (msg->is_audio()) {
            SrsRawAacStream aac;
            for (int i = 0; i < 64 && !es.empty(); i++) {
                char *frame = NULL;
                int nb = 0;
                SrsRawAacStreamCodec codec;
                srs_error_t err = aac.adts_demux(&es, &frame, &nb, codec);
                if (err != srs_success) {
                    delete err;
                    break;
                }
            }
        }
        return srs_success;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<char> copy((const char *)data, (const char *)data + size);
    copy.push_back(0);
    SrsBuffer buf(copy.data(), (int)size);

    SrsTsContext ctx;
    Handler handler;
    srs_error_t err = ctx.decode(&buf, &handler);
    if (err != srs_success) {
        delete err;
    }
    return 0;
}
