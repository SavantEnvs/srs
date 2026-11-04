// Fuzz the MPEG program stream demuxer used by GB28181.
#include <srs_kernel_error.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_ps.hpp>
#include <srs_kernel_stream.hpp>

#include <vector>

class Handler : public ISrsPsMessageHandler
{
public:
    virtual srs_error_t on_ts_message(SrsTsMessage *msg)
    {
        if (msg->payload_) {
            (void)msg->payload_->length();
        }
        return srs_success;
    }
    virtual void on_recover_mode(int nn_recover) {}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<char> copy((const char *)data, (const char *)data + size);
    copy.push_back(0);
    SrsBuffer buf(copy.data(), (int)size);

    SrsPsContext ctx;
    Handler handler;
    srs_error_t err = ctx.decode(&buf, &handler);
    if (err != srs_success) {
        delete err;
    }
    return 0;
}
