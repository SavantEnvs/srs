// Fuzz the STUN (ICE binding request) packet decoder.
#include <srs_kernel_error.hpp>
#include <srs_protocol_rtc_stun.hpp>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SrsStunPacket pkt;
    srs_error_t err = pkt.decode((const char *)data, (int)size);
    if (err != srs_success) {
        delete err;
        return 0;
    }
    (void)pkt.get_username();
    (void)pkt.get_message_type();
    return 0;
}
