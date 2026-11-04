// Fuzz the compound RTCP packet decoder (SR/RR/NACK/TWCC/PLI/XR...).
#include <srs_kernel_error.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_rtc_rtcp.hpp>

#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // The decoder reads a 4-byte common header without checking the length; shorter inputs are not RTCP.
    if (size < 4) {
        return -1;
    }
    std::vector<char> copy((const char *)data, (const char *)data + size);
    copy.push_back(0);
    SrsBuffer buf(copy.data(), (int)size);
    SrsRtcpCompound rtcp;
    srs_error_t err = rtcp.decode(&buf);
    if (err != srs_success) {
        delete err;
        return 0;
    }
    SrsRtcpCommon *c = NULL;
    while ((c = rtcp.get_next_rtcp()) != NULL) {
        (void)c->type();
        (void)c->get_ssrc();
        (void)c->nb_bytes();
    }
    return 0;
}
