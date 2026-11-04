// Fuzz the WebRTC/GB28181 SDP parser, then re-encode what it accepted.
#include <srs_kernel_error.hpp>
#include <srs_protocol_sdp.hpp>

#include <sstream>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SrsSdp sdp;
    srs_error_t err = sdp.parse(std::string((const char *)data, size));
    if (err != srs_success) {
        delete err;
        return 0;
    }

    (void)sdp.get_ice_ufrag();
    (void)sdp.get_fingerprint();
    (void)sdp.find_media_descs("audio");
    (void)sdp.find_media_descs("video");

    std::ostringstream os;
    err = sdp.encode(os);
    if (err != srs_success) {
        delete err;
    }
    return 0;
}
