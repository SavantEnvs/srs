// Fuzz the FLV audio/video tag parser (AAC/MP3 audio; AVC/HEVC sequence headers and NALUs).
// The input is a list of records [type:1][len:2 BE][payload] fed to one stateful SrsFormat, so
// a sequence header can precede the frames it configures.
#include <srs_kernel_error.hpp>
#include <srs_kernel_packet.hpp>
#include <srs_protocol_format.hpp>

#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SrsRtmpFormat fmt;
    srs_error_t err = fmt.initialize();
    if (err != srs_success) {
        delete err;
        return 0;
    }

    int64_t ts = 0;
    for (int n = 0; size >= 3 && n < 32; n++) {
        uint8_t type = data[0];
        size_t len = ((size_t)data[1] << 8) | data[2];
        data += 3;
        size -= 3;
        if (len > size) {
            len = size;
        }
        std::vector<char> payload((const char *)data, (const char *)data + len);
        payload.push_back(0);
        data += len;
        size -= len;

        if (type & 1) {
            err = fmt.on_audio(ts, payload.data(), (int)len);
        } else {
            err = fmt.on_video(ts, payload.data(), (int)len);
        }
        ts += 40;
        if (err != srs_success) {
            delete err;
        }
    }
    return 0;
}
