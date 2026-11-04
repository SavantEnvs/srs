// Fuzz the AMF0 decoder (RTMP command / metadata encoding).
#include <srs_kernel_error.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_protocol_amf0.hpp>

#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    std::vector<char> copy((const char *)data, (const char *)data + size);
    copy.push_back(0);
    SrsBuffer buf(copy.data(), (int)size);

    // Read a bounded sequence of values, as an RTMP command message carries several.
    for (int i = 0; i < 16 && !buf.empty(); i++) {
        SrsAmf0Any *any = NULL;
        srs_error_t err = srs_amf0_read_any(&buf, &any);
        if (err != srs_success) {
            delete err;
            delete any;
            break;
        }
        (void)any->total_size();
        if (any->is_object()) {
            SrsAmf0Object *obj = any->to_object();
            for (int j = 0; j < obj->count(); j++) {
                (void)obj->key_at(j);
                (void)obj->value_at(j)->total_size();
            }
            SrsAmf0Any *copied = obj->copy();
            delete copied;
        }
        delete any;
    }
    return 0;
}
