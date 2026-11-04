// Fuzz the JSON parser used by the HTTP API, callbacks and config.
#include <srs_kernel_error.hpp>
#include <srs_protocol_json.hpp>

#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    SrsJsonAny *any = SrsJsonAny::loads(std::string((const char *)data, size));
    if (!any) {
        return 0;
    }
    (void)any->dumps();
    if (any->is_object()) {
        SrsJsonObject *obj = any->to_object();
        for (int i = 0; i < obj->count(); i++) {
            (void)obj->key_at(i);
            (void)obj->value_at(i)->dumps();
        }
    }
    delete any;
    return 0;
}
