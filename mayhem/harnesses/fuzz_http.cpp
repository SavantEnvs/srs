// Fuzz the HTTP request/response parser (llhttp adapter) and the message body readers.
#include <srs_kernel_error.hpp>
#include <srs_kernel_io.hpp>
#include <srs_protocol_http_stack.hpp>
#include <srs_protocol_http_conn.hpp>

#include <string.h>

class MemReader : public ISrsReader
{
public:
    const uint8_t *data_;
    size_t size_;
    size_t pos_;
    MemReader(const uint8_t *d, size_t n) : data_(d), size_(n), pos_(0) {}
    virtual srs_error_t read(void *buf, size_t size, ssize_t *nread)
    {
        if (pos_ >= size_) {
            return srs_error_new(ERROR_SOCKET_READ, "eof");
        }
        size_t n = size < size_ - pos_ ? size : size_ - pos_;
        memcpy(buf, data_ + pos_, n);
        pos_ += n;
        if (nread) {
            *nread = (ssize_t)n;
        }
        return srs_success;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return 0;
    }
    llhttp_type type = (data[0] & 1) ? HTTP_RESPONSE : HTTP_REQUEST;
    data++;
    size--;

    MemReader reader(data, size);
    SrsHttpParser parser;
    srs_error_t err = parser.initialize(type);
    if (err != srs_success) {
        delete err;
        return 0;
    }

    for (int i = 0; i < 4; i++) {
        ISrsHttpMessage *msg = NULL;
        err = parser.parse_message(&reader, &msg);
        if (err != srs_success) {
            delete err;
            delete msg;
            break;
        }
        (void)msg->path();
        (void)msg->query();
        (void)msg->ext();
        (void)msg->url();
        (void)msg->host();
        (void)msg->is_keep_alive();
        (void)msg->header()->content_type();
        std::string body;
        err = msg->body_read_all(body);
        if (err != srs_success) {
            delete err;
        }
        delete msg;
    }
    return 0;
}
