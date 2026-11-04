// Fuzz the RTP packet decoder: header, header extensions (one-byte, TWCC) and the
// AVC/HEVC payload depacketizers (raw, STAP-A, FU-A, AP, FU).
#include <srs_kernel_error.hpp>
#include <srs_kernel_buffer.hpp>
#include <srs_kernel_rtc_rtp.hpp>

#include <vector>

class PayloadChooser : public ISrsRtpPacketDecodeHandler
{
public:
    int codec_;
    PayloadChooser(int codec) : codec_(codec) {}
    virtual void on_before_decode_payload(SrsRtpPacket *pkt, SrsBuffer *buf, ISrsRtpPayloader **ppayload, SrsRtpPacketPayloadType *ppt)
    {
        if (buf->empty()) {
            return;
        }
        if (codec_ == 1) {
            uint8_t v = SrsAvcNaluTypeParse(buf->head()[0]);
            pkt->nalu_type_ = v;
            if (v == kStapA) {
                *ppayload = new SrsRtpSTAPPayload();
                *ppt = SrsRtpPacketPayloadTypeSTAP;
            } else if (v == kFuA) {
                *ppayload = new SrsRtpFUAPayload2();
                *ppt = SrsRtpPacketPayloadTypeFUA2;
            }
        } else if (codec_ == 2) {
            uint8_t v = SrsHevcNaluTypeParse(buf->head()[0]);
            pkt->nalu_type_ = v;
            if (v == kStapHevc) {
                *ppayload = new SrsRtpSTAPPayloadHevc();
                *ppt = SrsRtpPacketPayloadTypeSTAPHevc;
            } else if (v == kFuHevc) {
                *ppayload = new SrsRtpFUAPayloadHevc2();
                *ppt = SrsRtpPacketPayloadTypeFUAHevc2;
            }
        } else if (codec_ == 3) {
            uint8_t v = SrsAvcNaluTypeParse(buf->head()[0]);
            pkt->nalu_type_ = v;
            if (v == kStapA) {
                *ppayload = new SrsRtpSTAPPayload();
                *ppt = SrsRtpPacketPayloadTypeSTAP;
            } else if (v == kFuA) {
                *ppayload = new SrsRtpFUAPayload();
                *ppt = SrsRtpPacketPayloadTypeFUA;
            }
        } else if (codec_ == 4) {
            uint8_t v = SrsHevcNaluTypeParse(buf->head()[0]);
            pkt->nalu_type_ = v;
            if (v == kFuHevc) {
                *ppayload = new SrsRtpFUAPayloadHevc();
                *ppt = SrsRtpPacketPayloadTypeFUAHevc;
            }
        }
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return 0;
    }
    // The first byte picks the payload depacketizer and whether TWCC extensions are decoded.
    int codec = data[0] & 0x07;
    bool twcc = data[0] & 0x08;
    data++;
    size--;

    std::vector<char> copy((const char *)data, (const char *)data + size);
    copy.push_back(0);

    SrsRtpExtensionTypes types;
    types.register_id(1, kRtpExtensionTransportSequenceNumber, "http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01");
    types.register_id(2, kRtpExtensionAudioLevel, "urn:ietf:params:rtp-hdrext:ssrc-audio-level");

    SrsRtpPacket pkt;
    PayloadChooser chooser(codec);
    pkt.set_decode_handler(&chooser);
    pkt.set_extension_types(&types);
    if (twcc) {
        pkt.enable_twcc_decode();
    }

    SrsBuffer buf(copy.data(), (int)size);
    srs_error_t err = pkt.decode(&buf);
    if (err != srs_success) {
        delete err;
        return 0;
    }
    (void)pkt.nb_bytes();
    // Keyframe detection downcasts the payload, so it is only valid for the depacketizers the
    // server's receive track installs (modes 1 and 2); modes 3 and 4 are the send-side classes.
    if (codec == 1) {
        (void)pkt.is_keyframe(SrsVideoCodecIdAVC);
    } else if (codec == 2) {
        (void)pkt.is_keyframe(SrsVideoCodecIdHEVC);
    }

    uint16_t sn = 0;
    srs_error_t e2 = srs_rtp_fast_parse_twcc(copy.data(), (int)size, 1, sn);
    if (e2 != srs_success) {
        delete e2;
    }
    return 0;
}
