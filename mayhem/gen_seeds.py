#!/usr/bin/env python3
"""Regenerate the starter seeds under mayhem/<target>/testsuite/ (run from the repo root).

Media seeds are derived from SRS's own sample trunk/3rdparty/srs-bench/avatar.flv (H.264 + AAC);
protocol seeds (SDP, STUN, RTCP, RTP, AMF0, HTTP, JSON) are small hand-built messages.
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FLV = os.path.join(ROOT, "trunk/3rdparty/srs-bench/avatar.flv")


def put(target, name, data):
    d = os.path.join(ROOT, "mayhem", target, "testsuite")
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())


def flv_tags(limit_video=6, limit_audio=6):
    data = open(FLV, "rb").read()
    pos = 9
    out = []
    nv = na = 0
    while pos + 15 <= len(data) and (nv < limit_video or na < limit_audio):
        pos += 4
        t = data[pos]
        size = int.from_bytes(data[pos + 1:pos + 4], "big")
        body = data[pos + 11:pos + 11 + size]
        pos += 11 + size
        if t == 9 and nv < limit_video:
            out.append((9, body))
            nv += 1
        elif t == 8 and na < limit_audio:
            out.append((8, body))
            na += 1
    return out


# ---------------------------------------------------------------- format (FLV tag bodies)
tags = flv_tags()
rec = b"".join(bytes([1 if t == 8 else 0]) + struct.pack(">H", len(b)) + b for t, b in tags)
put("fuzz_format", "avatar-av.bin", rec)
put("fuzz_format", "avatar-video.bin", b"".join(bytes([0]) + struct.pack(">H", len(b)) + b for t, b in tags if t == 9))
put("fuzz_format", "avatar-audio.bin", b"".join(bytes([1]) + struct.pack(">H", len(b)) + b for t, b in tags if t == 8))

video = [b for t, b in tags if t == 9]
audio = [b for t, b in tags if t == 8]
avcc = video[0][5:]  # AVCDecoderConfigurationRecord


def parse_avcc(rec):
    n_sps = rec[5] & 0x1F
    p = 6
    sps = []
    for _ in range(n_sps):
        l = struct.unpack(">H", rec[p:p + 2])[0]
        sps.append(rec[p + 2:p + 2 + l])
        p += 2 + l
    n_pps = rec[p]
    p += 1
    pps = []
    for _ in range(n_pps):
        l = struct.unpack(">H", rec[p:p + 2])[0]
        pps.append(rec[p + 2:p + 2 + l])
        p += 2 + l
    return sps, pps


def avcc_to_annexb(sample, nal_len=4):
    out = b""
    p = 0
    while p + nal_len <= len(sample):
        l = int.from_bytes(sample[p:p + nal_len], "big")
        out += b"\x00\x00\x00\x01" + sample[p + nal_len:p + nal_len + l]
        p += nal_len + l
    return out


sps, pps = parse_avcc(avcc)
frames = [avcc_to_annexb(b[5:]) for b in video[1:] if len(b) > 5]
annexb_params = b"".join(b"\x00\x00\x00\x01" + s for s in sps) + b"".join(b"\x00\x00\x00\x01" + p for p in pps)

# ---------------------------------------------------------------- mpegts
def crc32_mpeg(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 else (crc << 1) & 0xFFFFFFFF
    return crc


def ts_packet(pid, payload, pusi, cc, pcr=None):
    hdr = bytes([0x47, (0x40 if pusi else 0) | (pid >> 8), pid & 0xFF])
    room = 184
    if pcr is not None or len(payload) < room:
        af = bytearray([0x00, 0x10 if pcr is not None else 0x00])
        if pcr is not None:
            base = pcr * 300 // 300
            af += struct.pack(">Q", (base << 15) | (0x3F << 9))[3:]
            af += b""
        pad = room - len(payload) - len(af) - 0
        if pad < 0:
            raise ValueError("payload too large")
        af += b"\xff" * pad
        af[0] = len(af) - 1
        hdr += bytes([0x30 | (cc & 0xF)])
        return hdr + bytes(af) + payload
    hdr += bytes([0x10 | (cc & 0xF)])
    return hdr + payload


def psi(table_id, body_after_len_fields):
    sect = bytes([table_id]) + body_after_len_fields
    return sect


def pat():
    body = struct.pack(">H", 1) + bytes([0xC1, 0, 0]) + struct.pack(">HH", 1, 0xE000 | 0x1000)
    sect = bytes([0x00]) + struct.pack(">H", 0xB000 | (len(body) + 4)) + body
    sect += struct.pack(">I", crc32_mpeg(sect))
    return b"\x00" + sect


def pmt(video_pid=0x100, audio_pid=0x101):
    streams = bytes([0x1B]) + struct.pack(">HH", 0xE000 | video_pid, 0xF000) + bytes([0x0F]) + struct.pack(">HH", 0xE000 | audio_pid, 0xF000)
    body = struct.pack(">H", 1) + bytes([0xC1, 0, 0]) + struct.pack(">HH", 0xE000 | video_pid, 0xF000) + streams
    sect = bytes([0x02]) + struct.pack(">H", 0xB000 | (len(body) + 4)) + body
    sect += struct.pack(">I", crc32_mpeg(sect))
    return b"\x00" + sect


def pes(stream_id, payload, pts):
    def ts5(prefix, v):
        return bytes([(prefix << 4) | (((v >> 30) & 7) << 1) | 1, (v >> 22) & 0xFF, (((v >> 15) & 0x7F) << 1) | 1, (v >> 7) & 0xFF, ((v & 0x7F) << 1) | 1])
    hdr = ts5(2, pts)
    body = bytes([0x80, 0x80, len(hdr)]) + hdr + payload
    length = len(body) if len(body) <= 0xFFFF and stream_id != 0xE0 else 0
    return b"\x00\x00\x01" + bytes([stream_id]) + struct.pack(">H", length) + body


def mux_ts(es_video, es_audio_adts=None):
    out = ts_packet(0, pat(), True, 0) + ts_packet(0x1000, pmt(), True, 0)
    cc = {0x100: 0, 0x101: 0}
    pts = 90000
    for au in es_video:
        data = pes(0xE0, au, pts)
        first = True
        while data:
            room = 184 - (8 if first else 0)
            chunk, data = data[:184], data[184:]
            if len(chunk) == 184:
                out += bytes([0x47, (0x40 if first else 0) | 1, 0x00, 0x10 | (cc[0x100] & 0xF)]) + chunk
            else:
                out += ts_packet(0x100, chunk, first, cc[0x100], pcr=(pts if first else None) if False else None)
            cc[0x100] += 1
            first = False
        pts += 3600
    return out


put("fuzz_ts", "avatar-h264.ts", mux_ts([annexb_params + frames[0]] + frames[1:4]))
put("fuzz_ts", "avatar-h264-short.ts", mux_ts([annexb_params + frames[0]]))
# ADTS AAC frame (AAC-LC 44.1k stereo, 7-byte header, 16 payload bytes) in an audio PES.
adts = bytes([0xFF, 0xF1, 0x50, 0x80, 0x02, 0x1F, 0xFC]) + bytes(16 - 7 + 7)
adts = adts[:7] + bytes(16)
adts = bytes([0xFF, 0xF1, 0x50, 0x80, ((7 + 16) >> 3) & 0xFF, (((7 + 16) & 7) << 5) | 0x1F, 0xFC]) + bytes(16)
audio_ts = ts_packet(0, pat(), True, 0) + ts_packet(0x1000, pmt(), True, 0)
audio_ts += ts_packet(0x101, pes(0xC0, adts, 90000), True, 0)
put("fuzz_ts", "adts-audio.ts", audio_ts)

# ---------------------------------------------------------------- ps (GB28181 program stream)
def ps_pack_header(scr=0):
    b = bytearray(14)
    b[0:4] = b"\x00\x00\x01\xba"
    v = (1 << 46) | (((scr >> 30) & 7) << 43) | (1 << 42) | (((scr >> 15) & 0x7FFF) << 27) | (1 << 26) | ((scr & 0x7FFF) << 11) | (1 << 10)
    b[4:10] = (v << 0).to_bytes(6, "big")[-6:]
    b[10:13] = bytes([0x01, 0x89, 0xC3])
    b[13] = 0xF8
    return bytes(b)


def ps_system_header():
    body = bytes([0x80, 0x1B, 0xC1, 0x00, 0xE1, 0x7F, 0xE0, 0xE0, 0x80, 0xC0, 0xC0, 0x08])
    return b"\x00\x00\x01\xbb" + struct.pack(">H", len(body)) + body


def ps_map():
    es = bytes([0x1B, 0xE0, 0x00, 0x00])
    body = bytes([0xE1, 0xFF, 0x00, 0x00]) + struct.pack(">H", len(es)) + es
    body += struct.pack(">I", crc32_mpeg(b"\x00\x00\x01\xbc" + struct.pack(">H", len(body) + 4) + body))
    return b"\x00\x00\x01\xbc" + struct.pack(">H", len(body)) + body


def ps_pes(sid, payload, pts):
    return pes(sid, payload, pts)


ps_video = ps_pack_header() + ps_system_header() + ps_map() + ps_pes(0xE0, annexb_params + frames[0][:1200], 90000)
put("fuzz_ps", "avatar-h264.ps", ps_video)
put("fuzz_ps", "avatar-h264-2pack.ps", ps_video + ps_pack_header(3600) + ps_pes(0xE0, frames[1][:900], 93600))
put("fuzz_ps", "audio.ps", ps_pack_header() + ps_pes(0xC0, adts, 90000))

# ---------------------------------------------------------------- mp4
def box(t, payload=b""):
    return struct.pack(">I", 8 + len(payload)) + t + payload


def fullbox(t, payload=b"", ver=0, flags=0):
    return box(t, bytes([ver]) + flags.to_bytes(3, "big") + payload)


def build_mp4():
    samples = [b[5:] for b in video[1:] if len(b) > 5][:5]
    ftyp = box(b"ftyp", b"isom" + struct.pack(">I", 512) + b"isomiso2avc1mp41")
    mdat_payload = b"".join(samples)
    # sizes are fixed so the chunk offset can be computed after building moov
    def moov(offset):
        mvhd = fullbox(b"mvhd", struct.pack(">IIII", 0, 0, 1000, 200) + struct.pack(">IH", 0x10000, 0x100) + bytes(10)
                       + struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) + bytes(24) + struct.pack(">I", 2))
        tkhd = fullbox(b"tkhd", struct.pack(">IIIII", 0, 0, 1, 0, 200) + bytes(8) + struct.pack(">hhhH", 0, 0, 0, 0)
                       + struct.pack(">9I", 0x10000, 0, 0, 0, 0x10000, 0, 0, 0, 0x40000000) + struct.pack(">II", 320 << 16, 240 << 16), flags=3)
        mdhd = fullbox(b"mdhd", struct.pack(">IIII", 0, 0, 1000, 200) + struct.pack(">HH", 0x55C4, 0))
        hdlr = fullbox(b"hdlr", struct.pack(">I", 0) + b"vide" + bytes(12) + b"VideoHandler\x00")
        avc1 = bytes(6) + struct.pack(">H", 1) + bytes(16) + struct.pack(">HH", 320, 240) + struct.pack(">II", 0x480000, 0x480000) + struct.pack(">I", 0) \
            + struct.pack(">H", 1) + bytes(32) + struct.pack(">Hh", 0x18, -1) + box(b"avcC", avcc)
        stsd = fullbox(b"stsd", struct.pack(">I", 1) + box(b"avc1", avc1))
        stts = fullbox(b"stts", struct.pack(">III", 1, len(samples), 40))
        stsc = fullbox(b"stsc", struct.pack(">IIII", 1, 1, len(samples), 1))
        stsz = fullbox(b"stsz", struct.pack(">II", 0, len(samples)) + b"".join(struct.pack(">I", len(s)) for s in samples))
        stco = fullbox(b"stco", struct.pack(">II", 1, offset))
        stss = fullbox(b"stss", struct.pack(">II", 1, 1))
        stbl = box(b"stbl", stsd + stts + stss + stsc + stsz + stco)
        minf = box(b"minf", fullbox(b"vmhd", bytes(8), flags=1) + box(b"dinf", fullbox(b"dref", struct.pack(">I", 1) + fullbox(b"url ", b"", flags=1))) + stbl)
        trak = box(b"trak", tkhd + box(b"mdia", mdhd + hdlr + minf))
        return box(b"moov", mvhd + trak)
    m = moov(0)
    off = len(ftyp) + len(m) + 8
    return ftyp + moov(off) + box(b"mdat", mdat_payload)


put("fuzz_mp4", "avatar-h264.mp4", build_mp4())
put("fuzz_mp4", "ftyp-free-mdat.mp4", box(b"ftyp", b"isom" + bytes(4) + b"isom") + box(b"free", bytes(8)) + box(b"mdat", bytes(32)))

# ---------------------------------------------------------------- sdp
OFFER = """v=0
o=- 4611731400430051336 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0 1
a=msid-semantic: WMS stream
m=audio 9 UDP/TLS/RTP/SAVPF 111
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:ZkBn
a=ice-pwd:0u8W0yPbfBMdEnBdbPNTYO1P
a=fingerprint:sha-256 8F:2D:5B:3E:1A:0C:77:42:99:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67
a=setup:actpass
a=mid:0
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=sendrecv
a=rtcp-mux
a=rtpmap:111 opus/48000/2
a=rtcp-fb:111 transport-cc
a=fmtp:111 minptime=10;useinbandfec=1
a=ssrc:1001 cname:audiocname
m=video 9 UDP/TLS/RTP/SAVPF 102 103
c=IN IP4 0.0.0.0
a=rtcp:9 IN IP4 0.0.0.0
a=ice-ufrag:ZkBn
a=ice-pwd:0u8W0yPbfBMdEnBdbPNTYO1P
a=setup:actpass
a=mid:1
a=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=sendrecv
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:102 H264/90000
a=rtcp-fb:102 goog-remb
a=rtcp-fb:102 transport-cc
a=rtcp-fb:102 ccm fir
a=rtcp-fb:102 nack
a=rtcp-fb:102 nack pli
a=fmtp:102 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f
a=rtpmap:103 rtx/90000
a=fmtp:103 apt=102
a=ssrc-group:FID 2001 2002
a=ssrc:2001 cname:videocname
a=ssrc:2002 cname:videocname
a=candidate:1 1 udp 2130706431 192.168.1.10 8000 typ host
"""
put("fuzz_sdp", "offer.sdp", OFFER.replace("\n", "\r\n"))
put("fuzz_sdp", "offer-lf.sdp", OFFER)
put("fuzz_sdp", "audio-only.sdp", "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\na=rtpmap:111 opus/48000/2\r\n")

# ---------------------------------------------------------------- stun
def stun_attr(t, v):
    pad = (-len(v)) % 4
    return struct.pack(">HH", t, len(v)) + v + bytes(pad)


def stun(msg_type, attrs):
    body = b"".join(attrs)
    return struct.pack(">HHI", msg_type, len(body), 0x2112A442) + bytes(range(1, 13)) + body


put("fuzz_stun", "binding-request.bin", stun(0x0001, [
    stun_attr(0x0006, b"ZkBn:abcd"), stun_attr(0x802A, bytes(8)), stun_attr(0x0024, struct.pack(">I", 0x6E7F1EFF)),
    stun_attr(0x0025, b""), stun_attr(0x0008, bytes(range(20))), stun_attr(0x8028, struct.pack(">I", 0x12345678))]))
put("fuzz_stun", "binding-request-min.bin", stun(0x0001, [stun_attr(0x0006, b"a:b")]))
put("fuzz_stun", "binding-success.bin", stun(0x0101, [stun_attr(0x0020, bytes([0, 1, 0x21, 0x12, 0xE1, 0xBA, 0xA5, 0x42]) )]))

# ---------------------------------------------------------------- rtcp
def rtcp(pt, count_or_fmt, body):
    words = (4 + len(body)) // 4 - 1
    return bytes([0x80 | count_or_fmt, pt]) + struct.pack(">H", words) + body


sr = rtcp(200, 1, struct.pack(">IIIIII", 1001, 0xE0000000, 0x12345678, 90000, 100, 20000)
          + struct.pack(">IIIIII", 2001, 0, 1000, 5000, 7, 0)[:24])
rr = rtcp(201, 1, struct.pack(">I", 1001) + struct.pack(">IIIIII", 2001, 0, 1000, 5000, 7, 0))
sdes = rtcp(202, 1, struct.pack(">I", 1001) + bytes([1, 4]) + b"test" + bytes([0, 0, 0]))
nack = rtcp(205, 1, struct.pack(">II", 1001, 2001) + struct.pack(">HH", 100, 0x0005))
pli = rtcp(206, 1, struct.pack(">II", 1001, 2001))
remb = rtcp(206, 15, struct.pack(">II", 1001, 0) + b"REMB" + bytes([1, 0x18, 0x1F, 0xE0]) + struct.pack(">I", 2001))
twcc = rtcp(205, 15, struct.pack(">II", 1001, 2001) + struct.pack(">HHI", 10, 3, (0x123456 << 8) | 7)
            + struct.pack(">HH", 0x2003, 0x2001) + bytes([0x20, 0x40, 0x20, 0x00]))
bye = rtcp(203, 1, struct.pack(">I", 1001))
xr = rtcp(207, 0, struct.pack(">I", 1001) + bytes([4, 0]) + struct.pack(">H", 2) + struct.pack(">II", 0x12345678, 0x9ABCDEF0))
put("fuzz_rtcp", "sr-sdes.bin", sr + sdes)
put("fuzz_rtcp", "rr.bin", rr)
put("fuzz_rtcp", "nack.bin", nack)
put("fuzz_rtcp", "pli-remb.bin", pli + remb)
put("fuzz_rtcp", "twcc.bin", twcc)
put("fuzz_rtcp", "bye-xr.bin", bye + xr)

# ---------------------------------------------------------------- rtp (first byte = mode, see fuzz_rtp.cpp)
def rtp(payload, pt=102, seq=100, ts=90000, ssrc=0x7D1, ext=b"", marker=1):
    x = 0x10 if ext else 0
    hdr = bytes([0x80 | x, (marker << 7) | pt]) + struct.pack(">HII", seq, ts, ssrc)
    if ext:
        hdr += b"\xbe\xde" + struct.pack(">H", len(ext) // 4) + ext
    return hdr + payload


twcc_ext = bytes([0x11, 0x00, 0x2A, 0x00])  # id=1 len=2: transport-wide seq 42
audio_ext = bytes([0x20, 0x85, 0x00, 0x00])  # id=2 len=1: audio level
nalu_idr = bytes([0x65]) + bytes(range(1, 40))
nalu_sps = sps[0]
nalu_pps = pps[0]
stap = bytes([0x18]) + b"".join(struct.pack(">H", len(n)) + n for n in (nalu_sps, nalu_pps, nalu_idr))
fua_start = bytes([0x7C, 0x85]) + bytes(range(50, 90))
fua_mid = bytes([0x7C, 0x05]) + bytes(range(90, 130))
fua_end = bytes([0x7C, 0x45]) + bytes(range(130, 150))
put("fuzz_rtp", "avc-idr.bin", bytes([1]) + rtp(nalu_idr))
put("fuzz_rtp", "avc-stap-a.bin", bytes([1]) + rtp(stap))
put("fuzz_rtp", "avc-fu-a.bin", bytes([1]) + rtp(fua_start, marker=0))
put("fuzz_rtp", "avc-fu-a-end.bin", bytes([1]) + rtp(fua_end))
put("fuzz_rtp", "avc-twcc.bin", bytes([1 | 8]) + rtp(nalu_idr, ext=twcc_ext))
put("fuzz_rtp", "avc-audio-level.bin", bytes([1 | 8]) + rtp(nalu_idr, ext=audio_ext + bytes(0)))
put("fuzz_rtp", "avc-fua-old.bin", bytes([3]) + rtp(fua_mid))
hevc_stap = bytes([0x60, 0x01]) + b"".join(struct.pack(">H", len(n)) + n for n in (bytes([0x40, 0x01, 0x0C, 0x01]), bytes([0x42, 0x01, 0x01, 0x01]), bytes([0x4E, 0x01]) + bytes(20)))
hevc_fu = bytes([0x62, 0x01, 0x93]) + bytes(range(1, 40))
put("fuzz_rtp", "hevc-stap.bin", bytes([2]) + rtp(hevc_stap, pt=104))
put("fuzz_rtp", "hevc-fu.bin", bytes([2]) + rtp(hevc_fu, pt=104))
put("fuzz_rtp", "hevc-fu-old.bin", bytes([4]) + rtp(hevc_fu, pt=104))

# ---------------------------------------------------------------- amf0
def amf_str(s):
    return b"\x02" + struct.pack(">H", len(s)) + s.encode()


def amf_key(s):
    return struct.pack(">H", len(s)) + s.encode()


def amf_num(v):
    return b"\x00" + struct.pack(">d", v)


def amf_obj(items):
    out = b"\x03"
    for k, v in items:
        out += amf_key(k) + v
    return out + b"\x00\x00\x09"


connect = amf_str("connect") + amf_num(1) + amf_obj([
    ("app", amf_str("live")), ("type", amf_str("nonprivate")), ("flashVer", amf_str("FMLE/3.0")),
    ("tcUrl", amf_str("rtmp://127.0.0.1/live")), ("fpad", b"\x01\x00"), ("capabilities", amf_num(239)),
    ("audioCodecs", amf_num(3575)), ("videoCodecs", amf_num(252)), ("videoFunction", amf_num(1))])
meta = amf_str("onMetaData") + b"\x08" + struct.pack(">I", 4) + amf_key("duration") + amf_num(12.5) + amf_key("width") + amf_num(320) \
    + amf_key("height") + amf_num(240) + amf_key("videocodecid") + amf_num(7) + b"\x00\x00\x09"
publish = amf_str("publish") + amf_num(5) + b"\x05" + amf_str("livestream") + amf_str("live")
arr = amf_str("result") + amf_num(1) + b"\x05" + b"\x0a" + struct.pack(">I", 3) + amf_num(1) + amf_str("two") + b"\x01\x01"
put("fuzz_amf0", "connect.bin", connect)
put("fuzz_amf0", "onmetadata.bin", meta)
put("fuzz_amf0", "publish.bin", publish)
put("fuzz_amf0", "strict-array.bin", arr)

# ---------------------------------------------------------------- json
put("fuzz_json", "api-response.json", '{"code":0,"server":"vid-1","service":"svc","pid":"42","data":{"streams":[{"id":"s1","name":"livestream","video":{"codec":"H264","profile":"High","level":"4.1","width":1280,"height":720},"audio":null,"publish":{"active":true,"cid":"x"},"kbps":{"recv_30s":1500.5,"send_30s":0}}],"ok":[true,false,null]}}')
put("fuzz_json", "nested.json", '[1,-2.5e3,"a\\u00e9\\n",{"k":[[],{}]},{"":""}]')
put("fuzz_json", "hook.json", '{"action":"on_publish","client_id":"3p7w1v6q","ip":"127.0.0.1","vhost":"__defaultVhost__","app":"live","tcUrl":"rtmp://127.0.0.1/live","stream":"livestream","param":"?secret=1"}')

# ---------------------------------------------------------------- http (first byte 0=request, 1=response)
put("fuzz_http", "get.http", b"\x00GET /api/v1/versions?k=v&x=1 HTTP/1.1\r\nHost: 127.0.0.1:1985\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
put("fuzz_http", "post.http", b"\x00POST /rtc/v1/play/ HTTP/1.1\r\nHost: srs.local\r\nContent-Type: application/json\r\nContent-Length: 17\r\n\r\n{\"api\":\"/x\",\"a\":1}")
put("fuzz_http", "chunked.http", b"\x00PUT /live/livestream.flv HTTP/1.1\r\nHost: srs.local\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
put("fuzz_http", "response.http", b"\x01HTTP/1.1 200 OK\r\nServer: SRS\r\nContent-Type: video/x-flv\r\nContent-Length: 5\r\n\r\nhello")
put("fuzz_http", "two-requests.http", b"\x00GET /a HTTP/1.1\r\nHost: x\r\n\r\nGET /b.m3u8 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")

print("seeds written under", os.path.join(ROOT, "mayhem"))
