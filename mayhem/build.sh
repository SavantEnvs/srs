#!/usr/bin/env bash
#
# mayhem/build.sh — build SRS's fuzz harnesses and its gtest suite (offline, re-runnable).
#
# Runs inside the commit image as `mayhem` in /mayhem; the base image exports CC/CXX/SANITIZER_FLAGS/
# LIB_FUZZING_ENGINE/STANDALONE_FUZZ_MAIN/SRC.
#
# Layout of the build:
#   1. SRS's own ./configure builds its in-tree third parties (openssl, libsrtp, srt, st) with GCC and
#      the gtest binary `trunk/objs/srs_utest` with the project's normal flags (the test oracle).
#      OpenSSL 1.1.1 miscompiles with clang 19 (EC_GROUP_new_by_curve_name fails), so GCC builds those.
#   2. SRS's own core/kernel/protocol sources are then compiled with clang + $SANITIZER_FLAGS +
#      $DEBUG_FLAGS + SanitizerCoverage into trunk/objs/fuzz, and linked into every harness.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC/trunk"
OBJS="$SRC/trunk/objs"
OUT="$SRC/mayhem/out"   # fuzz + standalone binaries; gitignored via mayhem/.gitignore
LOGDIR="${TMPDIR:-/tmp}"
mkdir -p "$OUT"

# 1) Third parties + gtest suite, normal flags, GCC (SRS's default toolchain).
(
    # The configure script must not inherit the sanitizer/clang environment of the fuzz build.
    unset CC CXX CFLAGS CXXFLAGS LDFLAGS SANITIZER_FLAGS
    ./configure --cc=gcc --cxx=g++ --utest=on --sanitizer=off --srt=on --gb28181=on --rtsp=on \
        --ffmpeg-opus=off --nasm=off --srtp-nasm=off --build-cache=off --jobs="$MAYHEM_JOBS" \
        --extra-flags="$COVERAGE_FLAGS" >"$LOGDIR/srs-configure.log" 2>&1 || { tail -50 "$LOGDIR/srs-configure.log"; exit 1; }
    make utest -j"$MAYHEM_JOBS" >"$LOGDIR/srs-utest.log" 2>&1 || { tail -50 "$LOGDIR/srs-utest.log"; exit 1; }
)
# configure resets objs/src, so a stable copy of the test runner is kept outside the object tree.
mkdir -p "$SRC/trunk/objs/test"
cp -f "$OBJS/srs_utest" "$OBJS/test/srs_utest"

# 2) Sanitized, coverage-instrumented SRS objects for the fuzz targets.
FUZZ="$OBJS/fuzz"
mkdir -p "$FUZZ"
INCS="-I$SRC/trunk/src/core -I$SRC/trunk/src/kernel -I$SRC/trunk/src/protocol -I$SRC/trunk/src/app
      -I$OBJS -I$OBJS/st -I$OBJS/openssl/include -I$OBJS/srt/include -I$OBJS/srtp2/include"
CXXFLAGS_FUZZ="-std=c++11 -O1 -D_GLIBCXX_ASSERTIONS $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -Wno-unused-command-line-argument -w"

compile_one() {
    local src="$1" obj="$FUZZ/$(basename "${1%.cpp}").o" extra=""
    # Per-file UBSan relaxations; ASan and every other UBSan check stay halting everywhere.
    case "$src" in
        # srs_rtp_fast_parse_twcc reads ntohs(*(uint16_t*)p) from the packed RTP header-extension bytes
        # (fine on x86). Fires on seed fuzz_rtp/avc-twcc.bin at srs_kernel_rtc_rtp.cpp:121:23; the only
        # such casts in core/kernel/protocol are in this file (lines 94, 101, 121).
        *srs_kernel_rtc_rtp.cpp) extra="-fno-sanitize=alignment" ;;
        # The vendored llhttp amalgamation flushes a span (llhttp__on_method, _on_header_field, ...) at the
        # end of input through a `const char*`-typed pointer to an `unsigned char*` function: fires at
        # srs_protocol_http_stack_llhttp.cpp:10126:17 on any fuzz_http input that ends mid-token
        # (e.g. seed get.http cut to "\0GE"), before any SRS code runs.
        *srs_protocol_http_stack_llhttp.cpp) extra="-fno-sanitize=function" ;;
        # The vendored json-parser sizes its arena with a first pass that advances a NULL pointer: fires on
        # every fuzz_json seed at srs_protocol_json.cpp:748:34 (applying non-zero offset to null pointer).
        *srs_protocol_json.cpp) extra="-fno-sanitize=pointer-overflow" ;;
    esac
    if [ ! -f "$obj" ] || [ "$src" -nt "$obj" ]; then
        $CXX $CXXFLAGS_FUZZ $extra $INCS -c "$src" -o "$obj"
    fi
}
export -f compile_one
export FUZZ CXX CXXFLAGS_FUZZ INCS

ls "$SRC"/trunk/src/core/*.cpp "$SRC"/trunk/src/kernel/*.cpp "$SRC"/trunk/src/protocol/*.cpp \
    | xargs -P "$MAYHEM_JOBS" -I{} bash -c 'compile_one {}'

# Leak detection off at build time (ASan/UBSan stay on and halting).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$FUZZ/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ/standalone_main.o"

LIBS="$OBJS/st/libst.a $OBJS/openssl/lib/libssl.a $OBJS/openssl/lib/libcrypto.a $OBJS/srtp2/lib/libsrtp2.a $OBJS/srt/lib/libsrt.a -lpthread -ldl -lrt"

# 3) Link every harness twice: libFuzzer engine, and the standalone run-once reproducer.
# The SRS objects go into an archive so each harness only pulls the translation units it reaches.
rm -f "$FUZZ/libsrsfuzz.a"
ar rcs "$FUZZ/libsrsfuzz.a" "$FUZZ"/srs_*.o
$CXX $CXXFLAGS_FUZZ $INCS -c "$SRC/mayhem/harnesses/fuzz_support.cpp" -o "$FUZZ/fuzz_support.o"
for src in "$SRC"/mayhem/harnesses/fuzz_*.cpp; do
    name="$(basename "${src%.cpp}")"
    [ "$name" = fuzz_support ] && continue
    $CXX $CXXFLAGS_FUZZ $INCS -c "$src" -o "$FUZZ/$name.o"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$FUZZ/$name.o" "$FUZZ/fuzz_support.o" "$FUZZ/libsrsfuzz.a" "$FUZZ/lsan_off.o" $LIBS -o "$OUT/$name"
    $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$FUZZ/$name.o" "$FUZZ/standalone_main.o" "$FUZZ/fuzz_support.o" "$FUZZ/libsrsfuzz.a" "$FUZZ/lsan_off.o" $LIBS -o "$OUT/$name-standalone"
done
