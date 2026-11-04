// Process-wide globals that SRS's server binary normally defines (srs_main_server.cpp); the
// parser harnesses link only the kernel/protocol layers, so they provide silent equivalents here.
#include <srs_kernel_factory.hpp>
#include <srs_kernel_log.hpp>
#include <srs_kernel_kbps.hpp>
#include <srs_protocol_log.hpp>

#include <stdarg.h>

class SilentLog : public ISrsLog
{
public:
    srs_error_t initialize() { return srs_success; }
    void reopen() {}
    void log(SrsLogLevel, const char *, const SrsContextId &, const char *, va_list) {}
};

class UnusedFactory : public ISrsKernelFactory
{
public:
    ISrsCoroutine *create_coroutine(const std::string &, ISrsCoroutineHandler *, SrsContextId) { return NULL; }
    ISrsTime *create_time() { return NULL; }
    ISrsConfig *create_config() { return NULL; }
    ISrsCond *create_cond() { return NULL; }
    ISrsFastTimer *create_fast_timer(const std::string &, srs_utime_t) { return NULL; }
};

ISrsLog *_srs_log = new SilentLog();
ISrsContext *_srs_context = new SrsThreadContext();
ISrsKernelFactory *_srs_kernel_factory = new UnusedFactory();

// Defined by the server binary; srs_kernel_kbps.cpp and srs_kernel_error.cpp reference them, and
// the parsers only bump the counters.
const char *_srs_binary = "/proc/self/exe";
bool _srs_global_initialized = false;
SrsPps *_srs_pps_addrs = new SrsPps();
SrsPps *_srs_pps_fast_addrs = new SrsPps();
SrsPps *_srs_pps_pli = new SrsPps();
SrsPps *_srs_pps_rhnack = new SrsPps();
SrsPps *_srs_pps_rmnack = new SrsPps();
SrsPps *_srs_pps_rnack = new SrsPps();
SrsPps *_srs_pps_rnack2 = new SrsPps();
SrsPps *_srs_pps_rpkts = new SrsPps();
SrsPps *_srs_pps_rr = new SrsPps();
SrsPps *_srs_pps_rrtx = new SrsPps();
SrsPps *_srs_pps_rrtx_padding = new SrsPps();
SrsPps *_srs_pps_rrtx_unwrap = new SrsPps();
SrsPps *_srs_pps_sanack = new SrsPps();
SrsPps *_srs_pps_snack = new SrsPps();
SrsPps *_srs_pps_snack2 = new SrsPps();
SrsPps *_srs_pps_snack3 = new SrsPps();
SrsPps *_srs_pps_snack4 = new SrsPps();
SrsPps *_srs_pps_spkts = new SrsPps();
SrsPps *_srs_pps_srtcps = new SrsPps();
SrsPps *_srs_pps_srtps = new SrsPps();
SrsPps *_srs_pps_srtx = new SrsPps();
SrsPps *_srs_pps_sstuns = new SrsPps();
SrsPps *_srs_pps_svnack = new SrsPps();
SrsPps *_srs_pps_twcc = new SrsPps();

// Allocates the kernel's own stats counters (_srs_pps_objs_rtps and friends), as the server does at startup.
static srs_error_t kbps_initialized = srs_global_kbps_initialize();
