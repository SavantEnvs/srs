// Leak detection is off at build time; ASan and UBSan stay active.
extern "C" int __lsan_is_turned_off() { return 1; }
